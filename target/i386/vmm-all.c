/* vim:ts=4:sw=4:et
 * Copyright (c) 2020, joshua stein
 * Copyright (c) 2018-2019 Maxime Villard, All rights reserved.
 *
 * OpenBSD VMM accelerator for QEMU.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/address-spaces.h"
#include "exec/ioport.h"
#include "qemu-common.h"
#include "strings.h"
#include "sysemu/accel.h"
#include "sysemu/vmm.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h"
#include "qemu/main-loop.h"
#include "hw/boards.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qapi/error.h"
#include "migration/blocker.h"

#include <machine/vmmvar.h>
#include <sys/ioctl.h>

static bool vmm_allowed = false;

static struct {
    int vmm_fd;
    uint32_t vmm_id;
} vmm_global;

struct vmm_vcpu {
    uint32_t vmm_vcpu_id;
    struct vm_exit vmm_exit;
    uint8_t tpr;
    bool stop;

    /* Window-exiting for INTs/NMIs. */
    bool int_window_exit;
    bool nmi_window_exit;

    /* The guest is in an interrupt shadow (POP SS, etc). */
    bool int_shadow;
};

static struct vmm_vcpu *
get_vmm_vcpu(CPUState *cpu)
{
    return (struct vmm_vcpu *)cpu->hax_vcpu;
}

/* XXX: sniped from vmd and amd64/specialreg.h */

#define CR0_PE      0x00000001  /* Protected mode Enable */
#define CR0_MP      0x00000002  /* "Math" Present (NPX or NPX emulator) */
#define CR0_EM      0x00000004  /* EMulate non-NPX coproc. (trap ESC only) */
#define CR0_TS      0x00000008  /* Task Switched (if MP, trap ESC and WAIT) */
#define CR0_ET      0x00000010  /* Extension Type (387 (if set) vs 287) */
#define CR0_PG      0x80000000  /* PaGing enable */

#define PML4_PAGE   0x11000

#define CR4_PSE     0x00000010  /* large (4MB) page size enable */
#define CR4_PAE     0x00000020  /* physical address extension enable */
#define CR4_MCE     0x00000040  /* machine check enable */
#define CR4_PGE     0x00000080  /* page global enable */
#define CR4_PCE     0x00000100  /* enable RDPMC instruction for all cpls */

#define MSR_EFER    0xc0000080  /* Extended feature enable */
#define EFER_SCE    0x00000001  /* SYSCALL extension */
#define EFER_LME    0x00000100  /* Long Mode Enabled */
#define EFER_LMA    0x00000400  /* Long Mode Active */
#define EFER_NXE    0x00000800  /* No-Execute Enabled */
#define EFER_SVME   0x00001000  /* SVM Enabled */

#define XCR0_X87    0x00000001  /* x87 FPU/MMX state */
#define XCR0_SSE    0x00000002  /* SSE state */
#define XCR0_AVX    0x00000004  /* AVX state */

/*
 * Represents a standard register set for an OS to be booted
 * as a flat 64 bit address space.
 *
 * NOT set here are:
 *  RIP
 *  RSP
 *  GDTR BASE
 *
 * Specific bootloaders should clone this structure and override
 * those fields as needed.
 *
 * Note - CR3 and various bits in CR0 may be overridden by vmm(4) based on
 *        features of the CPU in use.
 */
static const struct vcpu_reg_state vcpu_init_flat64 = {
    .vrs_gprs[VCPU_REGS_RFLAGS] = 0x2,
    .vrs_gprs[VCPU_REGS_RIP] = 0x0,
    .vrs_gprs[VCPU_REGS_RSP] = 0x0,
    .vrs_crs[VCPU_REGS_CR0] = CR0_ET | CR0_PE | CR0_PG,
    .vrs_crs[VCPU_REGS_CR3] = PML4_PAGE,
    .vrs_crs[VCPU_REGS_CR4] = CR4_PAE | CR4_PSE,
    .vrs_crs[VCPU_REGS_PDPTE0] = 0ULL,
    .vrs_crs[VCPU_REGS_PDPTE1] = 0ULL,
    .vrs_crs[VCPU_REGS_PDPTE2] = 0ULL,
    .vrs_crs[VCPU_REGS_PDPTE3] = 0ULL,
    .vrs_sregs[VCPU_REGS_CS] = { 0x8, 0xFFFFFFFF, 0xC09F, 0x0},
    .vrs_sregs[VCPU_REGS_DS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
    .vrs_sregs[VCPU_REGS_ES] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
    .vrs_sregs[VCPU_REGS_FS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
    .vrs_sregs[VCPU_REGS_GS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
    .vrs_sregs[VCPU_REGS_SS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
    .vrs_gdtr = { 0x0, 0xFFFF, 0x0, 0x0},
    .vrs_idtr = { 0x0, 0xFFFF, 0x0, 0x0},
    .vrs_sregs[VCPU_REGS_LDTR] = { 0x0, 0xFFFF, 0x0082, 0x0},
    .vrs_sregs[VCPU_REGS_TR] = { 0x0, 0xFFFF, 0x008B, 0x0},
    .vrs_msrs[VCPU_REGS_EFER] = EFER_LME | EFER_LMA,
    .vrs_drs[VCPU_REGS_DR0] = 0x0,
    .vrs_drs[VCPU_REGS_DR1] = 0x0,
    .vrs_drs[VCPU_REGS_DR2] = 0x0,
    .vrs_drs[VCPU_REGS_DR3] = 0x0,
    .vrs_drs[VCPU_REGS_DR6] = 0xFFFF0FF0,
    .vrs_drs[VCPU_REGS_DR7] = 0x400,
    .vrs_msrs[VCPU_REGS_STAR] = 0ULL,
    .vrs_msrs[VCPU_REGS_LSTAR] = 0ULL,
    .vrs_msrs[VCPU_REGS_CSTAR] = 0ULL,
    .vrs_msrs[VCPU_REGS_SFMASK] = 0ULL,
    .vrs_msrs[VCPU_REGS_KGSBASE] = 0ULL,
    .vrs_msrs[VCPU_REGS_MISC_ENABLE] = 0ULL,
    .vrs_crs[VCPU_REGS_XCR0] = XCR0_X87
};

/*
 * Represents a standard register set for an BIOS to be booted
 * as a flat 16 bit address space.
 */
static const struct vcpu_reg_state vcpu_init_flat16 = {
    .vrs_gprs[VCPU_REGS_RFLAGS] = 0x2,
    .vrs_gprs[VCPU_REGS_RIP] = 0xFFF0,
    .vrs_gprs[VCPU_REGS_RSP] = 0x0,
    .vrs_crs[VCPU_REGS_CR0] = 0x60000010,
    .vrs_crs[VCPU_REGS_CR3] = 0,
    .vrs_sregs[VCPU_REGS_CS] = { 0xF000, 0xFFFF, 0x809F, 0xF0000},
    .vrs_sregs[VCPU_REGS_DS] = { 0x0, 0xFFFF, 0x8093, 0x0},
    .vrs_sregs[VCPU_REGS_ES] = { 0x0, 0xFFFF, 0x8093, 0x0},
    .vrs_sregs[VCPU_REGS_FS] = { 0x0, 0xFFFF, 0x8093, 0x0},
    .vrs_sregs[VCPU_REGS_GS] = { 0x0, 0xFFFF, 0x8093, 0x0},
    .vrs_sregs[VCPU_REGS_SS] = { 0x0, 0xFFFF, 0x8093, 0x0},
    .vrs_gdtr = { 0x0, 0xFFFF, 0x0, 0x0},
    .vrs_idtr = { 0x0, 0xFFFF, 0x0, 0x0},
    .vrs_sregs[VCPU_REGS_LDTR] = { 0x0, 0xFFFF, 0x0082, 0x0},
    .vrs_sregs[VCPU_REGS_TR] = { 0x0, 0xFFFF, 0x008B, 0x0},
    .vrs_msrs[VCPU_REGS_EFER] = 0ULL,
    .vrs_drs[VCPU_REGS_DR0] = 0x0,
    .vrs_drs[VCPU_REGS_DR1] = 0x0,
    .vrs_drs[VCPU_REGS_DR2] = 0x0,
    .vrs_drs[VCPU_REGS_DR3] = 0x0,
    .vrs_drs[VCPU_REGS_DR6] = 0xFFFF0FF0,
    .vrs_drs[VCPU_REGS_DR7] = 0x400,
    .vrs_msrs[VCPU_REGS_STAR] = 0ULL,
    .vrs_msrs[VCPU_REGS_LSTAR] = 0ULL,
    .vrs_msrs[VCPU_REGS_CSTAR] = 0ULL,
    .vrs_msrs[VCPU_REGS_SFMASK] = 0ULL,
    .vrs_msrs[VCPU_REGS_KGSBASE] = 0ULL,
    .vrs_crs[VCPU_REGS_XCR0] = XCR0_X87
};

static void
vmm_set_segment(struct vcpu_segment_info *vsi, const SegmentCache *qs)
{
    vsi->vsi_sel = qs->selector;
    vsi->vsi_limit = qs->limit;
    vsi->vsi_ar = qs->flags;
    vsi->vsi_base = qs->base;
}

static void
vmm_set_registers(CPUState *cpu)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);
    struct vm_rwregs_params vrwp;
    struct vcpu_reg_state vrs;

    assert(cpu_is_stopped(cpu) || qemu_cpu_is_self(cpu));

    memset(&vrwp, 0, sizeof(vrwp));
    memset(&vrs, 0, sizeof(vrs));

    vrwp.vrwp_vm_id = vmm_global.vmm_id;
    vrwp.vrwp_vcpu_id = vcpu->vmm_vcpu_id;
    vrwp.vrwp_regs = vrs;
    vrwp.vrwp_mask = VM_RWREGS_ALL;

    vrs.vrs_gprs[VCPU_REGS_RAX] = env->regs[R_EAX];
    vrs.vrs_gprs[VCPU_REGS_RBX] = env->regs[R_EBX];
    vrs.vrs_gprs[VCPU_REGS_RCX] = env->regs[R_ECX];
    vrs.vrs_gprs[VCPU_REGS_RDX] = env->regs[R_EDX];
    vrs.vrs_gprs[VCPU_REGS_RSI] = env->regs[R_ESI];
    vrs.vrs_gprs[VCPU_REGS_RDI] = env->regs[R_EDI];
    vrs.vrs_gprs[VCPU_REGS_R8]  = env->regs[R_R8];
    vrs.vrs_gprs[VCPU_REGS_R9]  = env->regs[R_R9];
    vrs.vrs_gprs[VCPU_REGS_R10] = env->regs[R_R10];
    vrs.vrs_gprs[VCPU_REGS_R11] = env->regs[R_R11];
    vrs.vrs_gprs[VCPU_REGS_R12] = env->regs[R_R12];
    vrs.vrs_gprs[VCPU_REGS_R13] = env->regs[R_R13];
    vrs.vrs_gprs[VCPU_REGS_R14] = env->regs[R_R14];
    vrs.vrs_gprs[VCPU_REGS_R15] = env->regs[R_R15];
    vrs.vrs_gprs[VCPU_REGS_RSP] = env->regs[R_ESP];
    vrs.vrs_gprs[VCPU_REGS_RBP] = env->regs[R_EBP];
    vrs.vrs_gprs[VCPU_REGS_RIP] = env->eip;
    vrs.vrs_gprs[VCPU_REGS_RFLAGS] = env->eflags;

    vrs.vrs_crs[VCPU_REGS_CR0] = env->cr[0];
    vrs.vrs_crs[VCPU_REGS_CR2] = env->cr[2];
    vrs.vrs_crs[VCPU_REGS_CR3] = env->cr[3];
    vrs.vrs_crs[VCPU_REGS_CR4] = env->cr[4];
    vrs.vrs_crs[VCPU_REGS_CR8] = vcpu->tpr;
    vrs.vrs_crs[VCPU_REGS_XCR0] = env->xcr0;

    vrs.vrs_msrs[VCPU_REGS_EFER] = env->efer;
    vrs.vrs_msrs[VCPU_REGS_STAR] = env->star;
    vrs.vrs_msrs[VCPU_REGS_LSTAR] = env->lstar;
    vrs.vrs_msrs[VCPU_REGS_CSTAR] = env->cstar;
    vrs.vrs_msrs[VCPU_REGS_SFMASK] = env->fmask;
    vrs.vrs_msrs[VCPU_REGS_KGSBASE] = env->kernelgsbase;
    /* TODO MSRs:
        env->sysenter_cs;
        env->sysenter_esp;
        env->sysenter_eip;
        env->pat;
        env->tsc;
     */

    vrs.vrs_drs[VCPU_REGS_DR0] = env->dr[0];
    vrs.vrs_drs[VCPU_REGS_DR1] = env->dr[1];
    vrs.vrs_drs[VCPU_REGS_DR2] = env->dr[2];
    vrs.vrs_drs[VCPU_REGS_DR3] = env->dr[3];
    vrs.vrs_drs[VCPU_REGS_DR6] = env->dr[6];
    vrs.vrs_drs[VCPU_REGS_DR7] = env->dr[7];

    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_CS], &env->segs[R_CS]);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_DS], &env->segs[R_DS]);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_ES], &env->segs[R_ES]);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_FS], &env->segs[R_FS]);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_GS], &env->segs[R_GS]);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_SS], &env->segs[R_SS]);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_LDTR], &env->ldt);
    vmm_set_segment(&vrs.vrs_sregs[VCPU_REGS_TR], &env->tr);

    vmm_set_segment(&vrs.vrs_gdtr, &env->gdt);
    vmm_set_segment(&vrs.vrs_idtr, &env->idt);

    /* TODO: FPU? */

    printf("VMM_IOC_WRITEREGS\n");
    if (ioctl(vmm_global.vmm_fd, VMM_IOC_WRITEREGS, &vrwp) == -1) {
        error_report("%s: VMM_IOC_WRITEREGS failed: %s", __func__,
            strerror(errno));
        return;
    }
}

static void
vmm_get_segment(SegmentCache *qs, const struct vcpu_segment_info *vsi)
{
    qs->selector = vsi->vsi_sel;
    qs->limit = vsi->vsi_limit;
    qs->flags = vsi->vsi_ar;
    qs->base = vsi->vsi_base;
}

static void
vmm_get_registers(CPUState *cpu)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);
    X86CPU *x86_cpu = X86_CPU(cpu);
    struct vm_rwregs_params vrwp;
    struct vcpu_reg_state vrs;
    uint64_t tpr;

    assert(cpu_is_stopped(cpu) || qemu_cpu_is_self(cpu));

    memset(&vrwp, 0, sizeof(vrwp));
    memset(&vrs, 0, sizeof(vrs));

    vrwp.vrwp_vm_id = vmm_global.vmm_id;
    vrwp.vrwp_vcpu_id = vcpu->vmm_vcpu_id;
    vrwp.vrwp_regs = vrs;
    vrwp.vrwp_mask = VM_RWREGS_ALL;

    printf("VMM_IOC_READREGS\n");
    if (ioctl(vmm_global.vmm_fd, VMM_IOC_READREGS, &vrwp) == -1) {
        error_report("%s: VMM_IOC_READREGS failed: %s", __func__,
            strerror(errno));
        return;
    }

    env->regs[R_EAX] = vrs.vrs_gprs[VCPU_REGS_RAX];
    env->regs[R_EBX] = vrs.vrs_gprs[VCPU_REGS_RBX];
    env->regs[R_ECX] = vrs.vrs_gprs[VCPU_REGS_RCX];
    env->regs[R_EDX] = vrs.vrs_gprs[VCPU_REGS_RDX];
    env->regs[R_ESI] = vrs.vrs_gprs[VCPU_REGS_RSI];
    env->regs[R_EDI] = vrs.vrs_gprs[VCPU_REGS_RDI];
    env->regs[R_R8] = vrs.vrs_gprs[VCPU_REGS_R8];
    env->regs[R_R9] = vrs.vrs_gprs[VCPU_REGS_R9];
    env->regs[R_R10] = vrs.vrs_gprs[VCPU_REGS_R10];
    env->regs[R_R11] = vrs.vrs_gprs[VCPU_REGS_R11];
    env->regs[R_R12] = vrs.vrs_gprs[VCPU_REGS_R12];
    env->regs[R_R13] = vrs.vrs_gprs[VCPU_REGS_R13];
    env->regs[R_R14] = vrs.vrs_gprs[VCPU_REGS_R14];
    env->regs[R_R15] = vrs.vrs_gprs[VCPU_REGS_R15];
    env->regs[R_ESP] = vrs.vrs_gprs[VCPU_REGS_RSP];
    env->regs[R_EBP] = vrs.vrs_gprs[VCPU_REGS_RBP];
    env->eip = vrs.vrs_gprs[VCPU_REGS_RIP];
    env->eflags = vrs.vrs_gprs[VCPU_REGS_RFLAGS];

    env->cr[0] = vrs.vrs_crs[VCPU_REGS_CR0];
    env->cr[2] = vrs.vrs_crs[VCPU_REGS_CR2];
    env->cr[3] = vrs.vrs_crs[VCPU_REGS_CR3];
    env->cr[4] = vrs.vrs_crs[VCPU_REGS_CR4];
    tpr = vrs.vrs_crs[VCPU_REGS_CR8];
    if (tpr != vcpu->tpr) {
        vcpu->tpr = tpr;
        cpu_set_apic_tpr(x86_cpu->apic_state, tpr);
    }
    env->xcr0 = vrs.vrs_crs[VCPU_REGS_XCR0];

    env->efer = vrs.vrs_msrs[VCPU_REGS_EFER];
    env->star = vrs.vrs_msrs[VCPU_REGS_STAR];
    env->lstar = vrs.vrs_msrs[VCPU_REGS_LSTAR];
    env->cstar = vrs.vrs_msrs[VCPU_REGS_CSTAR];
    env->fmask = vrs.vrs_msrs[VCPU_REGS_SFMASK];
    env->kernelgsbase = vrs.vrs_msrs[VCPU_REGS_KGSBASE];

    env->dr[0] = vrs.vrs_drs[VCPU_REGS_DR0];
    env->dr[1] = vrs.vrs_drs[VCPU_REGS_DR1];
    env->dr[2] = vrs.vrs_drs[VCPU_REGS_DR2];
    env->dr[3] = vrs.vrs_drs[VCPU_REGS_DR3];
    env->dr[6] = vrs.vrs_drs[VCPU_REGS_DR6];
    env->dr[7] = vrs.vrs_drs[VCPU_REGS_DR7];

    vmm_get_segment(&env->segs[R_CS], &vrs.vrs_sregs[VCPU_REGS_CS]);
    vmm_get_segment(&env->segs[R_DS], &vrs.vrs_sregs[VCPU_REGS_DS]);
    vmm_get_segment(&env->segs[R_ES], &vrs.vrs_sregs[VCPU_REGS_ES]);
    vmm_get_segment(&env->segs[R_FS], &vrs.vrs_sregs[VCPU_REGS_FS]);
    vmm_get_segment(&env->segs[R_GS], &vrs.vrs_sregs[VCPU_REGS_GS]);
    vmm_get_segment(&env->segs[R_SS], &vrs.vrs_sregs[VCPU_REGS_SS]);
    vmm_get_segment(&env->ldt, &vrs.vrs_sregs[VCPU_REGS_LDTR]);
    vmm_get_segment(&env->tr, &vrs.vrs_sregs[VCPU_REGS_TR]);

    vmm_get_segment(&env->gdt, &vrs.vrs_gdtr);
    vmm_get_segment(&env->idt, &vrs.vrs_idtr);

    /* TODO: FPU? */

    /* TODO MSRs:
        env->sysenter_cs;
        env->sysenter_esp;
        env->sysenter_eip;
        env->pat;
        env->tsc;
     */

    x86_update_hflags(env);
}

static bool
vmm_can_take_int(CPUState *cpu)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);

    if (vcpu->int_window_exit) {
        return false;
    }

    if (vcpu->int_shadow || (!(env->eflags & IF_MASK))) {
        /* Exit on interrupt window. */

        /* TODO: int_window_exiting = 1 */

        return false;
    }

    return true;
}

static bool
vmm_can_take_nmi(CPUState *cpu)
{
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);

    /*
     * Contrary to INTs, NMIs always schedule an exit when they are
     * completed. Therefore, if window-exiting is enabled, it means
     * NMIs are blocked.
     */
    if (vcpu->nmi_window_exit) {
        return false;
    }

    return true;
}

/*
 * Called before the VCPU is run. We inject events generated by the I/O
 * thread, and synchronize the guest TPR.
 */
static void
vmm_vcpu_pre_run(CPUState *cpu)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);
    X86CPU *x86_cpu = X86_CPU(cpu);
    struct vm_intr_params vip;
    bool has_intr = false;
    bool sync_tpr = false;
    uint8_t tpr;

    memset(&vip, 0, sizeof(vip));

    qemu_mutex_lock_iothread();

    tpr = cpu_get_apic_tpr(x86_cpu->apic_state);
    if (tpr != vcpu->tpr) {
        vcpu->tpr = tpr;
        sync_tpr = true;
    }

    /*
     * Force the VCPU out of its inner loop to process any INIT requests
     * or commit pending TPR access.
     */
    if (cpu->interrupt_request & (CPU_INTERRUPT_INIT|CPU_INTERRUPT_TPR)) {
        cpu->exit_request = 1;
    }

    if (cpu->interrupt_request & CPU_INTERRUPT_NMI) {
        if (vmm_can_take_nmi(cpu)) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_NMI;
            vip.vip_vm_id = vmm_global.vmm_id;
            vip.vip_vcpu_id = vcpu->vmm_vcpu_id;
            vip.vip_intr = 2;
            has_intr = true;
        }
    }

    if (!has_intr && (cpu->interrupt_request & CPU_INTERRUPT_HARD)) {
        if (vmm_can_take_int(cpu)) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_HARD;
            vip.vip_vm_id = vmm_global.vmm_id;
            vip.vip_vcpu_id = vcpu->vmm_vcpu_id;
            vip.vip_intr = cpu_get_pic_interrupt(env);
            has_intr = true;
        }
    }

    /* Don't want SMIs. */
    if (cpu->interrupt_request & CPU_INTERRUPT_SMI) {
        cpu->interrupt_request &= ~CPU_INTERRUPT_SMI;
    }

    if (sync_tpr) {
        /* TODO: WRITEREGS CR8 with vmm->tpr */
    }

    if (has_intr) {
        printf("VMM_IOC_INTR %d\n", vip.vip_intr);
        if (ioctl(vmm_global.vmm_fd, VMM_IOC_INTR, &vip) == -1) {
            error_report("%s: VMM_IOC_INTR %d failed: %s", __func__,
                vip.vip_intr, strerror(errno));
        }
    }

    qemu_mutex_unlock_iothread();
}

/*
 * Called after the VCPU ran. We synchronize the host view of the TPR and
 * RFLAGS.
 */
static void
vmm_vcpu_post_run(CPUState *cpu, struct vm_exit *exit)
{
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    X86CPU *x86_cpu = X86_CPU(cpu);
    uint8_t tpr;

    env->eflags = exit->vrs.vrs_gprs[VCPU_REGS_RFLAGS];

#if 0
    vcpu->int_shadow =
        exit->exitstate[NVMM_X64_EXITSTATE_INT_SHADOW];
    vcpu->int_window_exit =
        exit->exitstate[NVMM_X64_EXITSTATE_INT_WINDOW_EXIT];
    vcpu->nmi_window_exit =
        exit->exitstate[NVMM_X64_EXITSTATE_NMI_WINDOW_EXIT];
#endif

    tpr = exit->vrs.vrs_crs[VCPU_REGS_CR8];
    if (vcpu->tpr != tpr) {
        vcpu->tpr = tpr;
        qemu_mutex_lock_iothread();
        cpu_set_apic_tpr(x86_cpu->apic_state, vcpu->tpr);
        qemu_mutex_unlock_iothread();
    }
}

static int
vmm_handle_msr(CPUState *cpu, struct vm_exit *exit)
{
#if 0
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);
    X86CPU *x86_cpu = X86_CPU(cpu);
    uint64_t val;
    int ret;
#endif

    /* TODO */

    printf("TODO: %s\n", __func__);

    return 0;
}

static int
vmm_handle_halted(CPUState *cpu, struct vm_exit *exit)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    int ret = 0;

    qemu_mutex_lock_iothread();

    if (!((cpu->interrupt_request & CPU_INTERRUPT_HARD) &&
          (env->eflags & IF_MASK)) &&
        !(cpu->interrupt_request & CPU_INTERRUPT_NMI)) {
        cpu->exception_index = EXCP_HLT;
        cpu->halted = true;
        ret = 1;
    }

    qemu_mutex_unlock_iothread();

    return ret;
}

static int
vmm_vcpu_loop(CPUState *cpu)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);
    struct vmm_vcpu *vcpu = get_vmm_vcpu(cpu);
    X86CPU *x86_cpu = X86_CPU(cpu);
    struct vm_run_params vrp;
    int ret = 0;

    /*
     * Some asynchronous events must be handled outside of the inner
     * VCPU loop. They are handled here.
     */
    if (cpu->interrupt_request & CPU_INTERRUPT_INIT) {
        vmm_cpu_synchronize_state(cpu);
        do_cpu_init(x86_cpu);
        /* XXX: reset the INT/NMI windows */
    }
    if (cpu->interrupt_request & CPU_INTERRUPT_POLL) {
        cpu->interrupt_request &= ~CPU_INTERRUPT_POLL;
        apic_poll_irq(x86_cpu->apic_state);
    }
    if (((cpu->interrupt_request & CPU_INTERRUPT_HARD) &&
         (env->eflags & IF_MASK)) ||
        (cpu->interrupt_request & CPU_INTERRUPT_NMI)) {
        cpu->halted = false;
    }
    if (cpu->interrupt_request & CPU_INTERRUPT_SIPI) {
        vmm_cpu_synchronize_state(cpu);
        do_cpu_sipi(x86_cpu);
    }
    if (cpu->interrupt_request & CPU_INTERRUPT_TPR) {
        cpu->interrupt_request &= ~CPU_INTERRUPT_TPR;
        vmm_cpu_synchronize_state(cpu);
        apic_handle_tpr_access_report(x86_cpu->apic_state, env->eip,
            env->tpr_access_type);
    }

    if (cpu->halted) {
        cpu->exception_index = EXCP_HLT;
        atomic_set(&cpu->exit_request, false);
        return 0;
    }

    memset(&vrp, 0, sizeof(vrp));

    qemu_mutex_unlock_iothread();
    cpu_exec_start(cpu);

    /*
     * Inner VCPU loop.
     */
    do {
        if (cpu->vcpu_dirty) {
            vmm_set_registers(cpu);
            cpu->vcpu_dirty = false;
        }

        if (vcpu->stop) {
            cpu->exception_index = EXCP_INTERRUPT;
            vcpu->stop = false;
            ret = 1;
            break;
        }

        vmm_vcpu_pre_run(cpu);

        if (atomic_read(&cpu->exit_request)) {
            qemu_cpu_kick_self();
        }

        vrp.vrp_exit = &vcpu->vmm_exit;
        vrp.vrp_vm_id = vmm_global.vmm_id;
        vrp.vrp_vcpu_id = vcpu->vmm_vcpu_id;
        vrp.vrp_continue = 0;
        //vrp.vrp_irq = 0xFFFF;

        printf("VMM_IOC_RUN\n");
        if (ioctl(vmm_global.vmm_fd, VMM_IOC_RUN, &vrp) == -1) {
            error_report("%s: VMM_IOC_RUN failed: %s", __func__,
                strerror(errno));
            ret = -errno;
            break;
        }

        vmm_vcpu_post_run(cpu, vrp.vrp_exit);

        switch (vrp.vrp_exit_reason) {
        case VM_EXIT_TERMINATED:
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            cpu->exception_index = EXCP_INTERRUPT;
            ret = 1;
            break;
        case VM_EXIT_NONE:
            break;
        case VMX_EXIT_TRIPLE_FAULT:
            printf("VMX_EXIT_TRIPLE_FAULT\n");
            break;
        case SVM_VMEXIT_SHUTDOWN:
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            ret = EXCP_INTERRUPT;
            break;
        default:
            error_report("unhandled VM return code 0x%x", vrp.vrp_exit_reason);
            vmm_get_registers(cpu);
            qemu_mutex_lock_iothread();
            qemu_system_guest_panicked(cpu_get_crash_info(cpu));
            qemu_mutex_unlock_iothread();
            ret = -1;
            break;
        }
    } while (ret == 0);

    cpu_exec_end(cpu);
    qemu_mutex_lock_iothread();
    current_cpu = cpu;

    atomic_set(&cpu->exit_request, false);

    return ret < 0;
}

static void
do_vmm_cpu_synchronize_state(CPUState *cpu, run_on_cpu_data arg)
{
    vmm_get_registers(cpu);
    cpu->vcpu_dirty = true;
}

static void
do_vmm_cpu_synchronize_post_reset(CPUState *cpu, run_on_cpu_data arg)
{
    vmm_set_registers(cpu);
    cpu->vcpu_dirty = false;
}

static void
do_vmm_cpu_synchronize_post_init(CPUState *cpu, run_on_cpu_data arg)
{
    vmm_set_registers(cpu);
    cpu->vcpu_dirty = false;
}

static void
do_vmm_cpu_synchronize_pre_loadvm(CPUState *cpu, run_on_cpu_data arg)
{
    cpu->vcpu_dirty = true;
}

void vmm_cpu_synchronize_state(CPUState *cpu)
{
    if (!cpu->vcpu_dirty) {
        run_on_cpu(cpu, do_vmm_cpu_synchronize_state, RUN_ON_CPU_NULL);
    }
}

void vmm_cpu_synchronize_post_reset(CPUState *cpu)
{
    run_on_cpu(cpu, do_vmm_cpu_synchronize_post_reset, RUN_ON_CPU_NULL);
}

void vmm_cpu_synchronize_post_init(CPUState *cpu)
{
    run_on_cpu(cpu, do_vmm_cpu_synchronize_post_init, RUN_ON_CPU_NULL);
}

void vmm_cpu_synchronize_pre_loadvm(CPUState *cpu)
{
    run_on_cpu(cpu, do_vmm_cpu_synchronize_pre_loadvm, RUN_ON_CPU_NULL);
}

static void
vmm_ipi_signal(int sigcpu)
{
    struct vmm_vcpu *vcpu;

    if (current_cpu) {
        vcpu = get_vmm_vcpu(current_cpu);
        vcpu->stop = true;
    }
}

static void
vmm_init_cpu_signals(void)
{
    struct sigaction sigact;
    sigset_t set;

    /* Install the IPI handler. */
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = vmm_ipi_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    /* Allow IPIs on the current thread. */
    sigprocmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    pthread_sigmask(SIG_SETMASK, &set, NULL);
}

void
vmm_reset_vcpu(CPUState *cpu)
{
    struct CPUX86State *env = (CPUArchState *)(cpu->env_ptr);

    printf("%s\n", __func__);

    env->xcr0 = 1;

    /* enabled by default */
    env->poll_control_msr = 1;
}

static Error *vmm_migration_blocker;

int
vmm_init_vcpu(CPUState *cpu)
{
    Error *local_error = NULL;
    struct vmm_vcpu *vcpu;
    struct vcpu_reg_state vrs;
    struct vm_resetcpu_params vrp;

    vmm_init_cpu_signals();

    if (vmm_migration_blocker == NULL) {
        error_setg(&vmm_migration_blocker, "Migration not supported");

        (void)migrate_add_blocker(vmm_migration_blocker, &local_error);
        if (local_error) {
            error_report_err(local_error);
            migrate_del_blocker(vmm_migration_blocker);
            error_free(vmm_migration_blocker);
            return -EINVAL;
        }
    }

    vcpu = g_malloc0(sizeof(struct vmm_vcpu));
    if (vcpu == NULL) {
        error_report("failed to allocate VCPU context");
        return -ENOMEM;
    }
    vcpu->vmm_vcpu_id = cpu->cpu_index;

    //memcpy(&vrs, &vcpu_init_flat64, sizeof(vrs));
    memset(&vrs, 0, sizeof(vrs));

    memset(&vrp, 0, sizeof(vrp));
    vrp.vrp_vm_id = vmm_global.vmm_id;
    vrp.vrp_vcpu_id = vcpu->vmm_vcpu_id;
    memcpy(&vrp.vrp_init_state, &vrs, sizeof(struct vcpu_reg_state));

    printf("%s: VMM_IOC_RESETCPU\n", __func__);
    if (ioctl(vmm_global.vmm_fd, VMM_IOC_RESETCPU, &vrp) == -1) {
        error_report("failed VMM_IOC_RESETCPU: %s", strerror(errno));
        close(vmm_global.vmm_fd);
        return -errno;
    }

    cpu->vcpu_dirty = true;
    cpu->hax_vcpu = (struct hax_vcpu_state *)vcpu;

    return 0;
}

int
vmm_vcpu_exec(CPUState *cpu)
{
    int ret, fatal;

    while (1) {
        if (cpu->exception_index >= EXCP_INTERRUPT) {
            ret = cpu->exception_index;
            cpu->exception_index = -1;
            break;
        }

        fatal = vmm_vcpu_loop(cpu);

        if (fatal) {
            error_report("failed to execute vcpu loop");
            abort();
        }
    }

    return ret;
}

void
vmm_destroy_vcpu(CPUState *cpu)
{
    struct vm_terminate_params vtp;

    memset(&vtp, 0, sizeof(vtp));
    vtp.vtp_vm_id = vmm_global.vmm_id;

    if (ioctl(vmm_global.vmm_fd, VMM_IOC_TERM, &vtp) == -1) {
        error_report("failed VMM_IOC_TERM: %s", strerror(errno));
        close(vmm_global.vmm_fd);
        return;
    }

    close(vmm_global.vmm_fd);
    vmm_global.vmm_fd = -1;
    vmm_global.vmm_id = 0;

    g_free(cpu->hax_vcpu);
}

static void
vmm_update_mapping(hwaddr start_pa, ram_addr_t size, uintptr_t hva,
    bool add, bool rom, const char *name)
{
    struct vm_addmemrange_params vap;

    printf("vmm_update_mapping: %s GPA range '%s' PA:%p, "
        "Size:%p bytes, HostVA:%p\n",
        (add ? "map" : "unmap"), name, (void *)(uintptr_t)start_pa,
        (void *)size, (void *)hva);

    if (!add) {
        error_report("%s: mapping removal not supported\n", __func__);
        return;
    }

    vap.vap_vm_id = vmm_global.vmm_id;
    vap.vap_range.vmr_gpa = start_pa;
    vap.vap_range.vmr_va = hva;
    vap.vap_range.vmr_size = size;

    if (ioctl(vmm_global.vmm_fd, VMM_IOC_ADDMEMRANGE, &vap) == -1) {
        error_report("failed VMM_IOC_ADDMEMRANGE: %s", strerror(errno));
    }
}

static void
vmm_process_section(MemoryRegionSection *section, int add)
{
    MemoryRegion *mr = section->mr;
    hwaddr start_pa = section->offset_within_address_space;
    ram_addr_t size = int128_get64(section->size);
    unsigned int delta;
    uintptr_t hva;

    if (!memory_region_is_ram(mr)) {
        return;
    }

    /* Adjust start_pa and size so that they are page-aligned. */
    delta = qemu_real_host_page_size - (start_pa & ~qemu_real_host_page_mask);
    delta &= ~qemu_real_host_page_mask;
    if (delta > size) {
        return;
    }
    start_pa += delta;
    size -= delta;
    size &= qemu_real_host_page_mask;
    if (!size || (start_pa & ~qemu_real_host_page_mask)) {
        return;
    }

    hva = (uintptr_t)memory_region_get_ram_ptr(mr) +
        section->offset_within_region + delta;

    vmm_update_mapping(start_pa, size, hva, add, memory_region_is_rom(mr),
        mr->name);
}

static void
vmm_region_add(MemoryListener *listener, MemoryRegionSection *section)
{
    memory_region_ref(section->mr);
    vmm_process_section(section, 1);
}

static void
vmm_region_del(MemoryListener *listener, MemoryRegionSection *section)
{
    vmm_process_section(section, 0);
    memory_region_unref(section->mr);
}

static void
vmm_transaction_begin(MemoryListener *listener)
{
    /* nothing */
}

static void
vmm_transaction_commit(MemoryListener *listener)
{
    /* nothing */
}

static void
vmm_log_sync(MemoryListener *listener, MemoryRegionSection *section)
{
    MemoryRegion *mr = section->mr;

    if (!memory_region_is_ram(mr)) {
        return;
    }

    memory_region_set_dirty(mr, 0, int128_get64(section->size));
}

static MemoryListener vmm_memory_listener = {
    .begin = vmm_transaction_begin,
    .commit = vmm_transaction_commit,
    .region_add = vmm_region_add,
    .region_del = vmm_region_del,
    .log_sync = vmm_log_sync,
    .priority = 10,
};

static void
vmm_ram_block_added(RAMBlockNotifier *n, void *host, size_t size)
{
    uintptr_t hva = (uintptr_t)host;
    int ret;

    /* TODO */
    printf("vmm: map HVA, HostVA:%p Size:%p bytes\n", (void *)hva,
        (void *)size);
}

static struct RAMBlockNotifier nvmm_ram_notifier = {
    .ram_block_added = vmm_ram_block_added
};

static void
vmm_handle_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;

    if (!qemu_cpu_is_self(cpu)) {
        qemu_cpu_kick(cpu);
    }
}

static int
vmm_accel_init(MachineState *ms)
{
    struct vm_create_params vcp;
    void *p;
    size_t memsize;

    memset(&vmm_global, 0, sizeof(vmm_global));

    vmm_global.vmm_fd = open("/dev/vmm", O_RDWR);
    if (vmm_global.vmm_fd == -1) {
        error_report("failed opening /dev/vmm: %s", strerror(errno));
        return -errno;
    }

    memset(&vcp, 0, sizeof(vcp));
    vcp.vcp_ncpus = 1;

    if (ioctl(vmm_global.vmm_fd, VMM_IOC_CREATE, &vcp) == -1) {
        error_report("failed VMM_IOC_CREATE: %s", strerror(errno));
        close(vmm_global.vmm_fd);
        return -errno;
    }

    printf("ioctl VMM_IOC_CREATE: vmm id %d\n", vcp.vcp_id);
    vmm_global.vmm_id = vcp.vcp_id;

    memory_listener_register(&vmm_memory_listener, &address_space_memory);

    cpu_interrupt_handler = vmm_handle_interrupt;

    printf("OpenBSD VMM accelerator is operational\n");
    return 0;
}

int
vmm_enabled(void)
{
    return vmm_allowed;
}

static void
vmm_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "vmm";
    ac->init_machine = vmm_accel_init;
    ac->allowed = &vmm_allowed;
}

static const TypeInfo vmm_accel_type = {
    .name = ACCEL_CLASS_NAME("vmm"),
    .parent = TYPE_ACCEL,
    .class_init = vmm_accel_class_init,
};

static void
vmm_type_init(void)
{
    type_register_static(&vmm_accel_type);
}

type_init(vmm_type_init);
