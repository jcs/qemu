/*
 * QEMU VMM support
 *
 * Copyright 2020, joshua stein
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2 or later, as published by the Free Software Foundation,
 * and may be copied, distributed, and modified under those terms.
 *
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "sysemu/vmm.h"

int vmm_init_vcpu(CPUState *cpu)
{
    return -ENOSYS;
}

int vmm_vcpu_exec(CPUState *cpu)
{
    return -ENOSYS;
}

void vmm_destroy_vcpu(CPUState *cpu)
{
}
