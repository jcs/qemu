/*
 * QEMU VMM support
 *
 * Copyright 2020, joshua stein
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_VMM_H
#define QEMU_VMM_H

#include "config-host.h"
#include "qemu-common.h"

int vmm_init_vcpu(CPUState *);
int vmm_vcpu_exec(CPUState *);
void vmm_destroy_vcpu(CPUState *);
void vmm_reset_vcpu(CPUState *);

void vmm_cpu_synchronize_state(CPUState *);
void vmm_cpu_synchronize_post_reset(CPUState *);
void vmm_cpu_synchronize_post_init(CPUState *);
void vmm_cpu_synchronize_pre_loadvm(CPUState *);

#ifdef CONFIG_VMM
int vmm_enabled(void);
#else /* CONFIG_VMM */
#define vmm_enabled() (0)
#endif /* CONFIG_VMM */

#endif /* QEMU_VMM_H */
