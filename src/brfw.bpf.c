// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL v2";


SEC("fmod_ret/__x64_sys_connect")
int BPF_PROG(brfw_connect, struct pt_regs *regs)
{
    // Get the current pid.
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Detecting CONNECT for pid=%d\n", pid);  
    //Return 0. Just bypass.
    return 0;
}

SEC("fmod_ret/__x64_sys_bind")
int BPF_PROG(brfw_bind, struct pt_regs *regs)
{
    // Get the current pid.
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Detecting BIND for pid=%d\n", pid);
    //Return 0. Just bypass.
    return 0;
}