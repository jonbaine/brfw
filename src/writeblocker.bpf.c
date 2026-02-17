// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define EPERM 1

// openat flags — only intercept writes
#define O_ACCMODE   003
#define O_WRONLY    001
#define O_RDWR      002
#define O_CREAT    0100
#define O_TRUNC   01000
#define O_APPEND  02000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int wb_action = WB_ACTION_DISCARD;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct bin_key);
    __type(value, __u8);
} bin_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Resolve current task's binary to a bin_key, return true if found in map
static __always_inline bool match_binary(struct bin_key *key)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct file *exe_file;
    struct inode *inode;

    task = (struct task_struct *)bpf_get_current_task_btf();

    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return false;

    exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return false;

    inode = BPF_CORE_READ(exe_file, f_inode);
    if (!inode)
        return false;

    key->ino = BPF_CORE_READ(inode, i_ino);
    key->dev = BPF_CORE_READ(inode, i_sb, s_dev);

    return bpf_map_lookup_elem(&bin_map, key) != NULL;
}

static __always_inline void submit_event(int action, int fd, int syscall_type)
{
    struct wb_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->action = action;
        e->fd = fd;
        e->syscall = syscall_type;
        bpf_ringbuf_submit(e, 0);
    }
}

#if defined(__TARGET_ARCH_arm64)
SEC("fmod_ret/__arm64_sys_write")
#else
SEC("fmod_ret/__x64_sys_write")
#endif
int BPF_PROG(writeblocker_write, struct pt_regs *regs)
{
    struct bin_key key = {};
    if (!match_binary(&key))
        return 0;

    // Read syscall arguments from pt_regs
    u64 arg0, arg2;
#if defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&arg0, sizeof(arg0), (void *)regs);
    bpf_probe_read_kernel(&arg2, sizeof(arg2), (void *)regs + 16);
#else
    arg0 = PT_REGS_PARM1(regs);
    arg2 = PT_REGS_PARM3(regs);
#endif
    u32 fd = (u32)arg0;
    u32 count = (u32)arg2;
    if (fd <= 2)
        return 0;

    submit_event(wb_action, fd, WB_SYS_WRITE);

    if (wb_action == WB_ACTION_BLOCK)
        return -EPERM;
    if (wb_action == WB_ACTION_DISCARD)
        return count;

    return 0;
}

#if defined(__TARGET_ARCH_arm64)
SEC("fmod_ret/__arm64_sys_openat")
#else
SEC("fmod_ret/__x64_sys_openat")
#endif
int BPF_PROG(writeblocker_openat, struct pt_regs *regs)
{
    struct bin_key key = {};
    if (!match_binary(&key))
        return 0;

    // Read flags (3rd arg of openat: dirfd, pathname, flags, mode)
    u64 arg2;
#if defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&arg2, sizeof(arg2), (void *)regs + 16);
#else
    arg2 = PT_REGS_PARM3(regs);
#endif
    int flags = (int)arg2;

    // Only intercept opens with write intent
    int accmode = flags & O_ACCMODE;
    if (accmode != O_WRONLY && accmode != O_RDWR &&
        !(flags & O_CREAT) && !(flags & O_TRUNC) && !(flags & O_APPEND))
        return 0;

    submit_event(wb_action, flags, WB_SYS_OPENAT);

    // Can't fake a valid fd, so block for both BLOCK and DISCARD
    return -EPERM;
}
