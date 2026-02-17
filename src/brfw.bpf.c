#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define EPERM 1

char LICENSE[] SEC("license") = "GPL v2";

const volatile int fw_mode = FW_MODE_ALLOWLIST;

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

static __always_inline int check_binary(int syscall_type)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct file *exe_file;
    struct inode *inode;
    struct bin_key key = {};
    __u8 *found;
    int action;

    task = (struct task_struct *)bpf_get_current_task_btf();

    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return 0;

    inode = BPF_CORE_READ(exe_file, f_inode);
    if (!inode)
        return 0;

    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    found = bpf_map_lookup_elem(&bin_map, &key);

    if (fw_mode == FW_MODE_ALLOWLIST) {
        // Allowlist: found = allow, not found = block
        action = found ? 0 : 1;
    } else {
        // Blocklist: found = block, not found = allow
        action = found ? 1 : 0;
    }

    // Submit event to ring buffer
    struct fw_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->action = action;
        e->syscall = syscall_type;
        bpf_ringbuf_submit(e, 0);
    }

    return action ? -EPERM : 0;
}

#if defined(__TARGET_ARCH_arm64)
SEC("fmod_ret/__arm64_sys_connect")
#else
SEC("fmod_ret/__x64_sys_connect")
#endif
int BPF_PROG(brfw_connect, struct pt_regs *regs)
{
    return check_binary(0);
}

#if defined(__TARGET_ARCH_arm64)
SEC("fmod_ret/__arm64_sys_bind")
#else
SEC("fmod_ret/__x64_sys_bind")
#endif
int BPF_PROG(brfw_bind, struct pt_regs *regs)
{
    return check_binary(1);
}
