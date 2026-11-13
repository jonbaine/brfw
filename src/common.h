// SPDX-License-Identifier: BSD-3-Clause
#ifndef BRFW_COMMON_H
#define BRFW_COMMON_H

#define TASK_COMM_LEN 16

// brfw firewall structures

#define MAX_ENTRIES 128

// Key for the binary map — identifies a binary on disk
struct bin_key {
    __u64 ino;   // inode number
    __u32 dev;   // device number
    __u32 _pad;  // padding for alignment
};

// Firewall modes
#define FW_MODE_ALLOWLIST 0  // block everything except listed binaries
#define FW_MODE_BLOCKLIST 1  // allow everything except listed binaries

// Event reported to userspace
struct fw_event {
    int pid;
    char comm[TASK_COMM_LEN];
    int action;  // 0=allowed, 1=blocked
    int syscall; // 0=connect, 1=bind
};

// Writeblocker actions
#define WB_ACTION_BLOCK   1  // return -EPERM
#define WB_ACTION_DISCARD 2  // return count (fake success)

// Writeblocker syscall types
#define WB_SYS_WRITE  0
#define WB_SYS_OPENAT 1

struct wb_event {
    int pid;
    char comm[TASK_COMM_LEN];
    int action;   // WB_ACTION_*
    int fd;       // file descriptor (write) or flags (openat)
    int syscall;  // WB_SYS_*
};

// Static assertions to catch ABI drift at compile time
#ifndef __bpf__
#include <stddef.h>
_Static_assert(sizeof(struct bin_key) == 16, "bin_key size changed — update BPF maps");
_Static_assert(offsetof(struct bin_key, ino) == 0, "bin_key.ino offset changed");
_Static_assert(offsetof(struct bin_key, dev) == 8, "bin_key.dev offset changed");
_Static_assert(sizeof(struct fw_event) == 28, "fw_event size changed — check ring buffer compat");
_Static_assert(sizeof(struct wb_event) == 32, "wb_event size changed — check ring buffer compat");
#endif

#endif  // BRFW_COMMON_H
