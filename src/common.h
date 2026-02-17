// SPDX-License-Identifier: BSD-3-Clause
#ifndef BAD_BPF_COMMON_H
#define BAD_BPF_COMMON_H

// These are used by a number of
// different programs to sync eBPF Tail Call
// login between user space and kernel
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

// Used when replacing text
#define FILENAME_LEN_MAX 50
#define TEXT_LEN_MAX 20

// Simple message structure to get events from eBPF Programs
// in the kernel to user spcae
#define TASK_COMM_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

struct tr_file {
    char filename[FILENAME_LEN_MAX];
    unsigned int filename_len;
};

struct tr_text {
    char text[TEXT_LEN_MAX];
    unsigned int text_len;
};

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

#endif  // BAD_BPF_COMMON_H
