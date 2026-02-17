// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "writeblocker.skel.h"
#include "common_um.h"
#include "common.h"

#define MAX_BINARIES MAX_ENTRIES

static struct env {
    char *binaries[MAX_BINARIES];
    int num_binaries;
    int action; // WB_ACTION_*
} env = {
    .action = WB_ACTION_DISCARD,
};

const char *argp_program_version = "writeblocker 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Writeblocker - eBPF write syscall interceptor\n"
"\n"
"Intercepts write syscalls for specified binaries.\n"
"\n"
"USAGE: ./writeblocker -b /usr/bin/curl [-b /usr/bin/wget] [-a block|discard]\n";

static const struct argp_option opts[] = {
    { "binary", 'b', "PATH", 0, "Binary path to intercept writes for (repeatable)" },
    { "action", 'a', "ACTION", 0, "Action: block (-EPERM) or discard (fake success, default)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'b':
        if (env.num_binaries >= MAX_BINARIES) {
            fprintf(stderr, "Too many binaries (max %d)\n", MAX_BINARIES);
            argp_usage(state);
        }
        env.binaries[env.num_binaries++] = arg;
        break;
    case 'a':
        if (strcmp(arg, "block") == 0) {
            env.action = WB_ACTION_BLOCK;
        } else if (strcmp(arg, "discard") == 0) {
            env.action = WB_ACTION_DISCARD;
        } else {
            fprintf(stderr, "Invalid action: %s (use 'block' or 'discard')\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static const char *action_label(int action)
{
    switch (action) {
    case WB_ACTION_BLOCK:   return "BLOCKED";
    case WB_ACTION_DISCARD: return "DISCARDED";
    default:                return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct wb_event *e = data;
    if (e->syscall == WB_SYS_OPENAT) {
        printf("[%s] openat PID %d (%s) flags=0%o\n",
               action_label(e->action), e->pid, e->comm, e->fd);
    } else {
        printf("[%s] write  PID %d (%s) fd=%d\n",
               action_label(e->action), e->pid, e->comm, e->fd);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct writeblocker_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        exit(1);
    }

    if (env.num_binaries == 0) {
        fprintf(stderr, "Must supply at least one binary path (-b /path/to/binary)\n");
        exit(1);
    }

    // Resolve binary paths to inode/device pairs
    struct bin_key keys[MAX_BINARIES];
    for (int i = 0; i < env.num_binaries; i++) {
        struct stat st;
        if (stat(env.binaries[i], &st) != 0) {
            fprintf(stderr, "Failed to stat '%s': %s\n", env.binaries[i], strerror(errno));
            exit(1);
        }
        keys[i].ino = st.st_ino;
        keys[i].dev = (major(st.st_dev) << 20) | minor(st.st_dev);
        keys[i]._pad = 0;
        printf("Binary: %s -> ino=%lu dev=%u (major=%u minor=%u)\n",
               env.binaries[i], (unsigned long)keys[i].ino, keys[i].dev,
               major(st.st_dev), minor(st.st_dev));
    }

    skel = writeblocker_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Set action before loading
    skel->rodata->wb_action = env.action;

    err = writeblocker_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Populate the binary map
    int map_fd = bpf_map__fd(skel->maps.bin_map);
    for (int i = 0; i < env.num_binaries; i++) {
        __u8 val = 1;
        err = bpf_map_update_elem(map_fd, &keys[i], &val, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to add binary to map: %s\n", strerror(errno));
            goto cleanup;
        }
    }

    err = writeblocker_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("writeblocker started: %s writes from %d binaries\n",
           env.action == WB_ACTION_BLOCK ? "blocking" : "discarding",
           env.num_binaries);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    writeblocker_bpf__destroy(skel);
    return -err;
}
