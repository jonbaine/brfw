// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "brfw.skel.h"
#include "common_um.h"
#include "common.h"

#define MAX_BINARIES MAX_ENTRIES

static struct env {
    char *binaries[MAX_BINARIES];
    int num_binaries;
    int fw_mode; // 0=allowlist, 1=blocklist
} env;

const char *argp_program_version = "brfw 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"BRFW - Binary-path based eBPF Firewall\n"
"\n"
"Blocks or allows connect/bind syscalls based on binary path.\n"
"\n"
"USAGE: ./brfw -m blocklist -b /usr/bin/curl [-b /usr/bin/wget]\n";

static const struct argp_option opts[] = {
    { "binary", 'b', "PATH", 0, "Binary path to add to firewall list (repeatable)" },
    { "mode", 'm', "MODE", 0, "Firewall mode: allowlist (default) or blocklist" },
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
    case 'm':
        if (strcmp(arg, "blocklist") == 0) {
            env.fw_mode = FW_MODE_BLOCKLIST;
        } else if (strcmp(arg, "allowlist") == 0) {
            env.fw_mode = FW_MODE_ALLOWLIST;
        } else {
            fprintf(stderr, "Invalid mode: %s (use 'allowlist' or 'blocklist')\n", arg);
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

static const char *syscall_name(int sc)
{
    return sc == 0 ? "connect" : "bind";
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct fw_event *e = data;
    printf("[%s] %s PID %d (%s)\n",
           e->action ? "BLOCKED" : "ALLOWED",
           syscall_name(e->syscall),
           e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct brfw_bpf *skel;
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
        // Convert userspace dev_t to kernel's internal format: (major << 20) | minor
        keys[i].dev = (major(st.st_dev) << 20) | minor(st.st_dev);
        keys[i]._pad = 0;
        printf("Binary: %s -> ino=%lu dev=%u (major=%u minor=%u)\n",
               env.binaries[i], (unsigned long)keys[i].ino, keys[i].dev,
               major(st.st_dev), minor(st.st_dev));
    }

    skel = brfw_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Set firewall mode before loading
    skel->rodata->fw_mode = env.fw_mode;

    err = brfw_bpf__load(skel);
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

    err = brfw_bpf__attach(skel);
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

    printf("brfw started in %s mode with %d binaries\n",
           env.fw_mode == FW_MODE_BLOCKLIST ? "blocklist" : "allowlist",
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
    brfw_bpf__destroy(skel);
    return -err;
}
