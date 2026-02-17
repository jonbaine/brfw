// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <libgen.h>
#include <limits.h>
#include "brfw.skel.h"
#include "common_um.h"
#include "common.h"

#define MAX_BINARIES MAX_ENTRIES

struct watched_binary {
    char path[PATH_MAX];
    struct bin_key key;
    int watch_fd;   // inotify watch descriptor, for lookup on event
};

static struct watched_binary watched[MAX_BINARIES];
static int num_watched;

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

static void handle_inotify(int inotify_fd, int map_fd)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t len = read(inotify_fd, buf, sizeof(buf));
    if (len <= 0) return;

    char *ptr = buf;
    while (ptr < buf + len) {
        struct inotify_event *ev = (struct inotify_event *)ptr;

        for (int i = 0; i < num_watched; i++) {
            // Match by basename of path against ev->name
            const char *base = strrchr(watched[i].path, '/');
            base = base ? base + 1 : watched[i].path;
            if (ev->len == 0 || strcmp(ev->name, base) != 0) continue;

            struct stat st;
            if (stat(watched[i].path, &st) != 0) {
                fprintf(stderr, "Warning: cannot stat %s after update: %s\n",
                        watched[i].path, strerror(errno));
                continue;
            }

            struct bin_key new_key = {
                .ino = st.st_ino,
                .dev = (major(st.st_dev) << 20) | minor(st.st_dev),
                ._pad = 0,
            };

            if (new_key.ino == watched[i].key.ino &&
                new_key.dev == watched[i].key.dev) continue; // no change

            printf("Binary updated: %s ino=%lu->%lu\n",
                   watched[i].path,
                   (unsigned long)watched[i].key.ino,
                   (unsigned long)new_key.ino);
            fflush(stdout);

            __u8 val = 1;
            bpf_map_delete_elem(map_fd, &watched[i].key);
            bpf_map_update_elem(map_fd, &new_key, &val, BPF_ANY);
            watched[i].key = new_key;
        }

        ptr += sizeof(struct inotify_event) + ev->len;
    }
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct brfw_bpf *skel;
    int err;
    int inotify_fd = -1;
    int ep_fd = -1;

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

    // Resolve binary paths to inode/device pairs, stored in watched[]
    for (int i = 0; i < env.num_binaries; i++) {
        struct stat st;
        strncpy(watched[i].path, env.binaries[i], PATH_MAX - 1);
        watched[i].path[PATH_MAX - 1] = '\0';
        if (stat(watched[i].path, &st) != 0) {
            fprintf(stderr, "Failed to stat '%s': %s\n", watched[i].path, strerror(errno));
            exit(1);
        }
        watched[i].key.ino = st.st_ino;
        // Convert userspace dev_t to kernel's internal format: (major << 20) | minor
        watched[i].key.dev = (major(st.st_dev) << 20) | minor(st.st_dev);
        watched[i].key._pad = 0;
        watched[i].watch_fd = -1;
        printf("Binary: %s -> ino=%lu dev=%u (major=%u minor=%u)\n",
               watched[i].path, (unsigned long)watched[i].key.ino, watched[i].key.dev,
               major(st.st_dev), minor(st.st_dev));
    }
    num_watched = env.num_binaries;

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
    for (int i = 0; i < num_watched; i++) {
        __u8 val = 1;
        err = bpf_map_update_elem(map_fd, &watched[i].key, &val, BPF_ANY);
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

    // Set up inotify to watch parent directories of monitored binaries.
    // We watch directories (not files) because inotify on a file misses rename-over events.
    inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd < 0) {
        fprintf(stderr, "Failed to create inotify fd: %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }

    for (int i = 0; i < num_watched; i++) {
        char dir[PATH_MAX];
        strncpy(dir, watched[i].path, PATH_MAX - 1);
        dir[PATH_MAX - 1] = '\0';
        dirname(dir);   // mutates in place
        watched[i].watch_fd = inotify_add_watch(inotify_fd, dir,
            IN_MOVED_TO | IN_CLOSE_WRITE | IN_CREATE);
        if (watched[i].watch_fd < 0) {
            fprintf(stderr, "Failed to watch directory '%s': %s\n", dir, strerror(errno));
            err = -1;
            goto cleanup;
        }
    }

    // Set up epoll to multiplex ring buffer fd and inotify fd
    ep_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ep_fd < 0) {
        fprintf(stderr, "Failed to create epoll fd: %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }

    int rb_fd = ring_buffer__epoll_fd(rb);

    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = rb_fd;
    if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, rb_fd, &ev) < 0) {
        fprintf(stderr, "Failed to add ring buffer fd to epoll: %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }

    ev.events = EPOLLIN;
    ev.data.fd = inotify_fd;
    if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, inotify_fd, &ev) < 0) {
        fprintf(stderr, "Failed to add inotify fd to epoll: %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }

    printf("brfw started in %s mode with %d binaries\n",
           env.fw_mode == FW_MODE_BLOCKLIST ? "blocklist" : "allowlist",
           env.num_binaries);

    while (!exiting) {
        struct epoll_event events[2];
        int n = epoll_wait(ep_fd, events, 2, 100);
        if (n < 0 && errno == EINTR) break;

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == rb_fd) {
                int poll_err = ring_buffer__poll(rb, 0);
                if (poll_err < 0 && poll_err != -EINTR) {
                    fprintf(stderr, "Error polling ring buffer: %d\n", poll_err);
                    goto cleanup;
                }
            } else if (events[i].data.fd == inotify_fd) {
                handle_inotify(inotify_fd, map_fd);
            }
        }
    }

cleanup:
    if (inotify_fd >= 0) close(inotify_fd);
    if (ep_fd >= 0) close(ep_fd);
    ring_buffer__free(rb);
    brfw_bpf__destroy(skel);
    return -err;
}
