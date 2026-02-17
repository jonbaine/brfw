// SPDX-License-Identifier: BSD-3-Clause
// Minimal program that attempts connect() to 127.0.0.1:1.
// Exit codes:
//   0 — connect returned ECONNREFUSED (syscall was allowed)
//   1 — connect returned EPERM (syscall was blocked by BPF)
//   2 — unexpected error

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 2;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(1),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(fd);

    if (ret == 0) {
        // Unexpected success
        fprintf(stderr, "connect unexpectedly succeeded\n");
        return 2;
    }

    if (err == EPERM || err == EACCES) {
        fprintf(stderr, "connect: %s (blocked by BPF)\n", strerror(err));
        return 1;
    }

    if (err == ECONNREFUSED) {
        fprintf(stderr, "connect: %s (syscall allowed)\n", strerror(err));
        return 0;
    }

    fprintf(stderr, "connect: %s (unexpected)\n", strerror(err));
    return 2;
}
