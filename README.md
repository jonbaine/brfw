# brfw - eBPF Application Firewall

brfw is a Linux application firewall that blocks or allows `connect` and `bind` syscalls based on the binary path of the calling process.

It uses eBPF `fmod_ret` hooks to intercept syscalls before they execute, and matches processes by inode + device number for fast, reliable lookups inside the kernel.

brfw automatically refreshes monitored inodes in response to package manager updates, with no restart required.

> [!WARNING]
> Only **ARM64** and **x86-64** kernels are supported. All other architectures are not supported at this time.

## About the name

brfw means -literally- _brotxis firewall_, which is a lovely joke name that I share with my wife.

## How it works

1. You specify binary paths (e.g. `/usr/bin/curl`) and a firewall mode (allowlist or blocklist)
2. brfw resolves each path to an `(inode, device)` pair via `stat()`
3. An eBPF program attached to `connect` and `bind` syscalls reads the calling process's executable inode from `task->mm->exe_file->f_inode`
4. A hash map lookup determines whether to allow or block the syscall
5. Events are streamed to userspace via a ring buffer
6. brfw watches the parent directory of each monitored binary with `inotify`; when a binary is replaced on disk (e.g. via an atomic package-manager rename), brfw re-`stat()`s the path, detects the inode change, and atomically updates the eBPF map — no restart required

## Requirements

- Linux kernel 5.7+ with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- Root privileges to run

### Build dependencies

Debian/Ubuntu:

```bash
sudo apt install clang llvm libelf-dev libbpf-dev bpftool pkg-config zlib1g-dev
```

Fedora:

```bash
sudo dnf install clang llvm elfutils-libelf-devel libbpf-devel bpftool pkg-config zlib-devel
```

The Makefile uses `pkg-config` to find libbpf and generates `vmlinux.h` from the running kernel's BTF at build time.

## Building

```bash
cd src
make         # build everything
make brfw    # build brfw only
```

The binaries are placed in `src/bin/`.

## Usage

```bash
# Blocklist mode: block specific binaries, allow everything else
sudo ./bin/brfw -m blocklist -b /usr/bin/curl -b /usr/bin/wget

# Allowlist mode: only allow specific binaries, block everything else
sudo ./bin/brfw -m allowlist -b /usr/bin/curl
```

### Options

| Flag | Description |
|------|-------------|
| `-b PATH` | Binary path to add to the firewall list (repeatable) |
| `-m MODE` | Firewall mode: `allowlist` (default) or `blocklist` |

### Output

brfw prints events as they occur:

```
Binary: /usr/bin/curl -> ino=12345 dev=2049 (major=8 minor=1)
brfw started in blocklist mode with 1 binaries
[BLOCKED] connect PID 1234 (curl)
[ALLOWED] connect PID 5678 (bash)
[BLOCKED] bind PID 9012 (nc)
```

When a monitored binary is replaced on disk, brfw detects the inode change and updates the eBPF map automatically:

```
Binary updated: /usr/bin/curl ino=12345->12399
```

## Writeblocker

Writeblocker intercepts `write` and `openat` syscalls for specified binaries. It uses the same inode-based matching as brfw.

### Building

```bash
cd src
make writeblocker
```

### Usage

```bash
# Silently discard writes from curl (default action)
sudo ./bin/writeblocker -b /usr/bin/curl

# Block writes with -EPERM error
sudo ./bin/writeblocker -a block -b /usr/bin/vim

# Multiple binaries
sudo ./bin/writeblocker -a discard -b /usr/bin/curl -b /usr/bin/wget
```

### Options

| Flag | Description |
|------|-------------|
| `-b PATH` | Binary path to intercept writes for (repeatable) |
| `-a ACTION` | Action: `block` (-EPERM) or `discard` (fake success, default) |

### Actions

- **block** — returns `-EPERM` to the caller for both `write` and `openat`
- **discard** — fakes success for `write` (returns byte count), blocks `openat` with `-EPERM` (can't fake a valid fd)

### Output

```
[DISCARDED] write  PID 1234 (curl) fd=5
[DISCARDED] openat PID 1234 (bash) flags=0601
[BLOCKED]   write  PID 5678 (vim) fd=4
```

The `openat` hook catches write-intent opens (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`), preventing shell redirections like `echo "" > file` from truncating files.

## Testing

### Compile test

Verifies that all BPF objects, skeletons, and userland binaries build successfully. Also runs compile-time static assertions that catch ABI drift (struct size/offset changes).

```bash
cd src
make test-compile
```

### Integration tests

End-to-end tests that exercise brfw with real BPF programs attached. Requires root and a BTF-enabled kernel.

```bash
cd src
make clean && make
sudo ../tests/run_tests.sh
```

Or from the `src/` directory:

```bash
sudo make test
```

The test suite currently includes:

- **test_brfw_allowlist** — starts brfw in allowlist mode with an unrelated binary listed, then verifies that an unlisted binary's `connect()` is blocked with `EPERM`
- **test_brfw_inode_refresh** — atomically replaces a monitored binary (simulating a package manager update), then verifies brfw detects the inode change and continues to enforce the rule on the new binary

Tests that require root will print `SKIP` and exit cleanly when run as a non-root user.

## Architecture

- **`src/brfw.bpf.c`** - eBPF kernel program with `fmod_ret` hooks on connect/bind
- **`src/brfw.c`** - Userspace loader, CLI argument parsing, ring buffer consumer
- **`src/common.h`** - Shared data structures between kernel and userspace

## Limitations

- `fmod_ret` requires kernel 5.7+ and may not be available on all configurations
- Only intercepts `connect` and `bind` syscalls (not `sendto`, `sendmsg`, etc.)

