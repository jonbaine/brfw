# brfw - Binary-path based eBPF Firewall

brfw is a Linux application firewall that blocks or allows `connect` and `bind` syscalls based on the binary path of the calling process.

It uses eBPF `fmod_ret` hooks to intercept syscalls before they execute, and matches processes by inode + device number for fast, reliable lookups inside the kernel.

## How it works

1. You specify binary paths (e.g. `/usr/bin/curl`) and a firewall mode (allowlist or blocklist)
2. brfw resolves each path to an `(inode, device)` pair via `stat()`
3. An eBPF program attached to `connect` and `bind` syscalls reads the calling process's executable inode from `task->mm->exe_file->f_inode`
4. A hash map lookup determines whether to allow or block the syscall
5. Events are streamed to userspace via a ring buffer

## Requirements

- Linux kernel 5.7+ with BTF support
- clang, llvm-strip, bpftool
- libbpf (built from the included submodule)
- Root privileges to run

## Building

```bash
cd src
make brfw
```

The binary is placed in `src/bin/brfw`.

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
[BLOCKED] connect PID 1234 (curl)
[ALLOWED] connect PID 5678 (bash)
[BLOCKED] bind PID 9012 (nc)
```

## Architecture

- **`src/brfw.bpf.c`** - eBPF kernel program with `fmod_ret` hooks on connect/bind
- **`src/brfw.c`** - Userspace loader, CLI argument parsing, ring buffer consumer
- **`src/common.h`** - Shared data structures between kernel and userspace

## Limitations

- Matches by inode, so replacing a binary on disk (e.g. via package update) changes its identity
- `fmod_ret` requires kernel 5.7+ and may not be available on all configurations
- Only intercepts `connect` and `bind` syscalls (not `sendto`, `sendmsg`, etc.)
