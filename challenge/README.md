# NoteService CTF Challenge

**Category:** Binary Exploitation (pwn)  
**Architecture:** x86_64 Linux  
**Difficulty:** Hard  
**Mitigations:** Full Hardening (ASLR, NX, Stack Canaries, PIE, Full RELRO, CFI, Fortify Source)

## Description

A networked note-taking service with multiple memory corruption vulnerabilities that must be chained together to achieve remote code execution. The binary is compiled with all modern exploit mitigations enabled.

## Vulnerabilities

### 1. Format String Vulnerability (Info Leak)
**Location:** `cmd_write()` and `cmd_profile()` functions  
**Trigger:** `write <idx> <data>` and `profile` commands  
**Root Cause:** User-controlled data passed directly to `snprintf()` as format string:
```c
char fmtbuf[1024];
snprintf(fmtbuf, sizeof(fmtbuf), data);  // data is user-controlled!
send_all(c->fd, fmtbuf, strlen(fmtbuf));
```

**Impact:** Leaks stack canary, PIE base address, libc base address, heap addresses, and stack pointers.

### 2. Heap Buffer Overflow
**Location:** `cmd_edit()` function  
**Trigger:** `edit <idx> <offset> <data>` command  
**Root Cause:** Bounds check uses `capacity` but allows writing up to capacity boundary:
```c
if (offset + len > c->notes[idx].capacity) {
    send_all(c->fd, "Out of bounds\n", 14);
    return;
}
memcpy(c->notes[idx].content + offset, data, len);
```

**Impact:** Can overflow into adjacent heap metadata or neighboring chunks. Combined with UAF, enables arbitrary write primitive.

### 3. Use-After-Free
**Location:** `cmd_delete()` function  
**Trigger:** `delete <idx>` command  
**Root Cause:** Pointer not nulled after free (it is nulled but cookie check can be bypassed):
```c
free(c->notes[idx].content);
c->notes[idx].content = NULL;  // Set to NULL but...
c->notes[idx].in_use = 0;
// ...cookie remains valid until reallocation
```

**Impact:** Freed chunk can be reallocated with controlled data. Cookie validation uses XOR with predictable session cookie.

### 4. Stack Buffer Overflow (Protected)
**Location:** Various functions using fixed-size stack buffers  
**Mitigation:** Stack canary prevents direct exploitation  
**Bypass:** Requires canary leak from format string vulnerability

## Exploit Chain

```
┌─────────────────────────────────────────────────────────────┐
│                    EXPLOIT CHAIN                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. FORMAT STRING (write)                                    │
│     ├── Leak stack canary                                    │
│     ├── Leak PIE base (return address)                       │
│     ├── Leak libc base (__libc_start_main)                   │
│     └── Leak heap addresses                                  │
│                      │                                       │
│                      ▼                                       │
│  2. HEAP MANIPULATION                                        │
│     ├── Create chunks (0x200, 0x200, 0x100)                 │
│     ├── Delete chunk (UAF)                                   │
│     ├── Overflow adjacent chunk metadata                     │
│     └── Reallocate to control freed chunk                    │
│                      │                                       │
│                      ▼                                       │
│  3. ARBITRARY WRITE PRIMITIVE                                │
│     ├── Forge fake chunk with controlled fd/bk              │
│     ├── Target: GOT entry / function pointer / __free_hook  │
│     └── Write target address                                 │
│                      │                                       │
│                      ▼                                       │
│  4. CODE EXECUTION                                           │
│     ├── Option A: Overwrite __free_hook → system            │
│     ├── Option B: Stack pivot + ROP chain                   │
│     ├── Option C: FSOP (File Stream Oriented Programming)   │
│     └── Option D: Ret2dlresolve                             │
│                      │                                       │
│                      ▼                                       │
│  5. FLAG READ                                                │
│     └── cat /flag.txt                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Building

```bash
make
```

## Running

```bash
# Terminal 1: Start server
./noteservice

# Terminal 2: Test connection
nc localhost 1337
```

## Testing the Vulnerabilities

```bash
# Format string leak
register testuser
create 100
write 0 AAAA%lx.%lx.%lx.%lx.%lx

# Heap overflow
create 200
create 200
edit 0 200 AAAAAAAA  # Overflow

# UAF
create 100
delete 2
create 100  # Reallocate freed chunk
```

## Mitigations Enabled

| Mitigation | Status |
|------------|--------|
| ASLR | ✅ Enforced by kernel |
| NX (DEP) | ✅ `-z noexecstack` |
| Stack Canaries | ✅ `-fstack-protector-strong` |
| PIE | ✅ `-fPIE -pie` |
| Full RELRO | ✅ `-z relro -z now` |
| CFI (Shadow Stacks) | ✅ `-fcf-protection=full -z shstk` |
| Fortify Source | ✅ Built-in (level 3) |
| Stack Clash Protection | ✅ `-fstack-clash-protection` |

## Solution Approach

1. **Information Gathering**: Use format string to leak all necessary addresses
2. **Heap Feng Shui**: Arrange heap layout for controlled overflow/UAF
3. **Arbitrary Write**: Convert heap corruption into write-what-where
4. **Bypass Full RELRO**: Target writable function pointers or use FSOP/ROP
5. **Execute Shell**: Get RCE and read flag

## Files

- `vuln.c` - Vulnerable source code
- `Makefile` - Build system with hardening flags
- `flag.txt` - Flag file (read by binary at startup)
- `solve.py` - Exploit skeleton (to be completed)
- `README.md` - This file

## Learning Objectives

- Format string exploitation for info leaks
- Heap exploitation (overflow + UAF chaining)
- Bypassing modern mitigations (Full RELRO, CFI, PIE)
- Heap feng shui and layout manipulation
- ROP chain construction under constraints
- File Stream Oriented Programming (FSOP)

## Author

Created for advanced binary exploitation training.