#!/usr/bin/env python3
max_use = 0
while True:
    try:
        inp = input()
        if not inp.startswith("mem_stacks_B"):
            continue
        splitted = inp.split("=")
        stack_use = int(splitted[1])
        if stack_use > max_use:
            max_use = stack_use
    except EOFError:
        break

print("max stack use:", max_use)