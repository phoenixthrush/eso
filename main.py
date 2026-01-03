# -------------------------------
# Registers
# -------------------------------
regs = {
    "EAX": 0,  # current syscall code
    "EBX": 0,  # general-purpose value register, e.g., for printing or arithmetic
    "ECX": "",  # e.g., strings from input
    "EDX": 0,  # e.g., single character input
    "ESI": 0,
    "EDI": 0,
    "EBP": 0,
    "ESP": 0,
    "ZF": 0,  # zero flag: set by CMP, checked by JZ / JNZ for branching
    "SF": 0,  # sign flag: can track if last arithmetic result was negative
    "CF": 0,  # carry flag: can track overflow in unsigned arithmetic
    "OF": 0,  # overflow flag: can track overflow in signed arithmetic
}

# -------------------------------
# Syscall Table
# -------------------------------
syscalls = {
    1: lambda: print(regs["EBX"], end=""),
    # SYSCALL 1: Print the integer stored in EBX
    # Usage: Load value to print into EBX, set EAX = 1, then call SYSCALL
    2: lambda: exit(0),
    # SYSCALL 2: Exit the program immediately
    # Usage: Set EAX = 2, then call SYSCALL
    3: lambda: regs.update({"EBX": int(input())}),
    # SYSCALL 3: Read an integer from user input and store it in EBX
    # Usage: Set EAX = 3, then call SYSCALL; the program waits for input
    4: lambda: regs.update({"ECX": input(regs["ECX"] if regs["ECX"] else "")}),
    # SYSCALL 4: Read a string from user input and store it in ECX
    # Usage: Load prompt string into ECX, set EAX = 4, then call SYSCALL
    # If ECX is empty, no prompt is shown
    5: lambda: regs.update({"EDX": ord(input()[0])}),
    # SYSCALL 5: Read a single character from user input
    # The ASCII code of the character is stored in EDX
    # Usage: Set EAX = 5, then call SYSCALL; only the first character is used
    6: lambda: print(f"Registers: {regs}"),
    # SYSCALL 6: Print the current values of all registers (debug)
    # Usage: Set EAX = 6, then call SYSCALL
    7: lambda: print(f"Current syscall code: {regs['EAX']}"),
    # SYSCALL 7: Print the current value of the syscall code (EAX)
    # Useful for debugging programs that manipulate EAX
    8: lambda: regs.update({"EBX": ~regs["EBX"]}),
    # SYSCALL 8: Bitwise NOT operation on EBX
    # Flips every bit in EBX:
    # Example: EBX = 5 (00000101) → ~EBX = -6 (11111010 in two's complement)
    # Usage: Set EAX = 8, EBX must hold the value to invert, then call SYSCALL
    9: lambda: print(),
    # SYSCALL 9: Print a newline character
    # Usage: Set EAX = 9, then call SYSCALL
    10: lambda: print(regs["ECX"], end=""),
    # SYSCALL 10: Print the string stored in ECX
    # Usage: Load string into ECX, set EAX = 10, then call SYSCALL
    11: lambda: regs.update(
        {"EBX": __import__("random").randint(0, 18446744073709551615)}
    ),
    # SYSCALL 11: Generate random integer between 0 and 2^64-1 and store in EBX
    # Usage: Set EAX = 11, then call SYSCALL
    # Range: 0 to 18446744073709551615 (full 64-bit unsigned range)
}


# -------------------------------
# Helper: Update CPU flags
# -------------------------------
def update_flags(result, dest_val_before=0, op_type=None, src_val=0):
    """
    Updates ZF, SF, CF, OF flags after an arithmetic operation.
    """
    # Zero Flag
    regs["ZF"] = int(result == 0)
    # Sign Flag
    regs["SF"] = int(result < 0)
    # Carry Flag (unsigned overflow)
    if op_type == "ADD":
        regs["CF"] = int(result < dest_val_before)
    elif op_type == "SUB":
        regs["CF"] = int(dest_val_before < src_val)
    elif op_type == "MOD":
        regs["CF"] = int(dest_val_before < src_val)
    else:
        regs["CF"] = 0
    # Overflow Flag (signed overflow)
    if op_type == "ADD":
        regs["OF"] = int(
            (dest_val_before > 0 and src_val > 0 and result < 0)
            or (dest_val_before < 0 and src_val < 0 and result > 0)
        )
    elif op_type == "SUB":
        regs["OF"] = int(
            (dest_val_before > 0 and src_val < 0 and result < 0)
            or (dest_val_before < 0 and src_val > 0 and result > 0)
        )
    elif op_type == "MOD":
        regs["OF"] = 0  # Modulo can't overflow
    else:
        regs["OF"] = 0


# -------------------------------
# Parse Program from Text
# -------------------------------
def parse_program(raw_text):
    program = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):  # skip empty lines or full-line comments
            continue
        # Remove inline comments
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        if line.endswith(":"):  # label
            program.append(("LABEL", line[:-1]))
        else:
            # Handle quoted strings properly
            import shlex

            parts = shlex.split(line)
            op = parts[0].upper()
            args = []
            for a in parts[1:]:
                try:
                    args.append(int(a))
                except ValueError:
                    args.append(a)
            program.append((op, *args))
    return program


# -------------------------------
# Execute Program
# -------------------------------
def execute(program):
    # map labels to instruction indices
    labels = {instr[1]: i for i, instr in enumerate(program) if instr[0] == "LABEL"}
    ip = 0

    while ip < len(program):
        instr = program[ip]
        op = instr[0]

        if op == "MOV":
            _, dest, src = instr
            if isinstance(src, str) and src in regs:
                regs[dest] = regs[src]
            else:
                regs[dest] = src
            ip += 1

        elif op == "ADD":
            _, dest, src = instr
            src_val = regs[src] if isinstance(src, str) else src
            before = regs[dest]
            regs[dest] += src_val
            update_flags(regs[dest], before, "ADD", src_val)
            ip += 1

        elif op == "SUB":
            _, dest, src = instr
            src_val = regs[src] if isinstance(src, str) else src
            before = regs[dest]
            regs[dest] -= src_val
            update_flags(regs[dest], before, "SUB", src_val)
            ip += 1

        elif op == "INC":
            _, reg = instr
            before = regs[reg]
            regs[reg] += 1
            update_flags(regs[reg], before, "ADD", 1)
            ip += 1

        elif op == "DEC":
            _, reg = instr
            before = regs[reg]
            regs[reg] -= 1
            update_flags(regs[reg], before, "SUB", 1)
            ip += 1

        elif op == "MUL":
            _, dest, src = instr
            src_val = regs[src] if isinstance(src, str) else src
            before = regs[dest]
            regs[dest] *= src_val
            update_flags(regs[dest], before, "MUL", src_val)
            ip += 1

        elif op == "DIV":
            _, dest, src = instr
            src_val = regs[src] if isinstance(src, str) else src
            if src_val == 0:
                raise ZeroDivisionError(f"Division by zero in instruction {instr}")
            before = regs[dest]
            regs[dest] //= src_val
            update_flags(regs[dest], before, "DIV", src_val)
            ip += 1

        elif op == "MOD":
            _, dest, src = instr
            src_val = regs[src] if isinstance(src, str) else src
            if src_val == 0:
                raise ZeroDivisionError(f"Modulo by zero in instruction {instr}")
            before = regs[dest]
            regs[dest] %= src_val
            update_flags(regs[dest], before, "MOD", src_val)
            ip += 1

        elif op == "CMP":
            _, reg, value = instr
            val = regs[value] if isinstance(value, str) else value
            result = regs[reg] - val
            regs["ZF"] = int(result == 0)
            regs["SF"] = int(result < 0)
            regs["OF"] = 0  # we can ignore signed overflow for small integers
            ip += 1

        elif op == "JNZ":
            _, target = instr
            if regs["ZF"] == 0:
                ip = labels[target] if isinstance(target, str) else target
            else:
                ip += 1

        elif op == "JZ":
            _, target = instr
            if regs["ZF"] == 1:
                ip = labels[target] if isinstance(target, str) else target
            else:
                ip += 1

        elif op == "JG":  # jump if greater
            _, target = instr
            if regs["ZF"] == 0 and regs["SF"] == regs["OF"]:
                ip = labels[target]
            else:
                ip += 1

        elif op == "JL":  # jump if less
            _, target = instr
            if regs["SF"] != regs["OF"]:
                ip = labels[target]
            else:
                ip += 1

        elif op == "SYSCALL":
            code = regs["EAX"]
            if code in syscalls:
                syscalls[code]()
            else:
                print(f"Invalid SYSCALL code: {code}")
            ip += 1

        elif op == "JMP":
            _, target = instr
            ip = labels[target] if isinstance(target, str) else target

        elif op == "LABEL":
            ip += 1


# -------------------------------
# CPU Registers
# -------------------------------
# EAX: current syscall code
# EBX: general-purpose value register (used for printing, arithmetic, bitwise ops)
# ECX: general-purpose, e.g., store strings from input
# EDX: general-purpose, e.g., single character input (ASCII code)
# ESI
# EDI
# EBP
# ESP
# ZF : zero flag – set by CMP, checked by JZ / JNZ
# SF : sign flag – set if last arithmetic result was negative
# CF : carry flag – set if unsigned arithmetic overflow occurs
# OF : overflow flag – set if signed arithmetic overflow occurs

# -------------------------------
# Opcodes
# -------------------------------
# MOV dest src   -> move value from src (register or integer) into dest
# ADD dest src   -> add src to dest (register or integer)
# SUB dest src   -> subtract src from dest
# INC reg        -> increment register by 1
# DEC reg        -> decrement register by 1
# MUL dest src   -> multiply dest by src
# DIV dest src   -> divide dest by src (integer division)
# MOD dest src   -> remainder of dest divided by src
# CMP reg value  -> Compare register with value (sets ZF)
# JZ label       -> jump to label if ZF == 1
# JNZ label      -> jump to label if ZF == 0
# SYSCALL        -> call the syscall defined in EAX
# LABEL name     -> defines a label for jumps

# -------------------------------
# Syscalls
# -------------------------------
# EAX must contain the syscall code before calling SYSCALL
# 1  -> print integer stored in EBX
# 2  -> exit program
# 3  -> read integer from user input into EBX
# 4  -> read string from user input into ECX
# 5  -> read single character from user input into EDX (ASCII code)
# 6  -> print all registers (debug)
# 7  -> print current syscall code (EAX)
# 8  -> bitwise NOT on EBX (flips all bits, two's complement)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python main.py <program_file>")
        sys.exit(1)
    program = parse_program(open(sys.argv[1]).read())
    execute(program)
