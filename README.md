# eBPF Instruction Set Simulator (ISS)

An eBPF instruction set simulator for hardware verification that parses LLVM-compiled eBPF relocatable object files and generates execution traces in a format that can be used for Hardware verification.

## Features

- Parses relocatable ELF object files (`.o`) compiled from eBPF programs
- Simulates eBPF instruction execution
- Generates execution traces with register and memory updates
- Supports all major eBPF instruction classes:
  - ALU/ALU64 operations (register and immediate)
  - Memory operations (LD, ST, LDX, STX)
  - Jump instructions (JMP, JMP32)
  - Special instructions (EXIT, MOV, etc.)
- Configurable stack pointer (r10) initialization
- Human-readable disassembly matching objdump format

## Requirements

- Python 3.6 or higher
- LLVM/Clang (for compiling eBPF programs)

## Installation

No installation required. Simply ensure you have Python 3 installed:

```bash
python3 --version
```

## Usage

### Basic Usage

```bash
python3 main.py <input_file.o> [-o output_file] [--r10 value]
```

### Command-Line Options

- `input_file`: Path to the LLVM-compiled eBPF relocatable object file (`.o`)
- `-o, --output`: Optional output file path (default: stdout)
- `--r10`: Optional initial value for r10 (stack pointer) in hex (e.g., `0x1000`) or decimal (e.g., `4096`)

### Examples

```bash
# Run simulator and output to stdout
python3 main.py bpf.o

# Save output to a file
python3 main.py bpf.o -o trace.txt

# Set initial stack pointer to 0x1000
python3 main.py bpf.o --r10 0x1000

# Set initial stack pointer to 4096 (decimal)
python3 main.py bpf.o --r10 4096 -o trace.txt
```

## Generating eBPF Object Files

This simulator works with relocatable ELF object files compiled from eBPF programs. You can generate compatible object files using LLVM/Clang.

### Method 1: Compile C to eBPF Assembly, then Assemble

Based on the [LLVM eBPF assembly guide](https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/):

1. **Compile C source to eBPF assembly:**
   ```bash
   clang -target bpf -S -o bpf.s bpf.c
   ```

2. **Assemble to ELF object file:**
   ```bash
   llvm-mc -triple bpf -filetype=obj -o bpf.o bpf.s
   ```

### Method 2: Direct Compilation (Simple Programs)

For simple programs, you can compile directly:

```bash
clang -target bpf -Wall -O2 -c bpf.c -o bpf.o
```

### Method 3: Using llc (For More Complex Programs)

Some programs may need the `-mcpu` option:

```bash
clang -O2 -emit-llvm -c bpf.c -o - | \
    llc -march=bpf -mcpu=probe -filetype=obj -o bpf.o
```

### Example eBPF Program

Create a simple eBPF program in C:

```c
// bpf.c
int func()
{
    return 0;
}
```

Compile it:

```bash
clang -target bpf -S -o bpf.s bpf.c
llvm-mc -triple bpf -filetype=obj -o bpf.o bpf.s
```

Then run the simulator:

```bash
python3 main.py bpf.o
```

### Viewing the Object File

You can inspect the compiled eBPF object file using `llvm-objdump`:

```bash
llvm-objdump -d bpf.o
```

For disassembly with source code (if compiled with `-g`):

```bash
llvm-objdump -S bpf.o
```

## Output Format

The simulator generates execution traces in the following format:

```
<address>;<instruction_bytes>;<disassembly>;[<register_updates>]
```

Where:
- `address`: Instruction address in hex (8 digits)
- `instruction_bytes`: Raw instruction bytes in hex (uppercase)
- `disassembly`: Human-readable assembly instruction
- `register_updates`: Optional semicolon-separated list of register/memory updates

### Example Output

```
0x00000000;0xB701000000000000;r1 = 0;r1=0x0000000000000000
0x00000008;0x631AFCFF00000000;*(u32 *)(r10 - 0x4) = r1;mem[0x00000000FFFFFFFC]=0x0000000000000000
0x00000010;0xBF10000000000000;r0 = r1;r0=0x0000000000000000
0x00000018;0x9500000000000000;exit;exit
```

### Register Update Format

- Register updates: `r<num>=0x<value>` (16 hex digits)
- Memory updates: `mem[0x<address>]=0x<value>` (16 hex digits)

## eBPF Registers

The simulator models all 11 eBPF registers (R0-R10):

- **R0**: Return value
- **R1-R5**: Function arguments (caller-saved)
- **R6-R9**: Callee-saved registers
- **R10**: Read-only frame pointer (stack pointer)

## Limitations

- Only supports relocatable ELF files (ET_REL), not executables
- Helper function calls (CALL instruction) are not implemented
- Maximum instruction execution limit: 10,000 instructions (safety limit)
- Stack size: 512 bytes

## References

- [eBPF ISA v1.0 Specification](https://www.ietf.org/archive/id/draft-thaler-bpf-isa-00.html)
- [LLVM eBPF Assembly Guide](https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/)
- [BPF and XDP Reference Guide (Cilium)](https://docs.cilium.io/en/latest/bpf/)

## License

Apache 2.0 License