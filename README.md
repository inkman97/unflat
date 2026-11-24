# unflat

Three helpers for obfuscated x86-64 code, in Windows PE and Linux ELF files:

- **`unflat scan`**: tells you, per function, whether the code is control-flow flattened or runs a bytecode VM, and which command to run next.
- **`unflat flat`**: resolves the indirect dispatchers of control-flow flattened code (`jmp reg`, `jmp [mem]`, `call reg`, `call [mem]`) and patches them back into direct jumps, so that Ghidra, IDA or r2 can follow the code again.
- **`unflat vm`**: traces a function protected by a bytecode virtual machine and reports the dispatcher, the handlers, the bytecode and the virtual program it runs.

## Install

```
pip install git+https://github.com/inkman97/unflat.git
```

or, from a clone, `pip install .`

Works on Linux and Windows (Python 3.9+, capstone, unicorn, pefile, pyelftools).

## PE and ELF

The file format is detected from the magic bytes; every mode works the same on both.

| | PE (x64) | ELF (x86-64) |
|---|---|---|
| addresses | `ImageBase`-based | `p_vaddr` (0-based for PIE / static-pie, like r2 and objdump) |
| function ranges | `.pdata` | `.symtab`/`.dynsym` sizes and `.eh_frame` FDEs; `.eh_frame_hdr` through `PT_GNU_EH_FRAME` when section headers are stripped |
| fallback | entry point, exports, direct `call` targets | entry point, symbols, direct `call` targets |
| `vm -e` name | export | symbol |
| arguments (`vm -a`) | `rcx`, `rdx`, `r8`, `r9` | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` |
| thread block in the emulator | TEB at `gs:0` | TCB at `fs:0`, stack canary at `fs:0x28` |
| imports in the emulator | unmapped, return on first fetch | GOT/PLT slots point to `ret` stubs; `memset`, `memcpy`, `memmove`, `mempcpy`, `bzero`, `strlen` are emulated |
| relocations in the emulator | not needed (preferred base) | `RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `R_X86_64_64` applied; `IRELATIVE` ifuncs resolved by running the resolver |
| code cave for `flat -o` | new `.unflat` section | a `PT_NOTE` program header turned into a new `R+X` `PT_LOAD` at the end of the file |

ELF support covers executables, PIE, static and static-pie binaries and shared objects, with or without symbols and section headers.

## Mode 0: scan

Static and fast (no emulation): a first look before choosing a mode.

```
unflat scan sample.dll            # summary and the most flattened functions
unflat scan sample.dll -v         # every flagged function
```

For each function it counts:

- indirect dispatchers (`jmp reg` and `jmp [mem]`, plus `call reg` / `call [mem]` when a `cmovCC`/`setCC` comes right before them) and how many of them are preceded by a `cmovCC`/`setCC` that selects the target, plus `ud2` opaque predicate traps;
- byte fetches (`movzx reg, byte [reg]`) whose value indexes a table of 8-byte pointers right before an indirect `jmp`/`call` (VM opcode dispatch);
- tables of code pointers in data sections that the function references (handler tables).

It also prints section names and entropy, and points out protector section names (`.vmp*`, `.themida`, `.winlice`, `.enigma*`, UPX...) and high-entropy executable sections.

Example on WardenStealer stage 1:

```
verdict: control-flow flattening in 3 function(s)
  0x1800011dd    6265 insns  indirect 354  selected 311  ud2 21   -> unflat flat -f 0x1800011dd -l out.txt
  0x18000a346     221 insns  indirect 11   selected 10   ud2 1    -> unflat flat -f 0x18000a346 -l out.txt
  0x180009faa     161 insns  indirect 6    selected 5    ud2 0    -> unflat flat -f 0x180009faa -l out.txt
```

and on the toy VM:

```
verdict: bytecode VM suspected in 1 function(s)
  0x140001580      96 insns  fetch+dispatch sites 6   handler tables: 0x140004060 (9 entries)  -> unflat vm -e 0x140001580
```

Tested for false positives on `tests/clean/clean.c` (switch statements, `qsort`, a table of function pointers): nothing flagged. The scan is a heuristic: confirm with `flat` or `vm`. On statically linked ELF binaries, glibc's `printf` internals (a byte-indexed table of computed `goto` targets) can show up as a VM candidate.

## Mode 1: flat

Flattened code ends every block with something like:

```
cmp    rax, rdi
lea    rcx, [table_a]
lea    rdx, [table_b]
cmova  rdx, rcx
movsxd rcx, dword [rdx]
add    rcx, r14          ; r14 = base set once at function entry
jmp    rcx
```

Disassemblers stop at `jmp rcx`. unflat works out where each of these jumps can go and rewrites the tail as `jcc taken / jmp fallthrough`.

The last instruction can also read the target from memory, or be a call:

| dispatcher | example | how the target is read |
|---|---|---|
| `jmp reg` | `jmp rcx` | register value at the jump |
| `jmp [mem]` | `jmp qword [rdx + rcx*8]`, `jmp qword [rip + slot]` | 8 bytes at the effective address, read from the emulated memory (so tables filled or decrypted at runtime are seen as they are at the jump) |
| `call reg` | `call rdx` | register value at the call |
| `call [mem]` | `call qword [rax + 0x10]` | as `jmp [mem]` |

A `call` used as a dispatcher also pushes a return address, and the patch has to respect what the target does with it:

- **discard**: every target throws it away as its first instruction (`lea rsp, [rsp + 8]`, `add rsp, 8` with the flags rewritten before they are read, or `pop` into a register that is overwritten before it is read). The call is really a jump: it is patched as one, straight to the instruction after the discard.
- **keep**: anything else (for example helpers that end in `ret` and come back after the call). The patch pushes exactly the return address the original call pushed: a goto becomes a direct `call target` that ends where the original call ended; a conditional one becomes `jcc` to a cave stub that pushes the return address and jumps, plus a direct `call` for the other target. The push is position-independent and leaves flags and registers untouched.

`-v` shows the kind of each dispatcher and, for calls, the mode chosen.

### Usage

```
unflat flat sample.dll -o sample.unflat.dll       # patched copy
unflat flat sample.dll -l listing.txt -d cfg.dot  # recovered flow, no patching
unflat flat sample.dll -v                         # every dispatcher and its targets
unflat flat dump.dll -f 0x180001000 -l main.txt   # listing for one function
```

`flat` is the default mode, so `unflat sample.dll -o out.dll` works too.

The patched file is for static analysis only. Do not run it.

### How it works

1. Every `jmp reg` and `jmp [mem]` in executable sections is a candidate dispatcher. A `call reg` / `call [mem]` is a candidate when a `cmovCC`/`setCC` picks its target, or (`call reg`) when the register is loaded with a constant code address in the same block; calls through function pointers are left alone. Memory slots filled by the loader (IAT, GOT, IRELATIVE/ifunc) and `[base + index*scale]` jumps whose index is loaded from memory in the same block (VM opcode fetches, see `unflat vm`) are skipped.
2. Each block is emulated with Unicorn twice, forcing the selecting `cmovCC` or `setCC` both ways, with two random sets of unknown inputs. A target that does not change between the random runs is resolved.
3. When a block depends on values set earlier (a state index, a base register, a table pointer spilled to the stack), unflat walks the function from its entry and carries known register and stack values from block to block. Calls are stepped over, and real conditional jumps are followed both ways.
4. A branch that lands on `ud2`/`int3` is an opaque predicate and becomes an unconditional jump.
5. The tail of the block is rewritten in place. Instructions between the `cmov` and the `jmp` that must still run are kept; if they change flags, or don't leave room for the new jumps, they are moved, together with the jump, into a small code cave: a new `.unflat` section in a PE, a new `PT_LOAD` segment in an ELF.

Function entries come from `.pdata` (PE) or from symbols and `.eh_frame` (ELF). For memory dumps without them (e.g. pe-sieve output) they come from the entry point, the exports or symbols, and every direct `call` target.

### Ghidra

Disable the **Shared Return Calls** analyzer before auto-analysis, otherwise Ghidra splits the patched function at every jump target. In headless mode use `ghidra/NoSharedReturn.java` as a pre-script:

```
analyzeHeadless <project_dir> <name> -import sample.unflat.dll -scriptPath ghidra -preScript NoSharedReturn.java
```

### Output categories

| status | meaning |
|---|---|
| `cond` | two targets selected by a condition, patched to `jcc` + `jmp` |
| `goto` | single target (including removed opaque predicates), patched to `jmp` (or a direct `call` for a call dispatcher in keep mode) |
| `context` | target depends on the incoming path; reported, not patched |
| `switch` | compiler jump table with an index register (not flattening); left alone |
| `unresolved` | could not be resolved |

Dispatchers that are never reached from any function entry are usually dead blocks added by the obfuscator.

### Test

Three small hand-flattened functions, one per dispatcher family. Each builds as a PE or an ELF, and its output must be the same before and after patching:

| test | dispatchers | expected |
|---|---|---|
| `tests/flat/flat.c` | `cmov` + `jmp reg` | 2 cond + 4 goto, all patched |
| `tests/flat/flat_mem.c` | `jmp [reg]`, `jmp [reg + index*8]` selected by `setCC`, `jmp [rip + slot]` | 2 cond + 4 goto, all patched |
| `tests/flat/flat_call.c` | `call reg` into blocks that discard the return address, and into helpers that return | 3 cond + 5 goto, all patched (6 discard, 2 keep) |

```
gcc -O2 -o flat_call.elf tests/flat/flat_call.c
unflat flat flat_call.elf -o flat_call.unflat.elf
./flat_call.elf; ./flat_call.unflat.elf      # same numbers
```

They give the same output before and after patching as PIE, non-PIE and static-pie stripped ELF. The PE builds were checked by running the original and the patched function in an emulator, since there was no Windows host at hand.

Running the patched file is only meant for this test program you built yourself; patched samples are for static analysis.

### Results on WardenStealer

Measured with version 0.3.0 (before `jmp [mem]` / `call` support and the code-cave fallback for flag-safe instructions).

| | stage 1 (fake jli.dll) | stage 2 (in-memory payload) |
|---|---|---|
| dispatchers found | 408 | 2668 |
| reachable from a function entry | 311 | 1703 |
| resolved (reachable) | 285 | 1664 |
| unresolved (reachable) | 1 | 10 |
| patched | 349 | 2141 |
| run time | ~10 s | ~50 s |

Ghidra 12, Shared Return Calls disabled, same function before and after patching:

| function | before | after |
|---|---|---|
| stage 1 main (`0x1800011dd`) | 443 bytes, 23 lines of C | 22 149 bytes, 1845 lines |
| stage 2 HTTP client (`0x15fafa9fba3`) | 165 bytes, 25 lines | 7 327 bytes, 707 lines |
| stage 2 environment checks (`0x15fafa851f8`) | 37 862 bytes, 4994 lines | 37 862 bytes, 4792 lines (lightly flattened already) |

No `halt_baddata` or unrecovered jump tables in any of them.

### Limits

- x86-64 only (PE and ELF; no 32-bit, no ARM).
- `call reg` with a constant target is only taken as a dispatcher when the register is loaded in the same block; `call [mem]` only when a `cmov`/`setCC` picks the target. A call whose targets don't simply discard the return address is patched in "keep" mode, which is correct but less readable in a decompiler than a plain jump.
- `jmp [base + index*scale]` without a `cmov`/`setCC` and with a data-dependent index (compiler switch, VM dispatch) is left alone or reported as `switch`.
- The ELF code cave reuses a `PT_NOTE` program header; a file without one gets only the in-place patches (the ones that need a cave are reported as not patchable).
- Values only known at runtime (read from TLS, the heap, or produced by a call) cannot be resolved statically; such dispatchers are reported, not guessed.
- The result is correct control flow, not the original source structure: loops and `if`s come back as whatever the decompiler rebuilds from the patched jumps.

## Mode 2: vm

A VM-protected function no longer contains the original logic as x86 code: it holds bytecode and an interpreter that reads an opcode, jumps to the matching handler, and repeats. `unflat vm` emulates the function and reports:

- the **dispatch sites**: indirect `jmp`/`call` instructions that reach several handlers (a central loop or threaded code where every handler jumps to the next one);
- the **handlers**, how often each one runs, and a guess of what it does;
- the **bytecode** range and the **opcode** of each virtual instruction (the last byte/word read before each dispatch);
- the **virtual program**: one line per bytecode position, with opcode, handler, operand bytes and the values computed;
- the full **execution trace** of the virtual instructions.

### Usage

```
unflat vm sample.exe -e vm_run                 # entry by export name
unflat vm sample.exe -e 0x140001580 -a 0x10    # entry by address, rcx = 0x10
unflat vm sample.exe -e 0x140001580 -o vm.txt  # report to a file
unflat vm sample.elf -e vm_run -a 5            # ELF: symbol name, rdi = 5
```

### How handlers are classified

For each execution of a handler, unflat compares the values written to memory with the values read:

| guess | evidence |
|---|---|
| `add`, `sub`, `xor`, `and`, `mul`, `shl`, `shr` | a written value equals that operation on two values read, and the handler contains the matching x86 (or SSE) instruction |
| `push-const` | a written value equals the operand bytes read from the bytecode |
| `move` | a written value is a copy of a value read (load, store, push of a variable) |
| `branch` | the next opcode is not read right after this instruction's operands |
| `exit` | the last handler before the function returns |

The handler's label is the most frequent guess over all its executions.

### Example

`tests/toyvm/` holds a small stack VM in two flavours (threaded `jmp reg` dispatch, and a central `call [table]` loop). Build with mingw for PE, or with gcc for ELF:

```
x86_64-w64-mingw32-gcc -O2 -o toyvm.exe tests/toyvm/toyvm.c
x86_64-w64-mingw32-gcc -O2 -o toyvm_call.exe tests/toyvm/toyvm_call.c
x86_64-w64-mingw32-gcc -O2 -o clean.exe tests/clean/clean.c

gcc -O2 '-D__declspec(x)=' -o toyvm.elf tests/toyvm/toyvm.c
gcc -O2 '-D__declspec(x)=' -static-pie -s -o toyvm_static.elf tests/toyvm/toyvm.c
```

Both flavours, PE or ELF (dynamic, non-PIE, static-pie stripped), give the same virtual program, matching the C source:

```
+0000  op ??  H00  push-const  00000000   const 0x0
+0005  op 02  H03  move        00         value 0x0 index 0
+0007  op 00  H00  push-const  05000000   const 0x5
+000c  op 02  H03  move        01         value 0x5 index 1
+000e  op 01  H04  move        00         value 0x0 index 0
...
+0017  op 06  H07  mul         -          0x3 mul 0x5 = 0xf
+0018  op 03  H05  add         -          value 0xf
+001e  op 05  H08  xor         -          0x5a xor 0xf = 0x55
+0028  op 04  H01  sub         -          0x5 sub 0x1 = 0x4
+002d  op 07  H06  branch      df         vip 0x1400040ed -> 0x1400040ce
+0031  op 08  H02  exit        -          returns 0xdb
```

The first opcode shows `??` because the compiler jumps straight to the first handler without reading it.

### Limits

- This is analysis, not automatic devirtualization: it maps the VM and its program, it does not rebuild x86 code.
- Classification is value-based and can be wrong: handlers that do several things, VMs that encrypt the bytecode or the opcode, or mutated handler copies need the analyst to read the handler code (its address and body are in the report).
- Only what runs is seen: one trace covers one path through the virtual program.
- API calls are stubbed (they return immediately), so code that depends on their results may take a different path than on a real machine.
- Commercial protectors (VMProtect, Themida) add layers this does not handle on its own: obfuscated handlers, encrypted virtual registers, anti-emulation checks.
