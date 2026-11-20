# unflat

Three helpers for obfuscated x64 PE files:

- **`unflat scan`**: tells you, per function, whether the code is control-flow flattened or runs a bytecode VM, and which command to run next.
- **`unflat flat`**: resolves the register-indirect dispatchers of control-flow flattened code and patches them back into direct jumps, so that Ghidra, IDA or r2 can follow the code again.
- **`unflat vm`**: traces a function protected by a bytecode virtual machine and reports the dispatcher, the handlers, the bytecode and the virtual program it runs.

## Install

```
pip install git+https://github.com/inkman97/unflat.git
```

or, from a clone, `pip install .`

Works on Linux and Windows (Python 3.9+, capstone, unicorn, pefile).

## Mode 0: scan

Static and fast (no emulation): a first look before choosing a mode.

```
unflat scan sample.dll            # summary and the most flattened functions
unflat scan sample.dll -v         # every flagged function
```

For each function it counts:

- `jmp reg` instructions and how many of them are preceded by a `cmovCC`/`setCC` that selects the target (flattening dispatchers), plus `ud2` opaque predicate traps;
- byte fetches (`movzx reg, byte [reg]`) whose value indexes a table of 8-byte pointers right before an indirect `jmp`/`call` (VM opcode dispatch);
- tables of code pointers in data sections that the function references (handler tables).

It also prints section names and entropy, and points out protector section names (`.vmp*`, `.themida`, `.winlice`, `.enigma*`, UPX...) and high-entropy executable sections.

Example on WardenStealer stage 1:

```
verdict: control-flow flattening in 3 function(s)
  0x1800011dd    6265 insns  jmp-reg 354  selected 311  ud2 21   -> unflat flat -f 0x1800011dd -l out.txt
  0x18000a346     221 insns  jmp-reg 11   selected 10   ud2 1    -> unflat flat -f 0x18000a346 -l out.txt
  0x180009faa     161 insns  jmp-reg 6    selected 5    ud2 0    -> unflat flat -f 0x180009faa -l out.txt
```

and on the toy VM:

```
verdict: bytecode VM suspected in 1 function(s)
  0x140001580      96 insns  fetch+dispatch sites 6   handler tables: 0x140004060 (9 entries)  -> unflat vm -e 0x140001580
```

Tested for false positives on `tests/clean/clean.c` (switch statements, `qsort`, a table of function pointers): nothing flagged. The scan is a heuristic: confirm with `flat` or `vm`.

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

1. Every `jmp reg` in executable sections is a candidate dispatcher.
2. Each block is emulated with Unicorn twice, forcing the selecting `cmovCC` or `setCC` both ways, with two random sets of unknown inputs. A target that does not change between the random runs is resolved.
3. When a block depends on values set earlier (a state index, a base register, a table pointer spilled to the stack), unflat walks the function from its entry and carries known register and stack values from block to block. Calls are stepped over, and real conditional jumps are followed both ways.
4. A branch that lands on `ud2`/`int3` is an opaque predicate and becomes an unconditional jump.
5. The tail of the block is rewritten in place. Instructions between the `cmov` and the `jmp` that must still run are kept; if they change flags they are moved, together with the jump, into a small `.unflat` section.

Function entries come from `.pdata`. For memory dumps without it (e.g. pe-sieve output) they come from the entry point, the exports and every direct `call` target.

### Ghidra

Disable the **Shared Return Calls** analyzer before auto-analysis, otherwise Ghidra splits the patched function at every jump target. In headless mode use `ghidra/NoSharedReturn.java` as a pre-script:

```
analyzeHeadless <project_dir> <name> -import sample.unflat.dll -scriptPath ghidra -preScript NoSharedReturn.java
```

### Output categories

| status | meaning |
|---|---|
| `cond` | two targets selected by a condition, patched to `jcc` + `jmp` |
| `goto` | single target (including removed opaque predicates), patched to `jmp` |
| `context` | target depends on the incoming path; reported, not patched |
| `switch` | compiler jump table with an index register (not flattening); left alone |
| `unresolved` | could not be resolved |

Dispatchers that are never reached from any function entry are usually dead blocks added by the obfuscator.

### Results on WardenStealer

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

- x64 PE only; dispatchers of the `jmp reg` kind (no `call reg`, no `jmp [mem]`).
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

`tests/toyvm/` holds a small stack VM in two flavours (threaded `jmp reg` dispatch, and a central `call [table]` loop). Build with mingw:

```
x86_64-w64-mingw32-gcc -O2 -o toyvm.exe tests/toyvm/toyvm.c
x86_64-w64-mingw32-gcc -O2 -o toyvm_call.exe tests/toyvm/toyvm_call.c
x86_64-w64-mingw32-gcc -O2 -o clean.exe tests/clean/clean.c
```

Both give the same virtual program, matching the C source:

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
