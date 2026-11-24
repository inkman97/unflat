/* Hand-made control-flow flattening through memory-indirect jumps (`jmp [mem]`).
 * Same algorithm as flat.c, but every block leaves through a pointer read from a table in .data:
 *   - unconditional edges:  lea slot, reg ; jmp [reg]                                   (unflat: "goto")
 *   - conditional edges:    lea a, r1 ; lea b, r2 ; cmovCC r2, r1 ; jmp [r1]             (unflat: "cond")
 *   - indexed edges:        xor rcx, rcx ; setCC cl ; lea table, r1 ; jmp [r1 + rcx*8]   (unflat: "cond")
 * L_loop has a flag-safe filler after the cmov; L_body has an `imul` after the selector, so both patches go
 * through a code cave (the filler alone doesn't leave room for jcc + jmp next to it).
 *
 * Builds as an x64 PE (mingw) or an x86-64 ELF (gcc/clang). The result must not change after `unflat flat -o`.
 */
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#define ARG0 "%rcx"
#define FN_BEGIN ".globl flat_mem\n.def flat_mem; .scl 2; .type 32; .endef\n.seh_proc flat_mem\nflat_mem:\n.seh_endprologue\n"
#define FN_END ".seh_endproc\n"
#else
#define ARG0 "%rdi"
#define FN_BEGIN ".globl flat_mem\n.type flat_mem, @function\nflat_mem:\n.cfi_startproc\n"
#define FN_END ".cfi_endproc\n.size flat_mem, .-flat_mem\n"
#endif

int64_t flat_mem(int64_t n);

__asm__(
    ".data\n"
    ".balign 8\n"
    "T_loop:  .quad L_loop\n"
    "T_body:  .quad L_body\n"
    "T_done:  .quad L_done\n"
    "T_par:   .quad L_odd, L_even\n"     /* index 0 = odd, 1 = even (sete) */
    "T_next:  .quad L_next\n"
    ".text\n"
    FN_BEGIN
    "    mov  " ARG0 ", %r8\n"        /* n            */
    "    xor  %eax, %eax\n"           /* acc = 0      */
    "    xor  %r9d, %r9d\n"           /* i = 0        */
    "    lea  T_loop(%rip), %rdx\n"
    "    jmp  *(%rdx)\n"
    "L_loop:\n"                       /* i < n ? body : done */
    "    lea  T_body(%rip), %rdx\n"
    "    lea  T_done(%rip), %r10\n"
    "    cmp  %r8, %r9\n"
    "    cmovge %r10, %rdx\n"
    "    movabs $0x1122334455667788, %r11\n"  /* flag-safe filler: room for jcc + jmp */
    "    jmp  *(%rdx)\n"
    "L_body:\n"                       /* i odd ? odd : even, with acc *= 0x10001 in between */
    "    xor  %ecx, %ecx\n"
    "    test $1, %r9\n"
    "    sete %cl\n"
    "    lea  T_par(%rip), %rdx\n"
    "    imul $0x10001, %rax, %rax\n"      /* not flag-safe: needs a code cave */
    "    jmp  *(%rdx,%rcx,8)\n"
    "L_odd:\n"
    "    add  %r9, %rax\n"
    "    lea  T_next(%rip), %rdx\n"
    "    jmp  *(%rdx)\n"
    "L_even:\n"
    "    xor  $0x5a, %rax\n"
    "    jmp  *T_next(%rip)\n"            /* rip-relative slot */
    "L_next:\n"
    "    inc  %r9\n"
    "    lea  T_loop(%rip), %rdx\n"
    "    jmp  *(%rdx)\n"
    "L_done:\n"
    "    ret\n"
    FN_END
);

int main(void)
{
    for (int64_t n = 0; n < 12; n++)
        printf("%lld ", (long long)flat_mem(n));
    printf("\n");
    return 0;
}
