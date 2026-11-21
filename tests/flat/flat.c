/* Hand-made control-flow flattening, written in assembly so the compiler can't undo it.
 * Every block computes the next block's address and leaves through `jmp reg`:
 *   - unconditional edges:  lea target, reg ; jmp reg                (unflat: "goto")
 *   - conditional edges:    lea a, r1 ; lea b, r2 ; cmovCC r2, r1 ; jmp r1   (unflat: "cond")
 * L_loop has a flag-safe filler after the cmov (patched in place); L_body has an `imul` there, so its
 * patch needs a code cave (a new section in a PE, a new PT_LOAD segment in an ELF).
 *
 * Builds as an x64 PE (mingw) or an x86-64 ELF (gcc/clang). The result must not change after `unflat flat -o`.
 */
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#define ARG0 "%rcx"
#define FN_BEGIN ".globl flat\n.def flat; .scl 2; .type 32; .endef\n.seh_proc flat\nflat:\n.seh_endprologue\n"
#define FN_END ".seh_endproc\n"
#else
#define ARG0 "%rdi"
#define FN_BEGIN ".globl flat\n.type flat, @function\nflat:\n.cfi_startproc\n"
#define FN_END ".cfi_endproc\n.size flat, .-flat\n"
#endif

int64_t flat(int64_t n);

__asm__(
    ".text\n"
    FN_BEGIN
    "    mov  " ARG0 ", %r8\n"        /* n            */
    "    xor  %eax, %eax\n"           /* acc = 0      */
    "    xor  %r9d, %r9d\n"           /* i = 0        */
    "    lea  L_loop(%rip), %rdx\n"
    "    jmp  *%rdx\n"
    "L_loop:\n"                       /* i < n ? body : done */
    "    lea  L_body(%rip), %rdx\n"
    "    lea  L_done(%rip), %r10\n"
    "    cmp  %r8, %r9\n"
    "    cmovge %r10, %rdx\n"
    "    movabs $0x1122334455667788, %r11\n"  /* flag-safe filler: patched in place */
    "    jmp  *%rdx\n"
    "L_body:\n"                       /* i odd ? odd : even, with acc *= 0x10001 in between */
    "    lea  L_odd(%rip), %rdx\n"
    "    lea  L_even(%rip), %r10\n"
    "    test $1, %r9\n"
    "    cmovz %r10, %rdx\n"
    "    imul $0x10001, %rax, %rax\n"      /* not flag-safe: needs a code cave */
    "    jmp  *%rdx\n"
    "L_odd:\n"
    "    add  %r9, %rax\n"
    "    lea  L_next(%rip), %rdx\n"
    "    jmp  *%rdx\n"
    "L_even:\n"
    "    xor  $0x5a, %rax\n"
    "    lea  L_next(%rip), %rdx\n"
    "    jmp  *%rdx\n"
    "L_next:\n"
    "    inc  %r9\n"
    "    lea  L_loop(%rip), %rdx\n"
    "    jmp  *%rdx\n"
    "L_done:\n"
    "    ret\n"
    FN_END
);

int main(void)
{
    for (int64_t n = 0; n < 12; n++)
        printf("%lld ", (long long)flat(n));
    printf("\n");
    return 0;
}
