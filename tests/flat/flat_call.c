/* Hand-made control-flow flattening through register-indirect calls (`call reg`).
 * Two flavours of target, which need different patches:
 *   - blocks that throw the return address away as their first instruction
 *     (`lea 8(%rsp), %rsp`, `add $8, %rsp` or `pop` into a dead register): the call is only a jump in disguise;
 *   - helpers that end in `ret` and come back right after the call: the return address must stay the same.
 * L_loop and L_odd have flag-safe fillers after the cmov to leave room for the patch; L_body has an `imul` there,
 * so its patch needs a code cave.
 *
 * Builds as an x64 PE (mingw) or an x86-64 ELF (gcc/clang). The result must not change after `unflat flat -o`.
 */
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#define ARG0 "%rcx"
#define FN_BEGIN ".globl flat_call\n.def flat_call; .scl 2; .type 32; .endef\n.seh_proc flat_call\nflat_call:\n.seh_endprologue\n"
#define FN_END ".seh_endproc\n"
#else
#define ARG0 "%rdi"
#define FN_BEGIN ".globl flat_call\n.type flat_call, @function\nflat_call:\n.cfi_startproc\n"
#define FN_END ".cfi_endproc\n.size flat_call, .-flat_call\n"
#endif

int64_t flat_call(int64_t n);

__asm__(
    ".text\n"
    FN_BEGIN
    "    mov  " ARG0 ", %r8\n"        /* n            */
    "    xor  %eax, %eax\n"           /* acc = 0      */
    "    xor  %r9d, %r9d\n"           /* i = 0        */
    "    lea  L_loop(%rip), %rdx\n"
    "    call *%rdx\n"                /* goto, target discards the return address */
    "L_loop:\n"                       /* i < n ? body : done */
    "    lea  8(%rsp), %rsp\n"
    "    lea  L_body(%rip), %rdx\n"
    "    lea  L_done(%rip), %r10\n"
    "    cmp  %r8, %r9\n"
    "    cmovge %r10, %rdx\n"
    "    movabs $0x1122334455667788, %r11\n"  /* flag-safe filler: room for jcc + jmp */
    "    call *%rdx\n"
    "L_body:\n"                       /* i odd ? odd : even, with acc *= 0x10001 in between */
    "    add  $8, %rsp\n"                  /* clobbers flags, but test rewrites them before any read */
    "    lea  L_odd(%rip), %rdx\n"
    "    lea  L_even(%rip), %r10\n"
    "    test $1, %r9\n"
    "    cmovz %r10, %rdx\n"
    "    imul $0x10001, %rax, %rax\n"      /* not flag-safe: needs a code cave */
    "    call *%rdx\n"
    "L_odd:\n"
    "    pop  %r11\n"                      /* r11 is dead: overwritten by the next instruction */
    "    xor  %r11d, %r11d\n"
    "    add  %r9, %rax\n"
    "    lea  H_add(%rip), %rdx\n"
    "    lea  H_mul(%rip), %r10\n"
    "    test $2, %r9\n"
    "    cmovnz %r10, %rdx\n"
    "    mov  $0x1234, %r11d\n"            /* flag-safe filler: room for jcc + call */
    "    call *%rdx\n"                     /* cond call to helpers that return here */
    "    lea  L_next(%rip), %rdx\n"
    "    call *%rdx\n"
    "L_even:\n"
    "    lea  8(%rsp), %rsp\n"
    "    xor  $0x5a, %rax\n"
    "    lea  H_add(%rip), %rcx\n"
    "    call *%rcx\n"                     /* goto call to a helper that returns here */
    "    lea  L_next(%rip), %rdx\n"
    "    call *%rdx\n"
    "L_next:\n"
    "    pop  %r11\n"
    "    xor  %r11d, %r11d\n"
    "    inc  %r9\n"
    "    lea  L_loop(%rip), %rdx\n"
    "    call *%rdx\n"
    "L_done:\n"
    "    lea  8(%rsp), %rsp\n"
    "    ret\n"
    "H_add:\n"
    "    add  $3, %rax\n"
    "    ret\n"
    "H_mul:\n"
    "    imul $3, %rax, %rax\n"
    "    ret\n"
    FN_END
);

int main(void)
{
    for (int64_t n = 0; n < 12; n++)
        printf("%lld ", (long long)flat_call(n));
    printf("\n");
    return 0;
}
