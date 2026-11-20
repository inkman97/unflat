#include <stdint.h>

enum { OP_PUSH, OP_LOAD, OP_STORE, OP_ADD, OP_SUB, OP_XOR, OP_MUL, OP_JNZ, OP_HALT };

static const uint8_t program[] = {
    OP_PUSH, 0, 0, 0, 0,   OP_STORE, 0,          /* acc = 0             */
    OP_PUSH, 5, 0, 0, 0,   OP_STORE, 1,          /* n = 5               */
    OP_LOAD, 0,            OP_LOAD, 1,           /* loop: acc + n * 3   */
    OP_PUSH, 3, 0, 0, 0,   OP_MUL,   OP_ADD,
    OP_PUSH, 0x5A, 0, 0, 0, OP_XOR,  OP_STORE, 0, /* acc ^= 0x5a         */
    OP_LOAD, 1,            OP_PUSH, 1, 0, 0, 0,
    OP_SUB,                OP_STORE, 1,          /* n -= 1              */
    OP_LOAD, 1,            OP_JNZ, 0xDF,         /* if n goto loop      */
    OP_LOAD, 0,            OP_HALT,
};

__declspec(dllexport) __attribute__((noinline)) int64_t vm_run(void)
{
    int64_t stack[32], vars[4] = {0};
    int sp = 0;
    const uint8_t *ip = program;
    static void *table[] = {&&op_push, &&op_load, &&op_store, &&op_add, &&op_sub, &&op_xor, &&op_mul, &&op_jnz, &&op_halt};
#define NEXT goto *table[*ip++]
    NEXT;
op_push:  stack[sp++] = *(const int32_t *)ip; ip += 4; NEXT;
op_load:  stack[sp++] = vars[*ip++]; NEXT;
op_store: vars[*ip++] = stack[--sp]; NEXT;
op_add:   sp--; stack[sp - 1] += stack[sp]; NEXT;
op_sub:   sp--; stack[sp - 1] -= stack[sp]; NEXT;
op_xor:   sp--; stack[sp - 1] ^= stack[sp]; NEXT;
op_mul:   sp--; stack[sp - 1] *= stack[sp]; NEXT;
op_jnz:   { int8_t off = (int8_t)*ip++; if (stack[--sp]) ip += off; } NEXT;
op_halt:  return stack[sp - 1];
}

int main(void) { return (int)vm_run(); }
