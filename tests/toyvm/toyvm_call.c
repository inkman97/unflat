#include <stdint.h>

typedef struct vm { const uint8_t *ip; int64_t stack[32], vars[4]; int sp, halt; } vm_t;

static const uint8_t program[] = {
    0, 0, 0, 0, 0,  2, 0,  0, 5, 0, 0, 0,  2, 1,
    1, 0,  1, 1,  0, 3, 0, 0, 0,  6,  3,  0, 0x5A, 0, 0, 0,  5,  2, 0,
    1, 1,  0, 1, 0, 0, 0,  4,  2, 1,  1, 1,  7, 0xDF,  1, 0,  8,
};

static void op_push(vm_t *v)  { v->stack[v->sp++] = *(const int32_t *)v->ip; v->ip += 4; }
static void op_load(vm_t *v)  { v->stack[v->sp++] = v->vars[*v->ip++]; }
static void op_store(vm_t *v) { v->vars[*v->ip++] = v->stack[--v->sp]; }
static void op_add(vm_t *v)   { v->sp--; v->stack[v->sp - 1] += v->stack[v->sp]; }
static void op_sub(vm_t *v)   { v->sp--; v->stack[v->sp - 1] -= v->stack[v->sp]; }
static void op_xor(vm_t *v)   { v->sp--; v->stack[v->sp - 1] ^= v->stack[v->sp]; }
static void op_mul(vm_t *v)   { v->sp--; v->stack[v->sp - 1] *= v->stack[v->sp]; }
static void op_jnz(vm_t *v)   { int8_t off = (int8_t)*v->ip++; if (v->stack[--v->sp]) v->ip += off; }
static void op_halt(vm_t *v)  { v->halt = 1; }

static void (*const handlers[])(vm_t *) = {op_push, op_load, op_store, op_add, op_sub, op_xor, op_mul, op_jnz, op_halt};

__declspec(dllexport) __attribute__((noinline)) int64_t vm_run(void)
{
    vm_t v = {program};
    while (!v.halt)
        handlers[*v.ip++](&v);
    return v.stack[v.sp - 1];
}

int main(void) { return (int)vm_run(); }
