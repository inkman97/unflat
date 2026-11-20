#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

static int classify(int c)
{
    switch (c) {
    case 'a': return 1; case 'b': return 7; case 'c': return 3; case 'd': return 9;
    case 'e': return 4; case 'f': return 8; case 'g': return 2; case 'h': return 6;
    default: return 0;
    }
}

static int tokenize(const char *s)
{
    int sum = 0;
    for (; *s; s++) {
        switch (*s) {
        case '+': sum += 1; break; case '-': sum -= 1; break; case '*': sum *= 2; break;
        case '/': sum /= 2; break; case '%': sum %= 7; break; case '^': sum ^= 5; break;
        default: sum += classify(*s);
        }
    }
    return sum;
}

typedef int (*op_fn)(int, int);
static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static op_fn ops[] = {add, sub, mul, add, sub, mul};

int main(int argc, char **argv)
{
    int v[16];
    for (int i = 0; i < 16; i++) v[i] = rand() % 100;
    qsort(v, 16, sizeof v[0], cmp);
    int r = tokenize(argc > 1 ? argv[1] : "ab+cd*ef-gh/");
    for (int i = 0; i < 6; i++) r = ops[i](r, v[i]);
    printf("%d %zu\n", r, strlen(argv[0]));
    return 0;
}
