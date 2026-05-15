
#include <stdio.h>

static int helper(int x) {
    return x + 7;
}

int main(void) {
    puts("hello from xdbg");
    printf("helper(35) = %d\n", helper(35));
    return 0;
}
