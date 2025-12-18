#include "utils.h"

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>

int parse_int(const char* str, int* out)
{
    char* endptr = NULL;
    long num;

    num = strtol(str, &endptr, 10);
    if (*endptr != '\0' || num > INT_MAX || num < INT_MIN) {
        return 1;
    }
    *out = num;

    return 0;
}