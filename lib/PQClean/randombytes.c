#include <stdlib.h>

#include "randombytes.h"

extern void e2ees_randombytes(uint8_t *, size_t);

int randombytes(uint8_t *output, size_t output_len) {
    e2ees_randombytes(output, output_len);
    return 0;
}
