/* Compile as its own translation unit: includes the implementation to inject
 * allocator failures, without exposing allocator controls in the library API. */
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#define ALB_C512_EXPERIMENTAL 1
static int fail_allocations;
static void *test_calloc(size_t n, size_t size) {
    return fail_allocations ? NULL : calloc(n, size);
}
#define calloc test_calloc
#include "c512.c"
#undef calloc

int main(void) {
    uint8_t key[64] = {0}, nonce[32] = {0}, input[16] = {1};
    uint8_t ciphertext[48], output[64];
    size_t written = 999;
    assert(c512_research_run(C512_ENCRYPT, key, 64, nonce, 32, NULL, 0,
        input, 16, 0, ciphertext, 48, &written) == C512_OK && written == 48);
    assert(c512_research_run(C512_ENCRYPT, key, 64, nonce, 32, NULL, 0,
        input, 16, 0, output, 47, &written) == C512_CAPACITY && written == 0);
    assert(c512_research_run(C512_ENCRYPT, key, 64, nonce, 32, NULL, 0,
        input, 16, 0, key, 64, &written) == C512_OVERLAP);
    assert(c512_research_run(C512_ENCRYPT, key, 64, nonce, 32, NULL, 0,
        input, SIZE_MAX, 0, output, 64, &written) == C512_INVALID);
    assert(c512_research_run(C512_XOF, NULL, 64, NULL, 0, NULL, 0,
        NULL, 0, 32, output, 64, &written) == C512_INVALID);
    ciphertext[0] ^= 1;
    memset(output, 0x55, sizeof(output));
    assert(c512_research_run(C512_DECRYPT, key, 64, nonce, 32, NULL, 0,
        ciphertext, 48, 0, output, 64, &written) == C512_FAILED && written == 0);
    for (size_t i = 0; i < 16; ++i) assert(output[i] == 0);
    fail_allocations = 1;
    memset(output, 0x55, sizeof(output));
    assert(c512_research_run(C512_XOF, key, 64, NULL, 0, input, 16,
        NULL, 0, 32, output, 64, &written) == C512_FAILED && written == 0);
    for (size_t i = 0; i < 32; ++i) assert(output[i] == 0);
    assert(c512_research_run(C512_SIV_ENCRYPT, key, 64, NULL, 0, NULL, 0,
        NULL, 0, 0, output, 64, &written) == C512_FAILED && written == 0);
    for (size_t i = 0; i < 64; ++i) assert(output[i] == 0);
    return 0;
}
