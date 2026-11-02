#ifndef C512_H
#define C512_H
#ifndef ALB_C512_EXPERIMENTAL
#error "C512 is broken research cryptography; explicitly define ALB_C512_EXPERIMENTAL"
#endif
#include <stdint.h>
#include <stddef.h>
#define C512_KEY_SIZE 64
#define C512_NONCE_SIZE 32
#define C512_TAG_SIZE 32
#define C512_STATE_SIZE 128
#define C512_RATE_SIZE 64
#define C512_LANES 32
#define C512_RESEARCH_LIMIT ((size_t)16777216)
#define C512_MAX_INPUT C512_RESEARCH_LIMIT
/* Internal error taxonomy retained for existing research self-tests. */
enum { C512_ERR_NULL=-10, C512_ERR_LENGTH=-11, C512_ERR_OVERFLOW=-12,
 C512_ERR_CAPACITY=-13, C512_ERR_ALLOC=-14, C512_ERR_OVERLAP=-15,
 C512_ERR_AUTH=-16, C512_ERR_SELFTEST=-17 };
typedef enum { C512_OK=0, C512_INVALID=-1, C512_CAPACITY=-2, C512_OVERLAP=-3, C512_FAILED=-4 } c512_status;
typedef enum { C512_ENCRYPT, C512_DECRYPT, C512_SIV_ENCRYPT, C512_SIV_DECRYPT, C512_XOF } c512_operation;
/* Breaking safety API. No overlapping regions. XOF uses aad as context and
 * requested as output length; other operations require requested=0.
 * Non-AEAD operations require nonce_len=0. On processing failure, output is
 * cleared and *written=0. Bad caller pointers cannot be validated by C.
 */
c512_status c512_research_run(c512_operation op,
 const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len,
 const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
 size_t requested, uint8_t *out, size_t capacity, size_t *written);
int c512_self_test(void);
#endif
