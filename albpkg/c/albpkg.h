#ifndef ALBPKG_H
#define ALBPKG_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Review candidate, not independently audited. Never links to C512. */
typedef struct alb_identity alb_identity;
typedef struct { unsigned char pubid[3150]; int trust; } alb_contact;
enum { ALB_OK=0, ALB_ERROR=-1, ALB_UNVERIFIED=0, ALB_VERIFIED=1, ALB_REVOKED=2 };
typedef enum {
 ALB_ERR_NONE=0,
 ALB_ERR_ARGUMENT,
 ALB_ERR_PROVIDER,
 ALB_ERR_MEMORY,
 ALB_ERR_IO,
 ALB_ERR_FORMAT,
 ALB_ERR_AUTHENTICATION,
 ALB_ERR_TRUST,
 ALB_ERR_PERMISSION,
 ALB_ERR_CANCELLED,
 ALB_ERR_LIMIT,
 ALB_ERR_EXISTS,
 ALB_ERR_INTERNAL
} alb_error_code;
/* The last error is thread-local and is cleared at each public API entry. */
alb_error_code alb_last_error(void);
const char *alb_error_string(alb_error_code code);
/* Callback returning nonzero cancels before publication. */
typedef int (*alb_cancel)(void *user);
typedef int (*alb_passphrase)(void *user, unsigned char *out, size_t capacity,
                             size_t *length, int confirm);
int alb_generate_identity(alb_identity **out);
int alb_identity_from_seeds(const unsigned char kem[64], const unsigned char sig[32], alb_identity **out);
void alb_identity_free(alb_identity *identity);
int alb_export_public_identity(const alb_identity*,unsigned char *out,size_t capacity);
int alb_save_identity(const alb_identity*,const char *path,alb_passphrase,void*,int overwrite);
int alb_load_identity(const char *path,alb_passphrase,void*,alb_identity **out);
/* Explicit ALBPKSK2 migration. The source is never modified or deleted. */
int alb_migrate_legacy_identity(const char *source,const char *target,alb_passphrase,void*,int overwrite,alb_identity **out);
int alb_import_contact(const unsigned char*,size_t,alb_contact*);
int alb_verify_contact(alb_contact*,const unsigned char fingerprint[32]);
void alb_revoke_contact(alb_contact*);
int alb_fingerprint(const unsigned char pubid[3150],unsigned char out[32]);
/* Paths are UTF-8. Existing destinations are never overwritten. */
int alb_seal_file(const alb_identity*,const alb_contact*,const char *source,const char *destination,alb_cancel,void*);
int alb_open_file(const alb_identity*,const alb_contact*,const char *source,const char *destination,alb_cancel,void*);
/* Explicit overwrite variants still publish atomically at the final step. */
int alb_seal_file_mode(const alb_identity*,const alb_contact*,const char *source,const char *destination,int overwrite,alb_cancel,void*);
int alb_open_file_mode(const alb_identity*,const alb_contact*,const char *source,const char *destination,int overwrite,alb_cancel,void*);
#ifdef __cplusplus
}
#endif
#endif
