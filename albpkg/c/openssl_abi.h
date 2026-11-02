/* Minimal declarations of the OpenSSL 3.5 public C ABI. No cryptography here.
 * Production builds should use vendor development headers via ALB_OPENSSL_HEADERS.
 * Declarations allow verification against an installed OpenSSL 3.5 DLL as well.
 */
#pragma once
#include <stddef.h>
#ifdef ALB_OPENSSL_HEADERS
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_kdf_st EVP_KDF;
typedef struct evp_kdf_ctx_st EVP_KDF_CTX;
typedef struct {const char *key;unsigned int data_type;void *data;size_t data_size;size_t return_size;} OSSL_PARAM;
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char*,void*,size_t);
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char*,char*,size_t);
OSSL_PARAM OSSL_PARAM_construct_end(void);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(void*,const char*,const char*);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(void*,EVP_PKEY*,const char*);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX*);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX*);
int EVP_PKEY_generate(EVP_PKEY_CTX*,EVP_PKEY**);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX*);
int EVP_PKEY_fromdata(EVP_PKEY_CTX*,EVP_PKEY**,int,OSSL_PARAM*);
int EVP_PKEY_get_octet_string_param(const EVP_PKEY*,const char*,unsigned char*,size_t,size_t*);
void EVP_PKEY_free(EVP_PKEY*);
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX*,const OSSL_PARAM*);
int EVP_PKEY_encapsulate(EVP_PKEY_CTX*,unsigned char*,size_t*,unsigned char*,size_t*);
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX*,const OSSL_PARAM*);
int EVP_PKEY_decapsulate(EVP_PKEY_CTX*,unsigned char*,size_t*,const unsigned char*,size_t);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX*);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha512(void);
int EVP_DigestInit_ex(EVP_MD_CTX*,const EVP_MD*,void*);
int EVP_DigestUpdate(EVP_MD_CTX*,const void*,size_t);
int EVP_DigestFinal_ex(EVP_MD_CTX*,unsigned char*,unsigned int*);
int EVP_DigestSignInit_ex(EVP_MD_CTX*,EVP_PKEY_CTX**,const char*,void*,const char*,EVP_PKEY*,const OSSL_PARAM*);
int EVP_DigestSign(EVP_MD_CTX*,unsigned char*,size_t*,const unsigned char*,size_t);
int EVP_DigestVerifyInit_ex(EVP_MD_CTX*,EVP_PKEY_CTX**,const char*,void*,const char*,EVP_PKEY*,const OSSL_PARAM*);
int EVP_DigestVerify(EVP_MD_CTX*,const unsigned char*,size_t,const unsigned char*,size_t);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX*);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
int EVP_CipherInit_ex(EVP_CIPHER_CTX*,const EVP_CIPHER*,void*,const unsigned char*,const unsigned char*,int);
int EVP_CipherUpdate(EVP_CIPHER_CTX*,unsigned char*,int*,const unsigned char*,int);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX*,unsigned char*,int*);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX*,int,int,void*);
EVP_KDF *EVP_KDF_fetch(void*,const char*,const char*);
void EVP_KDF_free(EVP_KDF*);
EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF*);
void EVP_KDF_CTX_free(EVP_KDF_CTX*);
int EVP_KDF_derive(EVP_KDF_CTX*,unsigned char*,size_t,const OSSL_PARAM*);
int RAND_bytes(unsigned char*,int);
int PKCS5_PBKDF2_HMAC(const char*,int,const unsigned char*,int,int,const EVP_MD*,int,unsigned char*);
int EVP_EncodeBlock(unsigned char*,const unsigned char*,int);
int EVP_DecodeBlock(unsigned char*,const unsigned char*,int);
int CRYPTO_memcmp(const void*,const void*,size_t);
void OPENSSL_cleanse(void*,size_t);
unsigned long OpenSSL_version_num(void);
#define EVP_PKEY_KEYPAIR 0x87
#define EVP_PKEY_PUBLIC_KEY 0x86
#define EVP_CTRL_GCM_GET_TAG 0x10
#define EVP_CTRL_GCM_SET_TAG 0x11
#endif
