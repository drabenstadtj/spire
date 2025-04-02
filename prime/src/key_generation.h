#ifndef KEY_GENERATION_H
#define KEY_GENERATION_H

#include <stddef.h>
#include <openssl/evp.h>

#define AES_KEYLEN 32 // AES-256
#define AES_IVLEN 12  // IV size for AES-GCM
#define AES_TAGLEN 16 // AES-GCM tag size

typedef struct
{
    unsigned char* signature;
    size_t length;
} Signature;



/* Key Generation */
EVP_PKEY* generate_rsa_key(int bits);
char* generate_and_get_public_key(int bits);
char* generate_and_get_encrypted_private_key(int bits, const char* passphrase);

/* PEM Export */
char* get_public_key(EVP_PKEY* pkey);
char* get_private_key(EVP_PKEY* pkey);
char* get_encrypted_private_key(EVP_PKEY* pkey, const char* passphrase);
void free_rsa_key(EVP_PKEY* pkey);

/* File IO */
int write_key_to_file(const char* filename, const char* key);
unsigned char* read_file(const char* filename, size_t* length);

/* Signing and Verifying */
Signature sign_buffer(const unsigned char* data, size_t data_len, EVP_PKEY* priv_key);
int verify_buffer(const unsigned char* data, size_t data_len,
    const unsigned char* signature, size_t sig_len,
    EVP_PKEY* pub_key);
void free_signature(Signature* sig);

/* Symmetric Encryption */
unsigned char* generate_symmetric_key();
unsigned char* generate_iv();
int aes_gcm_encrypt(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char* ciphertext, unsigned char* tag);
int aes_gcm_decrypt(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* tag,
    const unsigned char* key, const unsigned char* iv,
    unsigned char* plaintext);
unsigned char* encrypt_symmetric_key_with_rsa(const unsigned char* sym_key, size_t sym_key_len,
    EVP_PKEY* pubkey, size_t* out_len);
EVP_PKEY* load_key_from_file(const char* filepath, int is_private);

#endif // KEY_GENERATION_H
