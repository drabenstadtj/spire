#include "key_generation.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

/* ---------- Internal Helpers ---------- */

static char* write_key_to_pem(EVP_PKEY* pkey, int is_public, const char* passphrase)
{
    if (!pkey)
        return NULL;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio)
        return NULL;

    int success = 0;
    if (is_public)
    {
        success = PEM_write_bio_PUBKEY(bio, pkey);
    }
    else if (passphrase)
    {
        success = PEM_write_bio_PrivateKey(bio, pkey, EVP_aes_256_cbc(),
            (unsigned char*)passphrase, strlen(passphrase), NULL, NULL);
    }
    else
    {
        success = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    }

    if (!success)
    {
        BIO_free(bio);
        return NULL;
    }

    size_t len = BIO_pending(bio);
    char* pem = malloc(len + 1);
    if (!pem)
    {
        BIO_free(bio);
        return NULL;
    }

    BIO_read(bio, pem, len);
    pem[len] = '\0';
    BIO_free(bio);
    return pem;
}

/* ---------- Key Generation ---------- */

// Generate an RSA key using EVP API
EVP_PKEY* generate_rsa_key(int bits)
{
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Creates a context for rsa keygen

    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }

    // Initialize the key generation context and set the key length
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        fprintf(stderr, "Error: RSA key generation initialization failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Generate the RSA key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        fprintf(stderr, "Error: RSA key generation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx); // Free the context after key generation
    return pkey;            // Return the generated key
}

char* generate_and_get_public_key(int bits)
{
    EVP_PKEY* key = generate_rsa_key(bits);
    if (!key)
        return NULL;

    char* pem = get_public_key(key);
    free_rsa_key(key);
    return pem;
}

char* generate_and_get_encrypted_private_key(int bits, const char* passphrase)
{
    EVP_PKEY* key = generate_rsa_key(bits);
    if (!key)
        return NULL;

    char* pem = get_encrypted_private_key(key, passphrase);
    free_rsa_key(key);
    return pem;
}

/* ---------- Key Serialization ---------- */

char* get_public_key(EVP_PKEY* pkey)
{
    return write_key_to_pem(pkey, 1, NULL);
}

char* get_private_key(EVP_PKEY* pkey)
{
    return write_key_to_pem(pkey, 0, NULL);
}

char* get_encrypted_private_key(EVP_PKEY* pkey, const char* passphrase)
{
    return write_key_to_pem(pkey, 0, passphrase);
}

// Free EVP_PKEY structure
void free_rsa_key(EVP_PKEY* pkey)
{
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
}

// Write a key to a file
int write_key_to_file(const char* filename, const char* key)
{
    if (!filename || !key)
    {
        fprintf(stderr, "Error: Invalid filename or key\n");
        return -1;
    }

    FILE* file = fopen(filename, "w");
    if (!file)
    {
        perror("Error opening file for writing");
        return -1;
    }

    if (fprintf(file, "%s", key) < 0)
    {
        fprintf(stderr, "Error: Failed to write key to file\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0; // Success
}

/* ---------- Signing / Verifying ---------- */

Signature sign_buffer(const unsigned char* data, size_t data_len, EVP_PKEY* priv_key)
{
    Signature result = { NULL, 0 };

    if (!data || !priv_key)
        return result;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        perror("EVP_MD_CTX_new failed");
        return result;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, priv_key) != 1 ||
        EVP_DigestSignUpdate(md_ctx, data, data_len) != 1 ||
        EVP_DigestSignFinal(md_ctx, NULL, &result.length) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return result;
    }

    result.signature = malloc(result.length);
    if (!result.signature)
    {
        perror("Memory allocation failed");
        EVP_MD_CTX_free(md_ctx);
        result.length = 0;
        return result;
    }

    if (EVP_DigestSignFinal(md_ctx, result.signature, &result.length) != 1)
    {
        ERR_print_errors_fp(stderr);
        free_signature(&result);
    }

    EVP_MD_CTX_free(md_ctx);
    return result;
}

int verify_buffer(const unsigned char* data, size_t data_len,
    const unsigned char* signature, size_t sig_len,
    EVP_PKEY* pub_key)
{
    if (!data || !signature || !pub_key)
        return 1;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        perror("EVP_MD_CTX_new failed");
        return 1;
    }

    int result = 1;
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pub_key) == 1 &&
        EVP_DigestVerifyUpdate(md_ctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(md_ctx, signature, sig_len) == 1)
    {
        result = 0;
    }

    if (result == 0)
        printf("Signature is valid.\n");
    else
        printf("Signature is INVALID.\n");

    EVP_MD_CTX_free(md_ctx);
    return result;
}

// Free allocated memory for signature
void free_signature(Signature* sig)
{
    if (sig && sig->signature)
    {
        free(sig->signature);
        sig->signature = NULL;
        sig->length = 0;
    }
}

/* --- Symmetric Encryption --- */

// Generate a random AES key
unsigned char* generate_symmetric_key()
{
    unsigned char* key = malloc(AES_KEYLEN);
    if (!key || RAND_bytes(key, AES_KEYLEN) != 1)
    {
        free(key);
        return NULL;
    }
    return key;
}

char* aes_ecb_encrypt_hex(const char* plaintext, const unsigned char* key)
{
	if (!plaintext || !key) return NULL;

	int pt_len = strlen(plaintext);
	int block_size = 16;
	int max_len = pt_len + block_size;

	unsigned char* ciphertext = malloc(max_len);
	if (!ciphertext) return NULL;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int len = 0, ciphertext_len = 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 1); // Enable PKCS#7 padding

	EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, pt_len);
	ciphertext_len = len;

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	char* hex = malloc(ciphertext_len * 2 + 1);
	if (!hex) {
		free(ciphertext);
		return NULL;
	}

	for (int i = 0; i < ciphertext_len; ++i)
		sprintf(&hex[i * 2], "%02x", ciphertext[i]);

	hex[ciphertext_len * 2] = '\0';
	free(ciphertext);
	return hex;
}


// Encrypt a symmetric key using a provided EVP_PKEY public key
unsigned char* encrypt_symmetric_key_with_rsa(const unsigned char* sym_key, size_t sym_key_len,
    EVP_PKEY* pubkey, size_t* out_len)
{
    if (!sym_key || !pubkey || !out_len)
        return NULL;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, out_len, sym_key, sym_key_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char* encrypted = malloc(*out_len);
    if (!encrypted)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted, out_len, sym_key, sym_key_len) <= 0)
    {
        free(encrypted);
        encrypted = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

// Load an EVP_PKEY from a PEM file (public or private)
EVP_PKEY* load_key_from_file(const char* filepath, int is_private)
{
    if (!filepath)
        return NULL;

    FILE* fp = fopen(filepath, "r");
    if (!fp)
    {
        perror("Error opening key file");
        return NULL;
    }

    EVP_PKEY* key = NULL;
    if (is_private)
        key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    else
        key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    if (!key)
        ERR_print_errors_fp(stderr);

    return key;
}