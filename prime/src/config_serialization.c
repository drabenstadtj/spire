#include "config_serialization.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

unsigned char* serialize_config_message(
    const unsigned char* iv, uint16_t iv_len,
    const unsigned char* tag, uint16_t tag_len,
    const unsigned char* encrypted_sym_key, uint32_t enc_key_len,
    const unsigned char* signature, uint32_t sig_len,
    const unsigned char* ciphertext, uint32_t ciphertext_len,
    size_t* out_total_len
) {
    size_t total_len = sizeof(uint16_t) + iv_len +
                       sizeof(uint16_t) + tag_len +
                       sizeof(uint32_t) + enc_key_len +
                       sizeof(uint32_t) + sig_len +
                       sizeof(uint32_t) + ciphertext_len;

    unsigned char* buf = malloc(total_len);
    if (!buf) return NULL;

    unsigned char* ptr = buf;

    memcpy(ptr, &iv_len, sizeof(uint16_t)); ptr += sizeof(uint16_t);
    memcpy(ptr, iv, iv_len); ptr += iv_len;

    memcpy(ptr, &tag_len, sizeof(uint16_t)); ptr += sizeof(uint16_t);
    memcpy(ptr, tag, tag_len); ptr += tag_len;

    memcpy(ptr, &enc_key_len, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, encrypted_sym_key, enc_key_len); ptr += enc_key_len;

    memcpy(ptr, &sig_len, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, signature, sig_len); ptr += sig_len;

    memcpy(ptr, &ciphertext_len, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, ciphertext, ciphertext_len); ptr += ciphertext_len;

    *out_total_len = total_len;
    return buf;
}

int deserialize_config_message(
    const unsigned char* buffer, size_t buffer_len,
    unsigned char** out_iv, uint16_t* iv_len,
    unsigned char** out_tag, uint16_t* tag_len,
    unsigned char** out_encrypted_sym_key, uint32_t* enc_key_len,
    unsigned char** out_signature, uint32_t* sig_len,
    unsigned char** out_ciphertext, uint32_t* ciphertext_len
) {
    const unsigned char* ptr = buffer;

    if (buffer_len < sizeof(uint16_t)) return -1;
    memcpy(iv_len, ptr, sizeof(uint16_t)); ptr += sizeof(uint16_t);
    if (ptr + *iv_len > buffer + buffer_len) return -1;
    *out_iv = malloc(*iv_len);
    memcpy(*out_iv, ptr, *iv_len); ptr += *iv_len;

    if (ptr + sizeof(uint16_t) > buffer + buffer_len) return -1;
    memcpy(tag_len, ptr, sizeof(uint16_t)); ptr += sizeof(uint16_t);
    if (ptr + *tag_len > buffer + buffer_len) return -1;
    *out_tag = malloc(*tag_len);
    memcpy(*out_tag, ptr, *tag_len); ptr += *tag_len;

    if (ptr + sizeof(uint32_t) > buffer + buffer_len) return -1;
    memcpy(enc_key_len, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    if (ptr + *enc_key_len > buffer + buffer_len) return -1;
    *out_encrypted_sym_key = malloc(*enc_key_len);
    memcpy(*out_encrypted_sym_key, ptr, *enc_key_len); ptr += *enc_key_len;

    if (ptr + sizeof(uint32_t) > buffer + buffer_len) return -1;
    memcpy(sig_len, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    if (ptr + *sig_len > buffer + buffer_len) return -1;
    *out_signature = malloc(*sig_len);
    memcpy(*out_signature, ptr, *sig_len); ptr += *sig_len;

    if (ptr + sizeof(uint32_t) > buffer + buffer_len) return -1;
    memcpy(ciphertext_len, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    if (ptr + *ciphertext_len > buffer + buffer_len) return -1;
    *out_ciphertext = malloc(*ciphertext_len);
    memcpy(*out_ciphertext, ptr, *ciphertext_len); ptr += *ciphertext_len;

    return 0;
}
