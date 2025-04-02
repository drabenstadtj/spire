#ifndef CONFIG_SERIALIZATION_H
#define CONFIG_SERIALIZATION_H

#include <stddef.h>
#include <stdint.h>

// Structure to hold the deserialized components
typedef struct {
    unsigned char* iv;
    uint16_t iv_len;

    unsigned char* tag;
    uint16_t tag_len;

    unsigned char* encrypted_sym_key;
    uint32_t enc_key_len;

    unsigned char* signature;
    uint32_t sig_len;

    unsigned char* ciphertext;
    uint32_t ciphertext_len;
} ConfigMessageComponents;

unsigned char* serialize_config_message(
    const unsigned char* iv, uint16_t iv_len,
    const unsigned char* tag, uint16_t tag_len,
    const unsigned char* encrypted_sym_key, uint32_t enc_key_len,
    const unsigned char* signature, uint32_t sig_len,
    const unsigned char* ciphertext, uint32_t ciphertext_len,
    size_t* out_total_len);

int deserialize_config_message(
    const unsigned char* buffer, size_t buffer_len,
    unsigned char** out_iv, uint16_t* iv_len,
    unsigned char** out_tag, uint16_t* tag_len,
    unsigned char** out_encrypted_sym_key, uint32_t* enc_key_len,
    unsigned char** out_signature, uint32_t* sig_len,
    unsigned char** out_ciphertext, uint32_t* ciphertext_len
);

void free_config_message_components(ConfigMessageComponents* msg);

#endif // CONFIG_SERIALIZATION_H
