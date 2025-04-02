#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "tc_wrapper.h"
#include "parser.h"
#include "key_generation.h"

#define TPM_KEY_DIR "tpm_keys/"
#define SM_TC_DIR "tc_keys/sm/"
#define PRIME_TC_DIR "tc_keys/prime/"

// Helper to read the share files from TC_with_args_generate
char *read_file_as_string(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp)
        return NULL;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    char *buffer = malloc(size + 1);
    if (!buffer)
    {
        fclose(fp);
        return NULL;
    }

    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

// Helper to ensure a directory exists
void ensure_directory(const char *path)
{
    struct stat st = {0};
    if (stat(path, &st) == -1)
    {
        if (mkdir(path, 0755) < 0)
        {
            perror(path);
        }
    }
}

/**
 *	First pass: Generate a simulated TPM key for the host
 */

void generate_simulated_tpm_key_for_host(struct host *host)
{
    char private_key_filepath[512];
    snprintf(private_key_filepath, sizeof(private_key_filepath), "%s%s_tpm_private.pem", TPM_KEY_DIR, host->name);

    ensure_directory(TPM_KEY_DIR);

    // update permanent key location in config
    host->permanent_key_location = strdup(private_key_filepath);

    // Generate RSA key for TPM simulation
    EVP_PKEY *tpm_key = generate_rsa_key(3072);
    if (!tpm_key)
    {
        fprintf(stderr, "Error: Failed to generate simulated TPM key for host %s\n", host->name);
        return;
    }

    // Extract private key in PEM format (unencrypted)
    char *tpm_private = get_private_key(tpm_key);
    if (!tpm_private)
    {
        fprintf(stderr, "Error: Failed to extract TPM private key for host %s\n", host->name);
        free_rsa_key(tpm_key);
        return;
    }

    // Write private key to file
    if (write_key_to_file(private_key_filepath, tpm_private) != 0)
    {
        fprintf(stderr, "Error: Failed to write TPM private key to %s\n", private_key_filepath);
        free(tpm_private);
        free_rsa_key(tpm_key);
        return;
    }

    // Save the private key location in the config
    host->permanent_key_location = strdup(private_key_filepath);

    // Extract and store the public key in config after successfully writing private key*
    char *tpm_public = get_public_key(tpm_key);
    if (!tpm_public)
    {
        fprintf(stderr, "Error: Failed to extract TPM public key for host %s\n", host->name);
        free(tpm_private);
        free_rsa_key(tpm_key);
        return;
    }

    // Set the field in the host to the public key
    host->permanent_public_key = tpm_public;

    // Cleanup
    free(tpm_private);
    free_rsa_key(tpm_key);
}

/* Second pass: Generate all keys using the permanent public key */

// Generate SM threshold key shares in tc_keys/sm/
void generate_sm_tc_keys(int req_shares, int faults, int rej_servers)
{
    ensure_directory("tc_keys");
    ensure_directory("tc_keys/sm");

    TC_with_args_Generate(req_shares, "tc_keys/sm", faults, rej_servers, 1);
}

// Generate Prime threshold key shares in tc_keys/prime/
void generate_prime_tc_keys(int req_shares, int faults, int rej_servers)
{
    ensure_directory("tc_keys");
    ensure_directory("tc_keys/prime");

    TC_with_args_Generate(req_shares, "tc_keys/prime", faults, rej_servers, 1);
}

// Loads threshold pubkeys from disk and
void load_threshold_pubkeys(struct config *cfg)
{
    char sm_pubkey_path[256];
    char prime_pubkey_path[256];

    snprintf(sm_pubkey_path, sizeof(sm_pubkey_path), "%spubkey_1.pem", SM_TC_DIR);
    snprintf(prime_pubkey_path, sizeof(prime_pubkey_path), "%spubkey_1.pem", PRIME_TC_DIR);

    cfg->service_keys.sm_threshold_public_key = read_file_as_string(sm_pubkey_path);
    cfg->service_keys.prime_threshold_public_key = read_file_as_string(prime_pubkey_path);

    if (!cfg->service_keys.sm_threshold_public_key || !cfg->service_keys.prime_threshold_public_key)
    {
        fprintf(stderr, "Error: Failed to read SM or Prime threshold public keys.\n");
        free_yaml_config(&cfg);
        exit(EXIT_FAILURE);
    }
}
void generate_keys_for_host(struct host *host)
{
    if (!host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s\n", host->name);
        return;
    }

    EVP_PKEY *tpm_pubkey = load_public_key_from_pem(host->permanent_public_key);
    if (!tpm_pubkey)
    {
        fprintf(stderr, "Error: Failed to load TPM public key for host %s\n", host->name);
        return;
    }

    // === Internal Key ===
    EVP_PKEY *internal_key = generate_rsa_key(2048);
    if (!internal_key)
    {
        fprintf(stderr, "Failed to generate internal RSA key\n");
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    host->spines_internal_public_key = get_public_key(internal_key);
    char *internal_private_pem = get_private_key(internal_key);

    struct HybridEncrypted internal_enc = hybrid_encrypt(
        (unsigned char *)internal_private_pem,
        strlen(internal_private_pem),
        tpm_pubkey);

    host->encrypted_spines_internal_private_key = hybrid_pack(&internal_enc);

    // Cleanup
    free(internal_enc.ciphertext_hex);
    free(internal_enc.enc_key_hex);
    free(internal_private_pem);
    free_rsa_key(internal_key);

    // === External Key ===
    EVP_PKEY *external_key = generate_rsa_key(2048);
    if (!external_key)
    {
        fprintf(stderr, "Failed to generate external RSA key\n");
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    host->spines_external_public_key = get_public_key(external_key);
    char *external_private_pem = get_private_key(external_key);

    struct HybridEncrypted external_enc = hybrid_encrypt(
        (unsigned char *)external_private_pem,
        strlen(external_private_pem),
        tpm_pubkey);

    host->encrypted_spines_external_private_key = hybrid_pack(&external_enc);

    // Cleanup
    free(external_enc.ciphertext_hex);
    free(external_enc.enc_key_hex);
    free(external_private_pem);
    free_rsa_key(external_key);

    EVP_PKEY_free(tpm_pubkey);
}

void generate_keys_for_replica(struct replica *replica, struct host *host, unsigned site_index)
{
    if (!host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s (replica %d)\n", host->name, replica->instance_id);
        return;
    }

    // Load the host's public key from PEM
    EVP_PKEY *tpm_pubkey = load_public_key_from_pem(host->permanent_public_key);
    if (!tpm_pubkey)
    {
        fprintf(stderr, "Error: Failed to load TPM public key for host %s (replica %d)\n", host->name, replica->instance_id);
        return;
    }

    // Generate instance key pair
    EVP_PKEY *instance_key = generate_rsa_key(2048);
    if (!instance_key)
    {
        fprintf(stderr, "Error: Failed to generate RSA key for replica %d\n", replica->instance_id);
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    replica->instance_public_key = get_public_key(instance_key);
    char *instance_private_pem = get_private_key(instance_key);

    struct HybridEncrypted inst_enc = hybrid_encrypt(
        (unsigned char *)instance_private_pem,
        strlen(instance_private_pem),
        tpm_pubkey);
    replica->encrypted_instance_private_key = hybrid_pack(&inst_enc);

    free(instance_private_pem);
    free(inst_enc.ciphertext_hex);
    free(inst_enc.enc_key_hex);
    free_rsa_key(instance_key);

    // Encrypt Threshold Shares

    char prime_share_path[512];
    snprintf(prime_share_path, sizeof(prime_share_path), PRIME_TC_DIR "share%d_1.pem", replica->instance_id - 1);

    char sm_share_path[512];
    snprintf(sm_share_path, sizeof(sm_share_path), SM_TC_DIR "share%d_1.pem", replica->instance_id - 1);

    char *prime_plain = read_file_as_string(prime_share_path);
    char *sm_plain = read_file_as_string(sm_share_path);

    if (!prime_plain || !sm_plain)
    {
        fprintf(stderr, "Error: Failed to read threshold shares for replica %d\n", replica->instance_id);
        free(prime_plain);
        free(sm_plain);
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    struct HybridEncrypted prime_enc = hybrid_encrypt(
        (unsigned char *)prime_plain,
        strlen(prime_plain),
        tpm_pubkey);
    replica->encrypted_prime_threshold_key_share = hybrid_pack(&prime_enc);

    struct HybridEncrypted sm_enc = hybrid_encrypt(
        (unsigned char *)sm_plain,
        strlen(sm_plain),
        tpm_pubkey);
    replica->encrypted_sm_threshold_key_share = hybrid_pack(&sm_enc);

    // Cleanup
    free(prime_plain);
    free(sm_plain);

    free(prime_enc.ciphertext_hex);
    free(prime_enc.enc_key_hex);

    free(sm_enc.ciphertext_hex);
    free(sm_enc.enc_key_hex);

    EVP_PKEY_free(tpm_pubkey);
}

// Find the host associated with a given replica
struct host *find_host_for_replica(struct site *site, const char *host_name)
{
    for (unsigned j = 0; j < site->hosts_count; j++)
    {
        if (strcmp(site->hosts[j].name, host_name) == 0)
        {
            return &site->hosts[j];
        }
    }
    return NULL; // No matching host found (shouldn't happen if the config is correct)
}

void first_pass_generate_tpm_keys(struct config *cfg)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            generate_simulated_tpm_key_for_host(&site->hosts[j]);
        }
    }
}

void second_pass_generate_keys(struct config *cfg)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            generate_keys_for_host(&site->hosts[j]);
        }

        for (unsigned j = 0; j < site->replicas_count; j++)
        {
            struct replica *replica = &site->replicas[j];
            struct host *replica_host = find_host_for_replica(site, replica->host);

            if (replica_host)
            {
                generate_keys_for_replica(replica, replica_host, i);
            }
            else
            {
                fprintf(stderr, "Error: Replica %d has no matching host %s!\n", replica->instance_id, replica->host);
            }
        }
    }
}

struct config *load_and_process_config(const char *input_yaml)
{
    struct config *cfg = load_yaml_config(input_yaml);
    if (!cfg)
        return NULL;

    first_pass_generate_tpm_keys(cfg);

    int faults = cfg->tolerated_byzantine_faults;
    int rej_servers = cfg->tolerated_unavailable_replicas;
    int req_shares = faults + 1;

    generate_sm_tc_keys(req_shares, faults, rej_servers);
    generate_prime_tc_keys(req_shares, faults, rej_servers);
    load_threshold_pubkeys(cfg);
    second_pass_generate_keys(cfg);

    return cfg;
}

int load_config_manager_keys(EVP_PKEY **priv_key, EVP_PKEY **pub_key)
{
    *priv_key = load_key_from_file("cm_keys/private_key.pem", 1);
    *pub_key = load_key_from_file("cm_keys/public_key.pem", 0);
    return (*priv_key && *pub_key) ? 0 : -1;
}

// big ugly functino for demonstration
void read_and_verify_config_file(const char *filepath, const char *signature_log_path, const char *decrypted_keys_path, EVP_PKEY *verifier_key, EVP_PKEY *unused_tpm_private_key)
{
    FILE *fp = fopen(filepath, "rb");
    if (!fp)
    {
        perror("Failed to open input file");
        return;
    }

    // Read signature length
    uint32_t sig_len = 0;
    if (fread(&sig_len, sizeof(uint32_t), 1, fp) != 1)
    {
        fprintf(stderr, "Failed to read signature length\n");
        fclose(fp);
        return;
    }

    // Read signature
    unsigned char *signature = malloc(sig_len);
    if (!signature || fread(signature, 1, sig_len, fp) != sig_len)
    {
        fprintf(stderr, "Failed to read signature\n");
        free(signature);
        fclose(fp);
        return;
    }

    // Read YAML content
    fseek(fp, 0, SEEK_END);
    long total_size = ftell(fp);
    fseek(fp, sizeof(uint32_t) + sig_len, SEEK_SET);

    long yaml_len = total_size - (sizeof(uint32_t) + sig_len);
    char *yaml_data = malloc(yaml_len + 1);
    if (!yaml_data || fread(yaml_data, 1, yaml_len, fp) != yaml_len)
    {
        fprintf(stderr, "Failed to read YAML content\n");
        free(signature);
        free(yaml_data);
        fclose(fp);
        return;
    }
    yaml_data[yaml_len] = '\0';
    fclose(fp);

    // Open output log files
    FILE *sig_log = fopen(signature_log_path, "w");
    FILE *dec_log = fopen(decrypted_keys_path, "w");
    if (!sig_log || !dec_log)
    {
        perror("Failed to open output log files");
        free(signature);
        free(yaml_data);
        return;
    }

    // Print signature validation result and YAML
    fprintf(sig_log, "YAML Configuration:\n%s\n\n", yaml_data);
    int valid = verify_buffer((unsigned char *)yaml_data, yaml_len, signature, sig_len, verifier_key);
    fprintf(sig_log, "Signature is %s.\n", valid == 0 ? "VALID" : "INVALID");

    // Attempt to load the config structure from YAML
    struct config *cfg = load_yaml_config_from_string(yaml_data, yaml_len);
    if (!cfg)
    {
        fprintf(stderr, "Failed to parse YAML into config structure\n");
        fclose(sig_log);
        fclose(dec_log);
        free(signature);
        free(yaml_data);
        return;
    }

    // Print decrypted keys from all hosts
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];
        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            struct host *host = &site->hosts[j];
            fprintf(dec_log, "Host: %s\n", host->name);

            EVP_PKEY *tpm_privkey = load_key_from_file(host->permanent_key_location, 1);
            if (!tpm_privkey)
            {
                fprintf(dec_log, "Failed to load TPM private key for host %s\n\n", host->name);
                continue;
            }

            char *enc_key_hex = NULL, *ciphertext_hex = NULL;
            hybrid_unpack(host->encrypted_spines_internal_private_key, &enc_key_hex, &ciphertext_hex);
            struct HybridDecryptionResult int_dec = hybrid_decrypt(ciphertext_hex, enc_key_hex, tpm_privkey);
            if (int_dec.plaintext)
                fprintf(dec_log, "Decrypted Internal Private Key:\n%s\n\n", int_dec.plaintext);
            else
                fprintf(dec_log, "Failed to decrypt internal private key for host %s\n\n", host->name);

            free(enc_key_hex);
            free(ciphertext_hex);
            free(int_dec.plaintext);

            hybrid_unpack(host->encrypted_spines_external_private_key, &enc_key_hex, &ciphertext_hex);
            struct HybridDecryptionResult ext_dec = hybrid_decrypt(ciphertext_hex, enc_key_hex, tpm_privkey);
            if (ext_dec.plaintext)
                fprintf(dec_log, "Decrypted External Private Key:\n%s\n\n", ext_dec.plaintext);
            else
                fprintf(dec_log, "Failed to decrypt external private key for host %s\n\n", host->name);

            free(enc_key_hex);
            free(ciphertext_hex);
            free(ext_dec.plaintext);

            EVP_PKEY_free(tpm_privkey);
        }
    }

    // Cleanup
    free(signature);
    free(yaml_data);
    free_yaml_config(&cfg);
    fclose(sig_log);
    fclose(dec_log);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <input_yaml> <output_yaml>\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct config *cfg = load_and_process_config(argv[1]);
    if (!cfg)
    {
        fprintf(stderr, "Failed to load or process config\n");
        return EXIT_FAILURE;
    }

    EVP_PKEY *cm_priv = NULL, *cm_pub = NULL;
    if (load_config_manager_keys(&cm_priv, &cm_pub) < 0)
    {
        fprintf(stderr, "Failed to load config manager keys\n");
        free_yaml_config(&cfg);
        return EXIT_FAILURE;
    }

    size_t payload_len = 0;

    size_t serialized_config_len = 0;

    char *serialized_config = serialize_yaml_config_to_string(cfg, &serialized_config_len);
    if (!serialized_config)
    {
        fprintf(stderr, "Failed to serialize config\n");
        free_yaml_config(&cfg);
        EVP_PKEY_free(cm_priv);
        EVP_PKEY_free(cm_pub);
        return EXIT_FAILURE;
    }

    Signature sig = sign_buffer((unsigned char *)serialized_config, serialized_config_len, cm_priv);
    if (!sig.signature)
    {
        fprintf(stderr, "Failed to sign configuration\n");
        free(serialized_config);
        free_yaml_config(&cfg);
        EVP_PKEY_free(cm_priv);
        EVP_PKEY_free(cm_pub);
        return EXIT_FAILURE;
    }

    // Write signature + config to output file
    FILE *out_fp = fopen(argv[2], "wb");
    if (!out_fp)
    {
        perror("Failed to open output file");
        free(serialized_config);
        free_signature(&sig);
        free_yaml_config(&cfg);
        EVP_PKEY_free(cm_priv);
        EVP_PKEY_free(cm_pub);
        return EXIT_FAILURE;
    }

    // Signature length
    uint32_t sig_len_u32 = (uint32_t)sig.length;
    fwrite(&sig_len_u32, sizeof(uint32_t), 1, out_fp);

    // Signature bytes
    fwrite(sig.signature, 1, sig.length, out_fp);

    // Config YAML string
    fwrite(serialized_config, 1, serialized_config_len, out_fp);

    fclose(out_fp);

    read_and_verify_config_file(argv[2], "signature_log.txt", "decrypted_keys.txt", cm_pub, cm_priv);

    // Cleanup
    free(serialized_config);
    free_signature(&sig);
    free_yaml_config(&cfg);
    EVP_PKEY_free(cm_priv);
    EVP_PKEY_free(cm_pub);

    return EXIT_SUCCESS;
}
