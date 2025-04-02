#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "tc_wrapper.h"
#include "config_serialization.h"
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

/**
 * Second pass: Generate all keys using the permanent public key
 */

// Helper to ensure a directory exists
void ensure_directory(const char *path) {
	struct stat st = {0};
	if (stat(path, &st) == -1) {
		if (mkdir(path, 0755) < 0) {
			perror(path);
		}
	}
}
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

// Generate necessary keys for host, encrypt them with the permanent public key, and add them to the data structure
void generate_keys_for_host(struct host *host)
{
	if (!host->permanent_public_key)
	{
		fprintf(stderr, "Error: TPM public key missing for host %s\n", host->name);
		return;
	}

	host->spines_internal_public_key = generate_and_get_public_key(2048);
	host->encrypted_spines_internal_private_key = get_encrypted_private_key(
		generate_rsa_key(2048), host->permanent_public_key);

	host->spines_external_public_key = generate_and_get_public_key(2048);
	host->encrypted_spines_external_private_key = get_encrypted_private_key(
		generate_rsa_key(2048), host->permanent_public_key);
}

void generate_keys_for_replica(struct replica *replica, struct host *host, unsigned site_index)
{
	if (!host->permanent_public_key)
	{
		fprintf(stderr, "Error: TPM public key missing for host %s (replica %d)\n", host->name, replica->instance_id);
		return;
	}

	// Generate instance key pair
	replica->instance_public_key = generate_and_get_public_key(2048);
	EVP_PKEY *instance_key = generate_rsa_key(2048);
	replica->encrypted_instance_private_key = get_encrypted_private_key(instance_key, host->permanent_public_key);
	free_rsa_key(instance_key);

	// Paths to threshold share files
	char prime_share_path[512];
	snprintf(prime_share_path, sizeof(prime_share_path), PRIME_TC_DIR "share%d_1.pem", replica->instance_id - 1);

	char sm_share_path[512];
	snprintf(sm_share_path, sizeof(sm_share_path), SM_TC_DIR "share%d_1.pem", replica->instance_id - 1);

	// Read PEM shares as strings
	char *prime_plain = read_file_as_string(prime_share_path);
	char *sm_plain = read_file_as_string(sm_share_path);

	if (!prime_plain || !sm_plain)
	{
		fprintf(stderr, "Error: Failed to read threshold shares for replica %d\n", replica->instance_id);
		free(prime_plain);
		free(sm_plain);
		return;
	}

	// Generate AES-256 key (32 random bytes)
	unsigned char *aes_key = generate_symmetric_key();
	if (!aes_key)
	{
		fprintf(stderr, "Error: Failed to generate AES key for replica %d\n", replica->instance_id);
		free(prime_plain);
		free(sm_plain);
		return;
	}

	// Encrypt shares with AES-ECB and encode as hex
	replica->encrypted_prime_threshold_key_share = aes_ecb_encrypt_hex(prime_plain, aes_key);
	replica->encrypted_sm_threshold_key_share = aes_ecb_encrypt_hex(sm_plain, aes_key);

	// Store or serialize `aes_key` later as you decide

	free(prime_plain);
	free(sm_plain);
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

// unsigned char *prepare_encrypted_config_payload(
// 	struct config *cfg,
// 	EVP_PKEY *cm_private_key,
// 	EVP_PKEY *cm_public_key,
// 	size_t *out_len)
// {
// 	size_t serialized_config_len = 0;
// 	char *serialized_config = serialize_yaml_config_to_string(cfg, &serialized_config_len);
// 	if (!serialized_config)
// 		return NULL;

// 	Signature sig = sign_buffer((unsigned char *)serialized_config, serialized_config_len, cm_private_key);
// 	if (!sig.signature)
// 	{
// 		free(serialized_config);
// 		return NULL;
// 	}

// 	unsigned char *sym_key = generate_symmetric_key();
// 	unsigned char *iv = generate_iv();
// 	if (!sym_key || !iv)
// 	{
// 		free(serialized_config);
// 		free_signature(&sig);
// 		return NULL;
// 	}

// 	unsigned char tag[AES_TAGLEN];
// 	unsigned char *ciphertext = malloc(serialized_config_len + 32); // padded a bit bc of seg fault

// 	int ct_len = aes_gcm_encrypt((unsigned char *)serialized_config, serialized_config_len,
// 								 sym_key, iv, ciphertext, tag);
// 	if (ct_len < 0)
// 	{
// 		free(serialized_config);
// 		free_signature(&sig);
// 		free(sym_key);
// 		free(iv);
// 		return NULL;
// 	}

// 	size_t enc_key_len = 0;
// 	unsigned char *enc_sym_key = encrypt_symmetric_key_with_rsa(sym_key, AES_KEYLEN, cm_public_key, &enc_key_len);
// 	if (!enc_sym_key)
// 	{
// 		free(serialized_config);
// 		free_signature(&sig);
// 		free(sym_key);
// 		free(iv);
// 		return NULL;
// 	}

// 	unsigned char *final_payload = serialize_config_message(
// 		iv, AES_IVLEN, tag, AES_TAGLEN,
// 		enc_sym_key, enc_key_len,
// 		sig.signature, sig.length,
// 		ciphertext, ct_len,
// 		out_len);

// 	free(serialized_config);
// 	free_signature(&sig);
// 	free(sym_key);
// 	free(iv);
// 	free(enc_sym_key);
// 	free(ciphertext);
// 	return final_payload;
// }

int load_config_manager_keys(EVP_PKEY **priv_key, EVP_PKEY **pub_key)
{
	*priv_key = load_key_from_file("cm_keys/private_key.pem", 1);
	*pub_key = load_key_from_file("cm_keys/public_key.pem", 0);
	return (*priv_key && *pub_key) ? 0 : -1;
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

	// Cleanup
	free(serialized_config);
	free_signature(&sig);
	free_yaml_config(&cfg);
	EVP_PKEY_free(cm_priv);
	EVP_PKEY_free(cm_pub);

	return EXIT_SUCCESS;
}
