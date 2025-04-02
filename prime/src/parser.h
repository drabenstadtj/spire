#ifndef PARSER_H
#define PARSER_H

#include <cyaml/cyaml.h>

enum site_type
{
    CONTROL_CENTER,
    DATA_CENTER,
    CLIENT,
};

struct host
{
    const char *name;
    const char *ip;
    const char *permanent_key_location;
    const char *permanent_public_key;
    unsigned int runs_spines_internal;
    unsigned int runs_spines_external;

    // Required but will be added later
    const char *spines_internal_public_key;
    const char *encrypted_spines_internal_private_key;
    const char *spines_external_public_key;
    const char *encrypted_spines_external_private_key;
};

struct replica
{
    unsigned instance_id;
    const char *host;
    const char *spines_internal_daemon;
    const char *spines_external_daemon;

    // Required but will be generated later
    const char *instance_public_key;
    const char *encrypted_instance_private_key;
    char *encrypted_prime_threshold_key_share;
    char *encrypted_sm_threshold_key_share;
};

struct site
{
    const char *name;
    enum site_type type;
    struct host *hosts; // array of hosts
    unsigned hosts_count;

    // Optional: can be manually managed after parsing
    struct replica *replicas;
    unsigned replicas_count;
};

struct service_keys
{
    const char *sm_threshold_public_key;
    const char *prime_threshold_public_key;
};

struct config
{
    unsigned configuration_id;
    unsigned tolerated_byzantine_faults;
    unsigned tolerated_unavailable_replicas;
    struct service_keys service_keys;
    struct site *sites;
    unsigned sites_count;

    // Required but will be set later
    struct spines_topology *spines_internal_topology;
    struct spines_topology *spines_external_topology;
};

struct config *load_yaml_config(const char *yaml_file);
int save_yaml_config(const char *yaml_file, struct config *cfg);
char *serialize_yaml_config_to_string(const struct config *cfg, size_t *out_len);
void free_yaml_config(struct config **cfg);

// Function(s) for generating topology
// int generate_topology(struct config *cfg);

// Functions for printing the yaml
void print_service_keys(const struct service_keys *keys, int indent);
void print_host(const struct host *h, int indent);
void print_replica(const struct replica *r, int indent);
void print_site(const struct site *s, int indent);
void print_config(const struct config *cfg);

#endif // PARSER_H