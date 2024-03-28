#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct network_service_node {
    char ip[40];  // IPv4 is 15 chars, IPv6 is 39 chars, + null terminator.
    uint16_t lmq_port;
    char x25519_pubkey_hex[64];
    char ed25519_pubkey_hex[64];

    uint8_t failure_count;
    bool invalid;
} network_service_node;

#ifdef __cplusplus
}
#endif
