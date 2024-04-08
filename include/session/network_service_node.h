#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct network_service_node {
    char ip[40];  // IPv4 is 15 chars, IPv6 is 39 chars, + null terminator.
    uint16_t lmq_port;
    char x25519_pubkey_hex[65];   // The 64-byte x25519 pubkey in hex + null terminator.
    char ed25519_pubkey_hex[65];  // The 64-byte ed25519 pubkey in hex + null terminator.

    uint8_t failure_count;
    bool invalid;
} network_service_node;

#ifdef __cplusplus
}
#endif
