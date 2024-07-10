#ifndef _QUIC_DEPROTECTION_H
#define _QUIC_DEPROTECTION_H

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#ifdef DEBUG_SWITCH

#define LOG_DEBUG(format, ...)                       \
    {                                                \
        fprintf(stdout, format "\n", ##__VA_ARGS__); \
        fflush(stdout);                              \
    }

#define LOG_WARN(format, ...)                        \
    {                                                \
        fprintf(stderr, format "\n", ##__VA_ARGS__); \
        fflush(stderr);                              \
    }

#define LOG_ERROR(format, ...)                       \
    {                                                \
        fprintf(stderr, format "\n", ##__VA_ARGS__); \
        fflush(stderr);                              \
    }

#else

#define LOG_DEBUG(format, ...)
#define LOG_WARN(format, ...)
#define LOG_ERROR(format, ...)

#endif

#define QUIC_MAX_UDP_PAYLOAD_SIZE 1460

#define quic_string(str)               \
    {                                  \
        sizeof(str) - 1, (u_char *)str \
    }

typedef struct
{
    size_t len;
    u_char *data;
} quic_str_t;

typedef struct quic_secret_s
{
    quic_str_t secret;
    quic_str_t key;
    quic_str_t iv;
    quic_str_t hp;
} quic_secret_t;

typedef enum
{
    ssl_encryption_initial = 0,
    ssl_encryption_early_data = 1,
    ssl_encryption_handshake = 2,
    ssl_encryption_application = 3,
} ssl_encryption_level_t;

typedef enum
{
    LONG = 0,
    SHORT = 1,
} quic_header_type;

typedef struct
{
    quic_secret_t client_secret;
    ssl_encryption_level_t level; // QUIC Packet Process Level
    quic_header_type header_type; // QUIC Packet Header Type

    uint32_t version; // QUIC Version
    uint8_t flags;    // QUIC Flags
    u_char *data;     // QUIC Packet Data
    size_t len;       // QUIC Packet Length
    u_char *pos;      // Process Ptr
    uint64_t largest_pkt_num;

    quic_str_t dcid;  // QUIC DCID
    quic_str_t scid;  // QUIC SCID
    quic_str_t token; // QUIC TOKEN

    size_t pkt_len;
    uint64_t pkt_num; // QUIC Packet Number
    u_char *plaintext;
    quic_str_t payload; // Decrypted data

    unsigned key_phase : 1;
} quic_dpt_t;

quic_dpt_t *quic_deprotection_new(void);
void quic_deprotection_free(quic_dpt_t *dpt);
void quic_deprotection_dump(quic_dpt_t *dpt);
int quic_deprotection(quic_dpt_t *dpt, const u_char *payload, size_t payload_len);

#ifdef __cpluscplus
}
#endif

#endif
