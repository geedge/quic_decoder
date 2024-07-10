#pragma once
#ifdef __cplusplus
extern "C"
{
#endif
#include <stddef.h>

enum quic_message_type
{
    QUIC_CLIENT_HELLO,
    QUIC_SERVER_HELLO,
    QUIC_PROTECTED_PAYLOAD,
    QUIC_MSG_MAX,
};

#define QUIC_DECODER_TOPIC "QUIC_DECODER_MESSAGE"
struct quic_message;
enum quic_message_type quic_message_type_get(const struct quic_message *msg);

/*
 *  0 is reserved for version negotiation, will never represent a real protocol. 
 *  https://www.rfc-editor.org/rfc/rfc9000.html#name-versions 
*/
unsigned int quic_message_version_get(const struct quic_message *msg);
const char *quic_message_readable_version_get0(const struct quic_message *msg);
const char *quic_message_readable_ja3hash_get0(const struct quic_message *msg);
void quic_message_sni_get0(const struct quic_message *msg, char **result, size_t *len);
void quic_message_user_agent_get0(const struct quic_message *msg, char **result, size_t *len);
void quic_message_protected_payload_get0(const struct quic_message *msg, char **result, size_t *len);

#ifdef __cplusplus
}
#endif
