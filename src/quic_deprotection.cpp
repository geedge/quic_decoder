#include "quic_deprotection.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#define QUIC_IV_LEN 12 /* RFC 5116, 5.1 and RFC 8439, 2.3 for all supported ciphers */
#define QUIC_HP_LEN 5  /* RFC 9001, 5.4.1.  Header Protection Application: 5-byte mask */

#define QUIC_MAX_CID_LEN 20
#define QUIC_AES_128_KEY_LEN 16
#define QUIC_MIN_INITIAL_SIZE 1200
#define QUIC_UNSET_PN (uint64_t) - 1

/*
 * RFC 9000, 17.2.  Long  Header Packets
 *           17.3.  Short Header Packets
 * QUIC flags in first byte
 */
#define QUIC_PKT_LONG 0x80 /* header form */
#define QUIC_PKT_FIXED_BIT 0x40
#define QUIC_PKT_TYPE 0x30   /* in long packet */
#define QUIC_PKT_KPHASE 0x04 /* in short packet */

#define quic_pkt_header_is_long(flags) ((flags)&QUIC_PKT_LONG)
#define quic_pkt_header_is_short(flags) (((flags)&QUIC_PKT_LONG) == 0)
#define quic_pkt_hp_mask(flags) (quic_pkt_header_is_long(flags) ? 0x0F : 0x1F)
#define quic_pkt_rb_mask(flags) (quic_pkt_header_is_long(flags) ? 0x0C : 0x18)

/* Long packet types */
#define quic_pkt_level_is_initial(flags) (((flags)&QUIC_PKT_TYPE) == 0x00)
#define quic_pkt_level_is_zrtt(flags) (((flags)&QUIC_PKT_TYPE) == 0x10)
#define quic_pkt_level_is_handshake(flags) (((flags)&QUIC_PKT_TYPE) == 0x20)

/* MAX MIN */
#define MAX(val1, val2) ((val1 < val2) ? (val2) : (val1))
#define MIN(val1, val2) ((val1 > val2) ? (val2) : (val1))

#define quic_pkt_level_to_name(lvl)                     \
    (lvl == ssl_encryption_application) ? "application" \
    : (lvl == ssl_encryption_initial)   ? "initial"     \
    : (lvl == ssl_encryption_handshake) ? "handshake"   \
                                        : "early"

typedef struct
{
    const EVP_CIPHER *c;
    const EVP_CIPHER *hp;
    const EVP_MD *d;
} quic_ciphers_t;

///////////////////////////////////////////////////////////////////////////////
// QUIC version
///////////////////////////////////////////////////////////////////////////////

#define QUIC_NVERSIONS (sizeof(quic_version_vals) / sizeof(quic_version_vals[0]))

const quic_str_t quic_version_vals[] = {
    {0x00000000, (u_char *)"Version Negotiation"},
    {0x00000001, (u_char *)"1"},
    /* Versions QXXX < Q050 are dissected by Wireshark as GQUIC and not as QUIC.
       Nonetheless, some implementations report these values in "Version Negotiation"
       packets, so decode these fields */
    {0x51303433, (u_char *)"Google Q043"},
    {0x51303434, (u_char *)"Google Q044"},
    {0x51303436, (u_char *)"Google Q046"},
    {0x51303530, (u_char *)"Google Q050"},
    {0x54303530, (u_char *)"Google T050"},
    {0x54303531, (u_char *)"Google T051"},
    {0xfaceb001, (u_char *)"Facebook mvfst (draft-22)"},
    {0xfaceb002, (u_char *)"Facebook mvfst (draft-27)"},
    {0xfaceb00e, (u_char *)"Facebook mvfst (Experimental)"},
    {0xff000004, (u_char *)"draft-04"},
    {0xff000005, (u_char *)"draft-05"},
    {0xff000006, (u_char *)"draft-06"},
    {0xff000007, (u_char *)"draft-07"},
    {0xff000008, (u_char *)"draft-08"},
    {0xff000009, (u_char *)"draft-09"},
    {0xff00000a, (u_char *)"draft-10"},
    {0xff00000b, (u_char *)"draft-11"},
    {0xff00000c, (u_char *)"draft-12"},
    {0xff00000d, (u_char *)"draft-13"},
    {0xff00000e, (u_char *)"draft-14"},
    {0xff00000f, (u_char *)"draft-15"},
    {0xff000010, (u_char *)"draft-16"},
    {0xff000011, (u_char *)"draft-17"},
    {0xff000012, (u_char *)"draft-18"},
    {0xff000013, (u_char *)"draft-19"},
    {0xff000014, (u_char *)"draft-20"},
    {0xff000015, (u_char *)"draft-21"},
    {0xff000016, (u_char *)"draft-22"},
    {0xff000017, (u_char *)"draft-23"},
    {0xff000018, (u_char *)"draft-24"},
    {0xff000019, (u_char *)"draft-25"},
    {0xff00001a, (u_char *)"draft-26"},
    {0xff00001b, (u_char *)"draft-27"},
    {0xff00001c, (u_char *)"draft-28"},
    {0xff00001d, (u_char *)"draft-29"},
    {0xff00001e, (u_char *)"draft-30"},
    {0xff00001f, (u_char *)"draft-31"},
    {0xff000020, (u_char *)"draft-32"},
    {0, NULL}};

static int quic_version_is_supported(uint32_t version)
{
    unsigned int i = 0;
    for (i = 0; i < QUIC_NVERSIONS; i++)
    {
        if (quic_version_vals[i].len == version)
        {
            return 1;
        }
    }

    return 0;
}

// Returns the QUIC draft version or 0 if not applicable.
static inline uint8_t quic_draft_version(uint32_t version)
{
    if ((version >> 8) == 0xff0000)
        return (uint8_t)version;

    // Facebook mvfst, based on draft -22.
    if (version == 0xfaceb001)
        return 22;

    // Facebook mvfst, based on draft -27.
    if (version == 0xfaceb002 || version == 0xfaceb00e)
        return 27;

    // GQUIC Q050, T050 and T051: they are not really based on any drafts,
    // but we must return a sensible value
    if (version == 0x51303530 || version == 0x54303530 || version == 0x54303531)
        return 27;

    /* 
	 * https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
	 * "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
	 * forcing version negotiation to be exercised"
	 * It is tricky to return a correct draft version: such number is primarly
	 * used to select a proper salt (which depends on the version itself), but
	 * we don't have a real version here! Let's hope that we need to handle
	 * only latest drafts... 
	 */
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
        return 29;

    return 0;
}

static inline uint8_t quic_draft_is_max(uint32_t version, uint8_t max_version)
{
    uint8_t draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

///////////////////////////////////////////////////////////////////////////////
// quic_parse_packet_header()
///////////////////////////////////////////////////////////////////////////////

static inline u_char *quic_parse_uint8(const u_char *pos, const u_char *end, uint8_t *out)
{
    if ((size_t)(end - pos) < 1)
    {
        return NULL;
    }

    *out = *pos;
    return (u_char *)pos + 1;
}

static inline u_char *quic_parse_int(const u_char *pos, const u_char *end, uint64_t *out)
{
    u_char *p;
    uint64_t value;
    int len;

    if (pos >= end)
    {
        return NULL;
    }

    p = (u_char *)pos;
    len = 1 << (*p >> 6);

    value = *p++ & 0x3f;

    if ((size_t)(end - p) < (size_t)(len - 1))
    {
        return NULL;
    }

    while (--len)
    {
        value = (value << 8) + *p++;
    }

    *out = value;
    return p;
}

static inline u_char *quic_parse_uint32(const u_char *pos, const u_char *end, uint32_t *out)
{
    if ((size_t)(end - pos) < sizeof(uint32_t))
    {
        return NULL;
    }

    *out = ((uint32_t)(pos)[0] << 24 | (pos)[1] << 16 | (pos)[2] << 8 | (pos)[3]);
    return (u_char *)pos + sizeof(uint32_t);
}

static inline u_char *quic_parse_nbytes(const u_char *pos, const u_char *end, size_t len, u_char **out)
{
    if ((size_t)(end - pos) < len)
    {
        return NULL;
    }

    *out = (u_char *)pos;
    return (u_char *)pos + len;
}

static int quic_parse_short_header(quic_dpt_t *dpt, size_t dcid_len)
{
    u_char *p = dpt->pos;
    u_char *end = dpt->data + dpt->len;

    if (!(dpt->flags & QUIC_PKT_FIXED_BIT))
    {
        LOG_WARN("QUIC fixed bit is not set");
        return -1;
    }

    p = quic_parse_nbytes(p, end, dcid_len, &dpt->dcid.data);
    if (p == NULL)
    {
        LOG_WARN("QUIC packet is too small to read dcid");
        return -1;
    }
    dpt->dcid.len = dcid_len;

    dpt->pos = p;
    return 0;
}

static int quic_parse_long_header(quic_dpt_t *dpt)
{
    uint8_t idlen;

    u_char *p = dpt->pos;
    u_char *end = dpt->data + dpt->len;

    // Parser Version
    p = quic_parse_uint32(p, end, &dpt->version);
    if (p == NULL)
    {
        LOG_WARN("QUIC packet is too small to read version");
        return -1;
    }

    if (!(dpt->flags & QUIC_PKT_FIXED_BIT))
    {
        LOG_WARN("QUIC fixed bit is not set");
        return -1;
    }

    // Parser DCID
    p = quic_parse_uint8(p, end, &idlen);
    if (p == NULL)
    {
        LOG_WARN("QUIC packet is too small to read dcid len");
        return -1;
    }
    if (idlen > QUIC_MAX_CID_LEN)
    {
        LOG_WARN("QUIC packet dcid is too long");
        return -1;
    }
    dpt->dcid.len = idlen;

    p = quic_parse_nbytes(p, end, idlen, &dpt->dcid.data);
    if (p == NULL)
    {
        LOG_WARN("QUIC packet is too small to read dcid");
        return -1;
    }

    // Parser SCID
    p = quic_parse_uint8(p, end, &idlen);
    if (p == NULL)
    {
        LOG_WARN("QUIC packet is too small to read scid len");
        return -1;
    }
    if (idlen > QUIC_MAX_CID_LEN)
    {
        LOG_WARN("QUIC packet scid is too long");
        return -1;
    }

    dpt->scid.len = idlen;

    p = quic_parse_nbytes(p, end, idlen, &dpt->scid.data);
    if (p == NULL)
    {
        LOG_WARN("QUIC packet is too small to read scid");
        return -1;
    }

    dpt->pos = p;
    return 0;
}

static int quic_parse_long_header_v1(quic_dpt_t *dpt)
{
    uint64_t varint;

    u_char *p = dpt->pos;
    u_char *end = (u_char *)dpt->data + dpt->len;

    // ssl_encryption_initial
    if (quic_pkt_level_is_initial(dpt->flags))
    {
        dpt->level = ssl_encryption_initial;
        if (dpt->len < QUIC_MIN_INITIAL_SIZE)
        {
            LOG_WARN("QUIC UDP datagram is too small for initial packet");
            return -1;
        }

        // Parse Token
        p = quic_parse_int(p, end, &varint);
        if (p == NULL)
        {
            LOG_WARN("QUIC failed to parse token length");
            return -1;
        }
        dpt->token.len = varint;

        p = quic_parse_nbytes(p, end, dpt->token.len, &dpt->token.data);
        if (p == NULL)
        {
            LOG_WARN("QUIC packet too small to read token data");
            return -1;
        }
    }
    // ssl_encryption_early_data
    else if (quic_pkt_level_is_zrtt(dpt->flags))
    {
        dpt->level = ssl_encryption_early_data;
    }
    // ssl_encryption_handshake
    else if (quic_pkt_level_is_handshake(dpt->flags))
    {
        dpt->level = ssl_encryption_handshake;
    }
    else
    {
        LOG_WARN("QUIC bad packet type");
        return -1;
    }

    // Parse Packet Length
    p = quic_parse_int(p, end, &varint);
    if (p == NULL)
    {
        LOG_WARN("QUIC bad packet length");
        return -1;
    }
    dpt->pkt_len = varint;

    if (varint > (uint64_t)((dpt->data + dpt->len) - p))
    {
        LOG_WARN("QUIC truncated packet with level %s", quic_pkt_level_to_name(dpt->level));
        return -1;
    }

    dpt->pos = p;
    dpt->len = p + varint - dpt->data;

    return 0;
}

static int quic_parse_packet_header(quic_dpt_t *dpt)
{
    if (quic_pkt_header_is_short(dpt->flags))
    {
        dpt->header_type = SHORT;
        dpt->level = ssl_encryption_application;

        // Parser DCID
        if (quic_parse_short_header(dpt, QUIC_MAX_CID_LEN) != 0)
        {
            return -1;
        }

        return 0;
    }

    dpt->header_type = LONG;

    // Parser Version, DCID, SCID
    if (quic_parse_long_header(dpt) != 0)
    {
        return -1;
    }

    // Check QUIC Version
    if (!quic_version_is_supported(dpt->version))
    {
        LOG_WARN("QUIC version %08" PRIx32 "unsupport", dpt->version);
        return -1;
    }

    // Parser Level, Token, Packet Length
    if (quic_parse_long_header_v1(dpt) != 0)
    {
        return -1;
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// quic_keys_set_initial_secret()
///////////////////////////////////////////////////////////////////////////////

static int hkdf_expand(quic_str_t *out, const EVP_MD *digest, const quic_str_t *prk, const quic_str_t *info)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
    {
        LOG_ERROR("EVP_PKEY_CTX_new_id() failed");
        return -1;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        LOG_ERROR("EVP_PKEY_derive_init() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_hkdf_mode() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_set_hkdf_md() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk->data, prk->len) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_set1_hkdf_key() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info->data, info->len) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_add1_hkdf_info() failed");
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out->data, &(out->len)) <= 0)
    {
        LOG_ERROR("EVP_PKEY_derive() failed");
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;

failed:

    EVP_PKEY_CTX_free(pctx);
    return -1;
}

static int quic_hkdf_expand(const EVP_MD *digest, quic_str_t *out, const quic_str_t *label, const quic_str_t *prk)
{
    uint8_t info_buf[20];
    info_buf[0] = 0;
    info_buf[1] = out->len;
    info_buf[2] = label->len;

    uint8_t *p = (u_char *)memcpy(&info_buf[3], label->data, label->len) + label->len;
    *p = '\0';

    quic_str_t info;
    info.len = 2 + 1 + label->len + 1;
    info.data = info_buf;

    if (hkdf_expand(out, digest, prk, &info) != 0)
    {
        return -1;
    }

    return 0;
}

static int hkdf_extract(quic_str_t *out, const EVP_MD *digest, const quic_str_t *secret, const quic_str_t *initial_salt)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
    {
        LOG_ERROR("EVP_PKEY_CTX_new_id() failed");
        return -1;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        LOG_ERROR("EVP_PKEY_derive_init() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_hkdf_mode() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_set_hkdf_md() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret->data, secret->len) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_set1_hkdf_key() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, initial_salt->data, initial_salt->len) <= 0)
    {
        LOG_ERROR("EVP_PKEY_CTX_set1_hkdf_salt() failed");
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out->data, &(out->len)) <= 0)
    {
        LOG_ERROR("EVP_PKEY_derive() failed");
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;

failed:

    EVP_PKEY_CTX_free(pctx);
    return -1;
}

static int quic_keys_set_initial_secret(quic_secret_t *client_secret, const quic_str_t *dcid, uint32_t version)
{
    unsigned int i;
    const quic_str_t initial_salt_v1 = quic_string(
        "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a");
    const quic_str_t initial_salt_draft_22 = quic_string(
        "\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a");
    const quic_str_t initial_salt_draft_23 = quic_string(
        "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02");
    const quic_str_t initial_salt_draft_29 = quic_string(
        "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99");
    const quic_str_t initial_salt_draft_q50 = quic_string(
        "\x50\x45\x74\xEF\xD0\x66\xFE\x2F\x9D\x94\x5C\xFC\xDB\xD3\xA7\xF0\xD3\xB5\x6B\x45");
    const quic_str_t initial_salt_draft_t50 = quic_string(
        "\x7f\xf5\x79\xe5\xac\xd0\x72\x91\x55\x80\x30\x4c\x43\xa2\x36\x7c\x60\x48\x83\x10");
    const quic_str_t initial_salt_draft_t51 = quic_string(
        "\x7a\x4e\xde\xf4\xe7\xcc\xee\x5f\xa4\x50\x6c\x19\x12\x4f\xc8\xcc\xda\x6e\x03\x3d");

    const quic_str_t *initial_salt;
    if (version == 0x51303530)
    {
        initial_salt = &initial_salt_draft_q50;
    }
    else if (version == 0x54303530)
    {
        initial_salt = &initial_salt_draft_t50;
    }
    else if (version == 0x54303531)
    {
        initial_salt = &initial_salt_draft_t51;
    }
    else if (quic_draft_is_max(version, 22))
    {
        initial_salt = &initial_salt_draft_22;
    }
    else if (quic_draft_is_max(version, 28))
    {
        initial_salt = &initial_salt_draft_23;
    }
    else if (quic_draft_is_max(version, 32))
    {
        initial_salt = &initial_salt_draft_29;
    }
    else
    {
        initial_salt = &initial_salt_v1;
    }

    /*
     * RFC 9001, section 5.  Packet Protection
     *
     * Initial packets use AEAD_AES_128_GCM.  The hash function
     * for HKDF when deriving initial secrets and keys is SHA-256.
     */
    const EVP_MD *digest = EVP_sha256();

    uint8_t is[SHA256_DIGEST_LENGTH] = {0};
    quic_str_t initial_secret;
    initial_secret.data = is;
    initial_secret.len = SHA256_DIGEST_LENGTH;

    // Use dcid and initial_salt get initial_secret
    if (hkdf_extract(&initial_secret, digest, dcid, initial_salt) != 0)
    {
        return -1;
    }

    struct
    {
        quic_str_t label;
        quic_str_t *key;
        quic_str_t *prk;
    } seq[] = {
        /* labels per RFC 9001, 5.1. Packet Protection Keys */
        {quic_string("tls13 client in"), &client_secret->secret, &initial_secret},
        {quic_string("tls13 quic key"), &client_secret->key, &client_secret->secret},
        {quic_string("tls13 quic iv"), &client_secret->iv, &client_secret->secret},
        {quic_string("tls13 quic hp"), &client_secret->hp, &client_secret->secret},
    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++)
    {
        if (quic_hkdf_expand(digest, seq[i].key, &seq[i].label, seq[i].prk) != 0)
        {
            return -1;
        }
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// quic_deprotection_packet()
///////////////////////////////////////////////////////////////////////////////

static int quic_deprotection_header(const EVP_CIPHER *cipher, const quic_secret_t *secret, u_char *out, const u_char *in)
{
    int outlen;
    u_char zero[QUIC_HP_LEN] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, secret->hp.data, in) != 1)
    {
        LOG_ERROR("EVP_EncryptInit_ex() failed");
        goto failed;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, zero, QUIC_HP_LEN))
    {
        LOG_ERROR("EVP_EncryptUpdate() failed");
        goto failed;
    }

    if (!EVP_EncryptFinal_ex(ctx, out + QUIC_HP_LEN, &outlen))
    {
        LOG_ERROR("EVP_EncryptFinal_ex() failed");
        goto failed;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;

failed:

    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static uint64_t quic_deprotection_pktnum(u_char **pos, int len, const u_char *mask, uint64_t *largest_pkt_num)
{
    u_char *p;
    uint64_t truncated_pn, expected_pn, candidate_pn;
    uint64_t pn_nbits, pn_win, pn_hwin, pn_mask;

    pn_nbits = MIN(len * 8, 62);

    p = *pos;
    truncated_pn = *p++ ^ *mask++;

    while (--len)
    {
        truncated_pn = (truncated_pn << 8) + (*p++ ^ *mask++);
    }

    *pos = p;

    expected_pn = *largest_pkt_num + 1;
    pn_win = 1ULL << pn_nbits;
    pn_hwin = pn_win / 2;
    pn_mask = pn_win - 1;

    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if ((int64_t)candidate_pn <= (int64_t)(expected_pn - pn_hwin) && candidate_pn < (1ULL << 62) - pn_win)
    {
        candidate_pn += pn_win;
    }
    else if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
    {
        candidate_pn -= pn_win;
    }

    *largest_pkt_num = MAX((int64_t)*largest_pkt_num, (int64_t)candidate_pn);

    return candidate_pn;
}

static void quic_deprotection_nonce(u_char *nonce, size_t len, uint64_t pkt_num)
{
    nonce[len - 4] ^= (pkt_num & 0xff000000) >> 24;
    nonce[len - 3] ^= (pkt_num & 0x00ff0000) >> 16;
    nonce[len - 2] ^= (pkt_num & 0x0000ff00) >> 8;
    nonce[len - 1] ^= (pkt_num & 0x000000ff);
}

static int quic_deprotection_payload(const EVP_CIPHER *cipher, const quic_secret_t *secret, quic_str_t *out, const u_char *nonce, const quic_str_t *in, const quic_str_t *ad)
{
    int len;
    u_char *tag;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        LOG_ERROR("EVP_CIPHER_CTX_new() failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_DecryptInit_ex() failed");
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, secret->iv.len, NULL) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, secret->key.data, nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_DecryptInit_ex() failed");
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_DecryptUpdate() failed");
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, out->data, &len, in->data, in->len - EVP_GCM_TLS_TAG_LEN) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_DecryptUpdate() failed");
        return -1;
    }

    out->len = len;
    tag = in->data + in->len - EVP_GCM_TLS_TAG_LEN;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tag) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed");
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, out->data + len, &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("EVP_DecryptFinal_ex failed");
        return -1;
    }

    out->len += len;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

static int quic_deprotection_packet(quic_dpt_t *dpt)
{
    u_char *p, *sample;
    size_t len;
    uint64_t pkt_num, lpn;
    int pnl, rc, key_phase;
    quic_str_t in, ad;
    uint8_t nonce[QUIC_IV_LEN] = {0}, mask[QUIC_HP_LEN] = {0};

    // Init ciphers, only process the quic package whose level is init, so only use AES_128_GCM_SHA256
    quic_ciphers_t ciphers;
    ciphers.c = EVP_aes_128_gcm();
    ciphers.hp = EVP_aes_128_ctr();
    ciphers.d = EVP_sha256();

    // 使用 client_secret secrets
    quic_secret_t *secret = &dpt->client_secret;

    p = dpt->pos;
    len = dpt->data + dpt->len - p;

    /*
     * RFC 9001, 5.4.2. Header Protection Sample
     *           5.4.3. AES-Based Header Protection
     *           5.4.4. ChaCha20-Based Header Protection
     *
     * the Packet Number field is assumed to be 4 bytes long
     * AES and ChaCha20 algorithms sample 16 bytes
     */

    if (len < EVP_GCM_TLS_TAG_LEN + 4)
    {
        LOG_WARN("QUIC payload length %zu too small", len);
        return -1;
    }

    sample = p + 4;

    /******************************************************
     * header protection
     ******************************************************/

    // Use the ciphers.hp algorithm and the secret.HP to encrypt the data in the sample and store it in the mask
    if (quic_deprotection_header(ciphers.hp, secret, mask, sample) != 0)
    {
        return -1;
    }

    // Parse Flags After Decode
    dpt->flags ^= mask[0] & quic_pkt_hp_mask(dpt->flags);

    if (quic_pkt_header_is_short(dpt->flags))
    {
        key_phase = (dpt->flags & QUIC_PKT_KPHASE) != 0;

        if (key_phase != dpt->key_phase)
        {
            // TODO
            LOG_WARN("key need update !!!!");
        }
    }

    lpn = dpt->largest_pkt_num;

    // RFC pn_length = (packet[0] & 0x03) + 1
    // Parser Packet Number length
    pnl = (dpt->flags & 0x03) + 1;

    // Parser Packet number
    pkt_num = quic_deprotection_pktnum(&p, pnl, &mask[1], &lpn);
    dpt->pkt_num = pkt_num;

    /******************************************************
     * packet protection
     ******************************************************/

    in.data = p;
    in.len = len - pnl;

    ad.len = p - dpt->data;
    ad.data = dpt->plaintext;

    memcpy(ad.data, dpt->data, ad.len);
    ad.data[0] = dpt->flags;

    do
    {
        ad.data[ad.len - pnl] = pkt_num >> (8 * (pnl - 1)) % 256;
    } while (--pnl);

    memcpy(nonce, secret->iv.data, secret->iv.len);
    quic_deprotection_nonce(nonce, sizeof(nonce), pkt_num);

    dpt->payload.len = in.len - EVP_GCM_TLS_TAG_LEN;
    dpt->payload.data = dpt->plaintext + ad.len;

    // Parser payload
    rc = quic_deprotection_payload(ciphers.c, secret, &dpt->payload, nonce, &in, &ad);
    if (rc != 0)
    {
        return -1;
    }

    if (dpt->payload.len == 0)
    {
        /*
         * RFC 9000, 12.4.  Frames and Frame Types
         *
         * An endpoint MUST treat receipt of a packet containing no
         * frames as a connection error of type PROTOCOL_VIOLATION.
         */
        LOG_WARN("QUIC zero-length packet");
        return -1;
    }

    if (dpt->flags & quic_pkt_rb_mask(dpt->flags))
    {
        /*
         * RFC 9000, Reserved Bits
         *
         * An endpoint MUST treat receipt of a packet that has
         * a non-zero value for these bits, after removing both
         * packet and header protection, as a connection error
         * of type PROTOCOL_VIOLATION.
         */
        LOG_WARN("QUIC reserved bit set in packet");
        return -1;
    }

    // Set Largest Packet Number
    dpt->largest_pkt_num = lpn;
    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// debug
///////////////////////////////////////////////////////////////////////////////

static void quic_str_to_hex(u_char *data, size_t len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static u_char *quic_version_to_str(uint32_t version)
{
    unsigned int i = 0;
    for (i = 0; i < QUIC_NVERSIONS; i++)
    {
        if (quic_version_vals[i].len == version)
        {
            return quic_version_vals[i].data;
        }
    }
    return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// PUB API
///////////////////////////////////////////////////////////////////////////////

quic_dpt_t *quic_deprotection_new(void)
{
    quic_dpt_t *dpt = (quic_dpt_t *)calloc(1, sizeof(quic_dpt_t));

    // Allocate the space of length len + 1, instead of allocating the space of length len, mainly for the convenience of debugging printf
    dpt->client_secret.secret.len = SHA256_DIGEST_LENGTH;
    dpt->client_secret.secret.data = (u_char *)calloc(SHA256_DIGEST_LENGTH + 1, sizeof(u_char));

    dpt->client_secret.key.len = QUIC_AES_128_KEY_LEN;
    dpt->client_secret.key.data = (u_char *)calloc(QUIC_AES_128_KEY_LEN + 1, sizeof(u_char));

    dpt->client_secret.hp.len = QUIC_AES_128_KEY_LEN;
    dpt->client_secret.hp.data = (u_char *)calloc(QUIC_AES_128_KEY_LEN + 1, sizeof(u_char));

    dpt->client_secret.iv.len = QUIC_IV_LEN;
    dpt->client_secret.iv.data = (u_char *)calloc(QUIC_IV_LEN + 1, sizeof(u_char));

    // NOTE: QUIC_MAX_UDP_PAYLOAD_SIZE is 65527(form Nginx-quice offical)
    dpt->plaintext = (u_char *)calloc(QUIC_MAX_UDP_PAYLOAD_SIZE + 1, sizeof(u_char));

    return dpt;
}

void quic_deprotection_free(quic_dpt_t *dpt)
{
    if (dpt == NULL)
    {
        return;
    }

    if (dpt->client_secret.secret.data)
    {
        free(dpt->client_secret.secret.data);
        dpt->client_secret.secret.data = NULL;
        dpt->client_secret.secret.len = 0;
    }

    if (dpt->client_secret.key.data)
    {
        free(dpt->client_secret.key.data);
        dpt->client_secret.key.data = NULL;
        dpt->client_secret.key.len = 0;
    }

    if (dpt->client_secret.hp.data)
    {
        free(dpt->client_secret.hp.data);
        dpt->client_secret.hp.data = NULL;
        dpt->client_secret.hp.len = 0;
    }

    if (dpt->client_secret.iv.data)
    {
        free(dpt->client_secret.iv.data);
        dpt->client_secret.iv.data = NULL;
        dpt->client_secret.iv.len = 0;
    }

    if (dpt->plaintext)
    {
        free(dpt->plaintext);
        dpt->plaintext = NULL;
    }

    free(dpt);
    dpt = NULL;
}

void quic_deprotection_dump(quic_dpt_t *dpt)
{
    printf("QUIC version  : %08" PRIx32 " %s\n", dpt->version, quic_version_to_str(dpt->version));
    printf("QUIC type     : %s\n", dpt->header_type == LONG ? "long" : "short");
    printf("QUIC level    : %s\n", quic_pkt_level_to_name(dpt->level));
    printf("QUIC flags    : %x\n", dpt->flags);
    printf("QUIC num      : %" PRIu64 "\n", dpt->pkt_num);
    printf("QUIC len      : %" PRIu64 "\n", dpt->pkt_len);
    printf("QUIC larg_num : %" PRIu64 "\n", dpt->largest_pkt_num);

    printf("QUIC dcid     : %zu, ", dpt->dcid.len);
    quic_str_to_hex(dpt->dcid.data, dpt->dcid.len);

    printf("QUIC scid     : %zu, ", dpt->scid.len);
    quic_str_to_hex(dpt->scid.data, dpt->scid.len);

    printf("QUIC token    : %zu, ", dpt->token.len);
    quic_str_to_hex(dpt->token.data, dpt->token.len);

    printf("QUIC hp       : %zu, ", dpt->client_secret.hp.len);
    quic_str_to_hex(dpt->client_secret.hp.data, dpt->client_secret.hp.len);

    printf("QUIC iv       : %zu, ", dpt->client_secret.iv.len);
    quic_str_to_hex(dpt->client_secret.iv.data, dpt->client_secret.iv.len);

    printf("QUIC key      : %zu, ", dpt->client_secret.key.len);
    quic_str_to_hex(dpt->client_secret.key.data, dpt->client_secret.key.len);

    printf("QUIC secretn  : %zu, ", dpt->client_secret.secret.len);
    quic_str_to_hex(dpt->client_secret.secret.data, dpt->client_secret.secret.len);

    printf("QUIC plaintex : %zu, ", strlen((char *)dpt->plaintext));
    quic_str_to_hex(dpt->plaintext, strlen((char *)dpt->plaintext));

    printf("QUIC payload  : %zu, ", dpt->payload.len);
    quic_str_to_hex(dpt->payload.data, dpt->payload.len);
}

int quic_deprotection(quic_dpt_t *dpt, const u_char *payload, size_t payload_len)
{
    dpt->data = (u_char *)payload;
    dpt->len = payload_len;
    dpt->pos = (u_char *)dpt->data;
    dpt->flags = payload[0];
    dpt->pos++;
    dpt->largest_pkt_num = QUIC_UNSET_PN;

    // Parser Level, Version, DCID, SCID, Token, Packet Length
    if (quic_parse_packet_header(dpt) == -1)
    {
        return -1;
    }

    if (dpt->level != ssl_encryption_initial)
    {
        LOG_WARN("QUIC level %s ignoring", quic_pkt_level_to_name(dpt->level))
        return -1;
    }

    /*
     * 1.Get the initial_salt to be used through pkt_version
     * 2.DCID and initial_salt generate initial_secret through SHA-256
     * 3.IN/Key/IV/HP lable of initial_secret and client_secret generates HP/Key/IV key of client_secret
     */
    if (quic_keys_set_initial_secret(&dpt->client_secret, &dpt->dcid, dpt->version) == -1)
    {
        goto failed;
    }

    if (dpt->client_secret.key.len == 0)
    {
        LOG_WARN("QUIC packet no client_secret, ignoring");
        goto failed;
    }

    if (quic_deprotection_packet(dpt) == -1)
    {
        goto failed;
    }

    // deprotection data: dpt->payload.data

    return 0;

failed:

    return -1;
}