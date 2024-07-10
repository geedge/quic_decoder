#pragma once

#define QUIC_IS_LONG_HEADER(c) (c & 0x80)
#define QUIC_IS_FIXED_BIT(c)   (c & 0x40)

#define QUIC_PKT_TYPE_INITIAL   0x00
#define QUIC_PKT_TYPE_0RTT      0x01
#define QUIC_PKT_TYPE_HANDSHAKE 0x02
#define QUIC_PKT_TYPE_RETRY     0x03

// https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets 
struct quic_long_header{
    unsigned char type_specific_bit:4;
    unsigned char packet_type:2;
    unsigned char fixed_bit:1;
    unsigned char header_form:1;
    unsigned int version;
}__attribute__((packed));

// https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet
struct quic_initial_pkt_header{
    unsigned char packet_number_length:2;
    unsigned char reserved_bits:2;
    unsigned char packet_type:2;
    unsigned char fixed_bit:1;
    unsigned char header_form:1;
    unsigned int version;
}__attribute__((packed));

struct quic_short_header{
    unsigned char toto:5;
    unsigned char spin_bit:1;
    unsigned char fixed_bit:1;
    unsigned char header_form:1;
}__attribute__((packed));