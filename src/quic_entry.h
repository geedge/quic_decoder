#pragma once

#include "quic_decoder.h"
#include <bits/types/struct_iovec.h>
typedef struct iovec qstring;

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#define FALSE	0x00
#define TRUE 	0x01
#define MAYBE 	0x02

#define QUIC_VERSION_STRING_MAX_SIZE (32)

#define	SUPPORT_QUIC_PORT_NUM	128

#define QUIC_HALF_CLOSE 			0x01
#define QUIC_WHOLE_CLOSE 			0x02
#define QUIC_DATA 			        0x03
#define QUIC_KEY 					1
#define QUIC_RETURN_NORM 				0x60
#define QUIC_RETURN_UNNORM 				0x61
#define QUIC_RETURN_RESET_BUFFER		0x62
#define QUIC_RETURN_DROPME 				0x63
#define MAX_REGION_NUM                  15
#define REGION_NAME_LEN                 32

struct quic_param
{
	struct stellar *st;
	int quic_plugid;
	int level;
	int quic_port_num;
	int decrypted_switch;
	// int max_parse_pkt_num;
	int max_chlo_size;
	// int context_bridge_id;
	int exdata_id;
	int udp_topic_id; //as subscriber
	int quic_topic_id; //as publisher
	unsigned short quic_port_list[SUPPORT_QUIC_PORT_NUM]; //network order
	char quic_conf_regionname[MAX_REGION_NUM][REGION_NAME_LEN];
	char log_path[128];
	void *logger;
};

enum quic_mes_type{
  VER_NEGO = 0,    //vertion negotiation packet
  PUB_RST,          //public reset packet
  FRAME,           //frame packet
  FEC,              //FEC packet
  Initial,          //iquic
  Retey,            //iquic
  Handshake,        //iquic
  MSG_UNKNOWN = 255
};
