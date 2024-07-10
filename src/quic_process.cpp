#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <MESA/MESA_handle_logger.h>
#include "quic_entry.h"
#include "quic_process.h"
#include "quic_deprotection.h"
#include "quic_header.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "quic_util.h"
#include <stellar/stellar.h>
#include <stellar/session.h>
#include <stellar/session_mq.h>
#include <stellar/session_exdata.h>
#ifdef __cplusplus
}
#endif

struct quic_client_hello_msg_hdr
{
	uint8_t handshake_type;
	uint8_t client_hello_len[3];
	uint16_t tls_version;
	uint8_t random[32];
};

static int check_port(const struct quic_param *quic_plugin_env, unsigned short port)
{
	for (int i = 0; i < quic_plugin_env->quic_port_num; i++)
	{
		if (quic_plugin_env->quic_port_list[i] == port)
		{
			return 1;
		}
	}
	return 0;
}

int quic_protocol_identify(struct session *sess, struct quic_param *quic_plugin_env)
{
	enum session_addr_type addr_type;
	struct session_addr *saddr = session_get0_addr(sess, &addr_type);
	unsigned short sport, dport;
	if (addr_type == SESSION_ADDR_TYPE_IPV4_UDP)
	{
		sport = saddr->ipv4.sport;
		dport = saddr->ipv4.dport;
	}
	else if (addr_type == SESSION_ADDR_TYPE_IPV6_UDP)
	{
		sport = saddr->ipv6.sport;
		dport = saddr->ipv6.dport;
	}
	else
	{
		return 0;
	}
	if (0 == (check_port(quic_plugin_env, sport) || check_port(quic_plugin_env, dport)))
	{
		return 0;
	}
	return 1;
}

static int gquic_pkn_bit2length(unsigned char bit_value)
{
	switch(bit_value)
	{
		case	0x30: return 6;
		case	0x20: return 4;
		case	0x10: return 2;
		default:
			return 1;
	}
	
	return 1;
}

/*
   for quic , the decrypted payload store in quic_dpt_t, will be freed after quic_decrypting_payload(),
   so we need to malloc memory and copy them to quic_info.
*/
#if 1
static int copy_extension_tag(const unsigned char *tag_start_pos, int tag_len, qstring *out)
{
	if(tag_start_pos!=NULL && tag_len>0)
	{
		if(out->iov_base!=NULL)
		{
			FREE(out->iov_base);
		}

		out->iov_base=CALLOC(1, tag_len+1);
		memcpy((void *)out->iov_base, tag_start_pos, tag_len);
		out->iov_len = tag_len;

		return tag_len;
	}

	return 0;
}
#else
static int quic_extension_tag_get0(const unsigned char *tag_start_pos, int tag_len, qstring *out)
{
	if(tag_start_pos!=NULL && tag_len>0)
	{
		out->iov_len = tag_len;
		out->iov_base = (void *)tag_start_pos;
		return tag_len;
	}
	return 0;
}
#endif

//Source: https://wise2.ipac.caltech.edu/staff/slw/docs/html/varint_8h_source.html
static int msb2_varint_decode(const unsigned char *buf, long *out)
{
	unsigned long val = buf[0] & 0x3f;
	unsigned int nfollow = 1<<(buf[0]>>6);
	switch (nfollow-1)
	{
         case 7: val = (val << 8) | buf[nfollow - 7]; /*fail through*/
         case 6: val = (val << 8) | buf[nfollow - 6]; /*fail through*/
         case 5: val = (val << 8) | buf[nfollow - 5]; /*fail through*/
         case 4: val = (val << 8) | buf[nfollow - 4]; /*fail through*/
         case 3: val = (val << 8) | buf[nfollow - 3]; /*fail through*/
         case 2: val = (val << 8) | buf[nfollow - 2]; /*fail through*/
         case 1: val = (val << 8) | buf[nfollow-1];
         case 0: break;
     }
	*out=val;
	
    return nfollow;
}

/*

//https://docs.google.com/document/d/1FcpCJGTDEMblAs-Bm5TYuqhHyUqeWpqrItw2vkMFsdY/edit

Long Header (used for packets that are sent prior to the completion of version negotiation and establishment of 1-RTT keys):
+-+-+-+-+-+-+-+-+
|1|1|T|T|R|R|P|P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/64)              ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/64)                 ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (8/16/24/32)             ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


static int join_client_hello_frames(const unsigned char *payload, int payload_len, unsigned char *join_payload, int *join_payload_len)
{
	int joined_length=0;
	int payload_offset=0;
	long frame_type=0, frame_offset=0, frame_length=0;
	
	for(; payload_offset<payload_len; )
	{
		frame_type=payload[payload_offset++]; // Frame Type=1
		if(frame_type==IQUIC_FRAME_PADDING || frame_type==IQUIC_FRAME_PING)
		{
			continue;
		}

		payload_offset+=msb2_varint_decode((const unsigned char *)(payload+payload_offset), &frame_offset);
		payload_offset+=msb2_varint_decode((const unsigned char *)(payload+payload_offset), &frame_length);

		if(joined_length+frame_length>(*join_payload_len) || frame_offset<0 || frame_offset+frame_length>payload_len)
		{
			return -1;
		}
		memcpy(join_payload+frame_offset, payload+payload_offset, frame_length);
		joined_length+=frame_length;
		payload_offset+=frame_length;
	}

	(*join_payload_len)=joined_length;

	return joined_length;
}

static int parse_gquic_version_44to48_header(const char *payload, int payload_len, int *payload_offset)
{
	unsigned pkn_length=0;
	unsigned char client_CID_len=0;
	unsigned char server_CID_len=0;
	unsigned char public_flags=payload[*payload_offset];
	*payload_offset+=1; //skip public flags

	*payload_offset+=sizeof(int); // skip version
	
	if((payload[*payload_offset])&GQUIC_VERSION_44to48_CID_MASK)
	{
		client_CID_len=(payload[*payload_offset]&GQUIC_VERSION_44to48_CID_MASK) + 3;
	}

	if((payload[*payload_offset]>>4)&GQUIC_VERSION_44to48_CID_MASK)
	{
		server_CID_len=((payload[*payload_offset]>>4)&GQUIC_VERSION_44to48_CID_MASK) + 3;
	}

	*payload_offset+=1;  // both connection_id length
	*payload_offset+=server_CID_len;  // Destination connection id length
	*payload_offset+=client_CID_len;  // source connection id length
	
	pkn_length=(public_flags&GQUIC_VERSION_44to48_PKN_LEN_MASK)+1;
	*payload_offset+=pkn_length;

	*payload_offset+=12;  //message authentication hash
	
	return 1;
}

int parse_special_frame_stream(struct quic_info* quic_info, const unsigned char *payload, int payload_len)
{
	int tag_num = 0;
	int payload_offset=0;
	unsigned int message_tag;
	int pass_tag_num=0;
	int ext_tag_type=0;	
	int tag_value_start_offset=0;
	int total_tag_len=0,one_tag_len=0;	
	int parse_result=PARSE_RESULT_VERSION;
	int one_tag_offset_end=0,pre_one_tag_offset_end=0;

	if(payload_len-payload_offset<=8)
	{
		return PARSE_RESULT_VERSION;
	}
	
	switch(quic_info->quic_version)
	{
		case	GQUIC_VERSION_Q041:
			payload_offset+=1; // unknown
		case	GQUIC_VERSION_Q044:
			message_tag=(unsigned int)ntohl(*(unsigned int *)(payload+payload_offset));
			payload_offset+=4;

			tag_num=*(int *)(payload+payload_offset);
			payload_offset+=4; //tag_num
			break;
		default:
			message_tag=(unsigned int)ntohl(*(unsigned int *)(payload+payload_offset));
			payload_offset+=4;

			tag_num=*(unsigned short *)(payload+payload_offset);
			payload_offset+=2; //tag_num
			payload_offset+=2; //padding
			break;
	}

	if(message_tag!=CHLO || tag_num>64 || tag_num<=0)
	{
		return PARSE_RESULT_VERSION;
	}

	// if(quic_info->client_hello==NULL)
	// {
	// 	quic_info->client_hello=(struct quic_client_hello *)CALLOC(1, sizeof(struct quic_client_hello));
	// 	memset(quic_info->client_hello, 0, sizeof(struct quic_client_hello));
	// }

	tag_value_start_offset=payload_offset+tag_num*4*2;  // skip length of type and offset, type(offset)=szieof(int)

	while(tag_num>pass_tag_num)
	{
		ext_tag_type=ntohl(*(unsigned int *)(payload+payload_offset));
		payload_offset+=sizeof(int);
		
		one_tag_offset_end=*(unsigned int *)(payload+payload_offset);
		payload_offset+=sizeof(int);
		
		one_tag_len=one_tag_offset_end-pre_one_tag_offset_end;
		if(one_tag_len<=0 || (one_tag_offset_end>=payload_len) || (one_tag_len+tag_value_start_offset)>payload_len)
		{
			break;
		}

		switch(ext_tag_type)
		{
			case	TAG_UAID:
				copy_extension_tag(payload+tag_value_start_offset, one_tag_len, &quic_info->user_agent);
				parse_result=PARSE_RESULT_CLIENT_HELLO;
				break;
			case	TAG_SNI:
				copy_extension_tag(payload+tag_value_start_offset, one_tag_len, &quic_info->sni);
				parse_result=PARSE_RESULT_CLIENT_HELLO;
				break;
			default:
				break;
		}
			
		pass_tag_num++;
		tag_value_start_offset+=one_tag_len;
		total_tag_len+=one_tag_len;
		pre_one_tag_offset_end=one_tag_offset_end;
	}

	return parse_result;
}

int parse_quic_transport_parameter(struct quic_info *quic_info, const unsigned char *quic_para, int quic_para_len)
{
	int one_para_length=0;
	int para_offset=0;
	long one_para_type=0;
	
	while(quic_para_len > para_offset)
	{
		para_offset+=msb2_varint_decode((const unsigned char *)(quic_para+para_offset), &one_para_type);
		switch(one_para_type)
		{
			case	EXT_QUIC_PARAM_USER_AGENT: // 2021-10-20 deprecated
					one_para_length=quic_para[para_offset++]; // length=1
					if(one_para_length+para_offset>quic_para_len)
					{
						return 0;
					}
					para_offset+=copy_extension_tag(quic_para+para_offset, one_para_length, &quic_info->user_agent);
					return 1;
			default:
				one_para_length=(int)(quic_para[para_offset++]); // length=1
				if(one_para_length<0 || one_para_length>quic_para_len)
				{
					break;
				}
				para_offset+=one_para_length;
				break;
		}
	}

	return 0;
}

int parse_extension_server_name(struct quic_info *quic_info, const unsigned char *ext_server_name, int ext_server_name_length)
{
	unsigned short sni_type=0;
	unsigned short sni_length=0;
	unsigned short extension_offset=0;
	unsigned short server_name_list_len=0;
		
	server_name_list_len=ntohs(*(unsigned short *)(ext_server_name+extension_offset));  //Server Name List length
	if(server_name_list_len<=0 || server_name_list_len>ext_server_name_length)
	{
		return 0;
	}
	extension_offset+=2; //Server Name List length

	sni_type=ext_server_name[extension_offset++];  //Server Name type
	if(sni_type!=EXTENSION_SERVER_NAME)
	{
		return 0;
	}

	sni_length=ntohs(*(unsigned short*)(ext_server_name+extension_offset));  //Server Name length
	if(sni_length<=0 || sni_length>ext_server_name_length)
	{
		return 0;
	}
	extension_offset+=2;

	copy_extension_tag(ext_server_name+extension_offset, sni_length, &quic_info->sni);

	return 1;
}

int parse_tls_client_hello(struct quic_info *quic_info, const unsigned char *payload, int payload_len)
{
	int ret=0,skip_len=0;
	int payload_offset=0;
	int extension_offset=0;
	const unsigned char *extension_start_pos=NULL;	
	int parse_result=PARSE_RESULT_VERSION;
	unsigned short one_ext_type=0, one_ext_len=0, extension_total_len=0;

	if(payload_len-payload_offset<=(int)sizeof(struct quic_client_hello_msg_hdr))
	{
		return PARSE_RESULT_VERSION;
	}

	// handshake type(1), client hello length(3), ssl_version(2), Random(32)
	payload_offset+=sizeof(struct quic_client_hello_msg_hdr);

	skip_len=payload[payload_offset++];   //Session ID length
	if(payload_len-payload_offset<=skip_len)
	{
		return PARSE_RESULT_VERSION;
	}
	payload_offset+=skip_len;

	skip_len=ntohs(*(unsigned short *)(payload+payload_offset));  //Ciper Suites length
	if(payload_len-payload_offset<=skip_len+2)
	{
		return PARSE_RESULT_VERSION;
	}
	payload_offset+=skip_len+2;
	
	skip_len=payload[payload_offset++];   //Compression Methods
	if(payload_len-payload_offset<skip_len)
	{
		return PARSE_RESULT_VERSION;
	}
	payload_offset+=skip_len;
	
	extension_total_len=ntohs(*(unsigned short *)(payload+payload_offset));  //Extension length
	if(payload_len-payload_offset<extension_total_len)
	{
		return PARSE_RESULT_VERSION;
	}

	payload_offset+=2;

	// if(*client_hello==NULL)
	// {
	// 	*client_hello=(struct quic_client_hello *)CALLOC(1, sizeof(struct quic_client_hello));
	// 	// memset(*client_hello, 0, sizeof(struct quic_client_hello));
	// }

	extension_start_pos=payload+payload_offset;
	
	while(extension_total_len > extension_offset)
	{
		one_ext_type=ntohs(*(unsigned short *)(extension_start_pos+extension_offset));  //Extension type
		extension_offset+=2;
		
		one_ext_len=ntohs(*(unsigned short *)(extension_start_pos+extension_offset));	//length
		extension_offset+=2;
		
		if(extension_total_len-extension_offset<one_ext_len)
		{
			break;
		}
				
		switch(one_ext_type)
		{
			case	EXTENSION_SERVER_NAME:
				ret=parse_extension_server_name(quic_info, extension_start_pos+extension_offset, one_ext_len);
				break;
			case	EXTENSION_QUIC_PARAM_TLS_13:
			case	EXTENSION_QUIC_PARAM_TLS_33:
				ret=parse_quic_transport_parameter(quic_info, extension_start_pos+extension_offset, one_ext_len);
				break;
			default:
				break;
		}

		if(ret==1)
		{
			ret=0;
			parse_result=PARSE_RESULT_CLIENT_HELLO;
		}
		
		extension_offset+=one_ext_len;
	}
	
	return parse_result;
}

int get_chlo_total_length(const unsigned char *payload, int payload_len)
{
	const struct quic_client_hello_msg_hdr *chlo_hdr=(const struct quic_client_hello_msg_hdr *)payload;
	int chlo_len=0;
	uint8_t *p = (uint8_t *)&chlo_len;
	p[2] = chlo_hdr->client_hello_len[0];
	p[1] = chlo_hdr->client_hello_len[1];
	p[0] = chlo_hdr->client_hello_len[2];
	return chlo_len;
}

int parse_quic_decrypted_payload(struct quic_info *quic_info, const unsigned char * payload, int payload_len)
{
	unsigned char join_payload[MAX_CLIENT_HELLO_CHUNK_SIZE]={0};
	int join_payload_len=sizeof(join_payload);
	unsigned int quic_version=quic_info->quic_version;

	if( (quic_version>=MVFST_VERSION_00 && quic_version<=MVFST_VERSION_0F)		||
		(quic_version>=GQUIC_VERSION_T050 && quic_version<=GQUIC_VERSION_T059)	||
		(quic_version>=IQUIC_VERSION_I022 && quic_version<=IQUIC_VERSION_I029)	||
		(quic_version==IQUIC_VERSION_RFC9000)
		)
	{
		join_payload_len=join_client_hello_frames(payload, payload_len, join_payload, &join_payload_len);
		if(join_payload_len<=0)
		{
			return PARSE_RESULT_VERSION;
		}
		
		if(join_payload[0] == QUIC_HANDSHAKE_TYPE_CLIENTHELLO)
		{
			return parse_tls_client_hello(quic_info, join_payload, join_payload_len);
		}
	}
	else //if(quic_version>=GQUIC_VERSION_Q047 && quic_version<=GQUIC_VERSION_Q059)
	{	
		return parse_special_frame_stream(quic_info, payload+4, payload_len-4); // Frame type=1,offset=1,length=2
	}

	return PARSE_RESULT_VERSION;
}

int parse_quic_uncryption_payload(struct quic_info *quic_info, const unsigned char * payload, int payload_len)
{
	int stream_id_len=0;
	int offset_len=0;
	unsigned char frame_type;
	int payload_offset=0;
	
	frame_type=payload[payload_offset];
	payload_offset+=1;  //skip frame_type

	//https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit# 
	//Frame Type: The Frame Type byte is an 8-bit value containing various flags (1fdooossB):
	if(frame_type&GQUIC_SPECIAL_FRAME_STREAM || (frame_type&0xC0)==GQUIC_SPECIAL_FRAME_ACK)
	{
		stream_id_len=(frame_type&GQUIC_SPECIAL_FRAME_STREAM_ID)+1;
		if(payload_len-payload_offset<=stream_id_len)
		{
			return PARSE_RESULT_VERSION;
		}
			
		payload_offset+=stream_id_len;	// stream ID length
		
		if(frame_type&GQUIC_SPECIAL_FRAME_STREAM_DLEN)
		{
			if(payload_len-payload_offset<2)
			{
				return PARSE_RESULT_VERSION;
			}
			payload_offset+=2;  //data length
		}

		if(frame_type&GQUIC_SPECIAL_FRAME_STREAM_OFFSET)
		{//The next three 'ooo' bits encode the length of the Offset header field as 0, 16, 24, 32, 40, 48, 56, or 64 bits long.
			offset_len= (((frame_type&GQUIC_SPECIAL_FRAME_STREAM_OFFSET))>>2)+1;
			if(payload_len-payload_offset<=offset_len)
			{
				return PARSE_RESULT_VERSION;
			}
			payload_offset+=offset_len;  //data length
		}
		
		return parse_special_frame_stream(quic_info, payload+payload_offset, payload_len-payload_offset);
	}
	
	return PARSE_RESULT_VERSION;
}

/*
//https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit

--- src
     0        1        2        3        4            8
+--------+--------+--------+--------+--------+---    ---+
| Public |    Connection ID (64)    ...                 | ->
|Flags(8)|      (optional)                              |
+--------+--------+--------+--------+--------+---    ---+

     9       10       11        12   
+--------+--------+--------+--------+
|      QUIC Version (32)            | ->
|         (optional)                |                           
+--------+--------+--------+--------+


    13       14       15        16      17       18       19       20
+--------+--------+--------+--------+--------+--------+--------+--------+
|                        Diversification Nonce                          | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+

    21       22       23        24      25       26       27       28
+--------+--------+--------+--------+--------+--------+--------+--------+
|                   Diversification Nonce Continued                     | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+

    29       30       31        32      33       34       35       36
+--------+--------+--------+--------+--------+--------+--------+--------+
|                   Diversification Nonce Continued                     | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+

    37       38       39        40      41       42       43       44
+--------+--------+--------+--------+--------+--------+--------+--------+
|                   Diversification Nonce Continued                     | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+


    45      46       47        48       49       50
+--------+--------+--------+--------+--------+--------+
|           Packet Number (8, 16, 32, or 48)          |
|                  (variable length)                  |
+--------+--------+--------+--------+--------+--------+

*/
enum QUIC_VERSION_T identify_gquic_version0to43(const char *payload, int payload_len, int *payload_offset)
{
	unsigned char pkn_length=0;
	unsigned char public_flags=0;
	enum QUIC_VERSION_T quic_version=QUIC_VERSION_UNKNOWN;

	public_flags=payload[*payload_offset];
	*payload_offset+=1;

	if(!(public_flags&GQUIC_PUBLIC_FLAG_VERSION))
	{
		return QUIC_VERSION_UNKNOWN;
	}

	/*
		0x08 = Indicates the full 8 byte Connection ID is present in the packet. 
		This must be set in all packets until negotiated to a different value for a given direction
		(e.g., client may request fewer bytes of the Connection ID be presented)
	*/
	if(public_flags&GQUIC_PUBLIC_FLAG_CID)
	{
		*payload_offset+=8; // CID length
	}
	
	if(public_flags&GQUIC_PUBLIC_FLAG_VERSION && (*(unsigned char *)(payload+*payload_offset)==0x51))
	{
		quic_version=(enum QUIC_VERSION_T)ntohl(*(unsigned int *)(payload+*payload_offset));
		*payload_offset+=sizeof(int); // skip version
	}
	
	if(quic_version<GQUIC_VERSION_Q001 || quic_version>GQUIC_VERSION_Q043)
	{
		return QUIC_VERSION_UNKNOWN;
	}

	pkn_length=gquic_pkn_bit2length(public_flags&GQUIC_VERSION_0to43_PKN_LEN_MASK);
	*payload_offset+=pkn_length; // packet number length
	
	if(public_flags==GQUIC_PUBLIC_FLAG_NONCE)
	{
		*payload_offset+=32; //diversification nonce
	}

	// Version 11 reduced the length of null encryption authentication tag  from 16 to 12 bytes
	if(quic_version > GQUIC_VERSION_Q010)
	{
		*payload_offset+=12;
	}
	else
	{
		*payload_offset+=16;
	}
	
	// Version 34 removed entropy bits from packets and ACK frames, 
	// removed private flag from packet header and changed the ACK format to specify ranges of packets acknowledged rather than missing ranges.
	if(quic_version < GQUIC_VERSION_Q034)
	{
		*payload_offset+=1;  //private flags
	}

	return quic_version;	
}

enum QUIC_VERSION_T identify_quic_version(const char *payload, int payload_len, int *payload_offset)
{
	enum QUIC_VERSION_T quic_version=(enum QUIC_VERSION_T)ntohl(*(unsigned int *)(payload+(*payload_offset+1)));
	if(quic_version>=GQUIC_VERSION_Q044 && quic_version<=GQUIC_VERSION_Q048)
	{
		parse_gquic_version_44to48_header(payload, payload_len, payload_offset);
		return quic_version;	
	}
	else if(
			(quic_version==GQUIC_VERSION_Q099) ||
			(quic_version==PICOQUIC_VERSION_30) ||
			(quic_version==PQUIC_VERSION_PROX) ||
			(quic_version==GQUIC_VERSION_T099) ||
			(quic_version>=GQUIC_VERSION_Q049 && quic_version<=GQUIC_VERSION_Q050) ||
			(quic_version>=GQUIC_VERSION_Q051 && quic_version<=GQUIC_VERSION_Q059) ||
			(quic_version>=GQUIC_VERSION_T048 && quic_version<=GQUIC_VERSION_T049) ||
			(quic_version>=GQUIC_VERSION_T050 && quic_version<=GQUIC_VERSION_T059) ||
			(quic_version>=QUANT_VERSION_00 && quic_version<=QUANT_VERSION_FF) ||
			(quic_version>=QUIC_GO_VERSION_00 && quic_version<=QUIC_GO_VERSION_FF) ||
			(quic_version>=QUICLY_VERSION_00 && quic_version<=QUICLY_VERSION_FF) ||
			(quic_version>=MSQUIC_VERSION_00 && quic_version<=MSQUIC_VERSION_0F) ||
			(quic_version>=MOZQUIC_VERSION_00 && quic_version<=MOZQUIC_VERSION_0F) ||
			(quic_version>=MVFST_VERSION_00 && quic_version<=MVFST_VERSION_0F) ||
			(quic_version>=IQUIC_VERSION_I001 && quic_version<=IQUIC_VERSION_I032) ||
			(quic_version==IQUIC_VERSION_RFC9000)
	)
	{		
		return quic_version;
	}

	return QUIC_VERSION_UNKNOWN;
}

enum QUIC_VERSION_T is_quic_protocol(const char *payload, int payload_len, int *payload_offset)
{
	enum QUIC_VERSION_T quic_version=QUIC_VERSION_UNKNOWN;
	unsigned char frame_type=(unsigned char)(payload[0]);

	if(payload_len<=4)
	{
		return QUIC_VERSION_UNKNOWN;
	}

	if(frame_type&QUIC_LONG_HEADER_MASK)
	{
		quic_version=identify_quic_version(payload, payload_len, payload_offset);
	}
	else if(frame_type<QUIC_LONG_HEADER_MASK)
	{		
		quic_version=identify_gquic_version0to43(payload, payload_len, payload_offset);
	}
	else
	{
		return QUIC_VERSION_UNKNOWN;
	}
	
	return quic_version;
}

//
static void quic_chlo_chunk_assemble(struct quic_buffer *qbuf, unsigned char *new_payload, int new_len)
{
	if(NULL == new_payload || new_len <= 0){
		return;
	}
	if(NULL == qbuf->buffer){
		qbuf->buffer = (unsigned char *)calloc(1, MAX_CLIENT_HELLO_CHUNK_SIZE);
		qbuf->max_size = MAX_CLIENT_HELLO_CHUNK_SIZE;
	}
	int max_copy_len = MIN((int)(qbuf->max_size - qbuf->datalen), new_len);
	memcpy(qbuf->buffer + qbuf->datalen, new_payload, max_copy_len);
	qbuf->datalen += max_copy_len;
}

/*
	1: is chlo, is complete.
	0: is chlo, is fragment;
	-1: not support
*/
static int quic_chlo_is_complete(enum QUIC_VERSION_T quic_version, const unsigned char *payload, int payload_len)
{
	if(!( (quic_version>=MVFST_VERSION_00 && quic_version<=MVFST_VERSION_0F)	||
		(quic_version>=GQUIC_VERSION_T050 && quic_version<=GQUIC_VERSION_T059)	||
		(quic_version>=IQUIC_VERSION_I022 && quic_version<=IQUIC_VERSION_I029)	||
		(quic_version==IQUIC_VERSION_RFC9000)))
	{
		return -1;
	}

	if((payload[0] != IQUIC_FRAME_CRYPTO) && (payload[0] != 0x08)) 
	{
		return -1;
	}
	int payload_offset = 0;
	long frame_offset, frame_length;
	payload_offset = 1; //skip frame type
	payload_offset+=msb2_varint_decode(payload+payload_offset, &frame_offset);
	payload_offset+=msb2_varint_decode(payload+payload_offset, &frame_length);

	if(payload[payload_offset] != QUIC_HANDSHAKE_TYPE_CLIENTHELLO)
	{
		return -1;
	}
	int expect_len = get_chlo_total_length(payload + payload_offset, payload_len-payload_offset);
	if(payload_len-payload_offset >= expect_len){
		return 1;
	}
	return 0;
}

static enum PARSE_RESULT quic_decrypting_payload(struct quic_context *qcontext, unsigned char *udp_payload, int udp_payload_len)
{
	struct quic_buffer *qbuf = &qcontext->quic_buf;
	unsigned char *quic_decrypted_payload;
	int ret, quic_decrypted_payload_len;
	quic_dpt_t *dpt = quic_deprotection_new();

	if(quic_deprotection(dpt, (const u_char *)udp_payload, udp_payload_len) < 0){
		goto err_exit;
	}

	if(qbuf->datalen > 0){ //some fragment exist
		quic_chlo_chunk_assemble(qbuf, dpt->payload.data, dpt->payload.len);
		quic_decrypted_payload = qbuf->buffer;
		quic_decrypted_payload_len = qbuf->datalen;
	}else{
		quic_decrypted_payload = dpt->payload.data;
		quic_decrypted_payload_len = dpt->payload.len;
	}

	ret = quic_chlo_is_complete((enum QUIC_VERSION_T)qcontext->quic_info.quic_version, quic_decrypted_payload, quic_decrypted_payload_len);
	if(0 == ret){
		if(NULL == qbuf->buffer || 0 == qbuf->datalen){
			quic_chlo_chunk_assemble(qbuf, dpt->payload.data, dpt->payload.len);
		}
		goto fun_exit;
	}else{
		qbuf->is_completed = 1;
	}
	parse_quic_decrypted_payload(&qcontext->quic_info, quic_decrypted_payload, quic_decrypted_payload_len);

fun_exit:	
	quic_deprotection_free(dpt);
	return PARSE_RESULT_VERSION;

err_exit:
	quic_deprotection_free(dpt);
	return PARSE_RESULT_VERSION;
}

enum PARSE_RESULT parse_quic_all_version(const struct quic_param *g_quic_plugin_env, struct quic_context *qcontext, const char *payload, int payload_len)
{
	struct quic_info *quic_info = &qcontext->quic_info;
	int payload_offset = 0;
	enum QUIC_VERSION_T quic_version = QUIC_VERSION_UNKNOWN;

	if (payload == NULL || payload_len <= 0)
	{
		return PARSE_RESULT_UNKNOWN;
	}
	quic_version = is_quic_protocol(payload, payload_len, &payload_offset);
	if (quic_version == QUIC_VERSION_UNKNOWN)
	{
		if(QUIC_IS_LONG_HEADER(payload[0]) == 0){
			return PARSE_RESULT_PAYLOAD;
		}
		return PARSE_RESULT_UNKNOWN;
	}

	if (quic_version >= GQUIC_VERSION_Q001 && quic_version <= GQUIC_VERSION_Q048)
	{
		if (payload_len > payload_offset)
		{
			return (enum PARSE_RESULT)parse_quic_uncryption_payload(quic_info, (const unsigned char *)payload + payload_offset, payload_len - payload_offset);
		}
		return PARSE_RESULT_VERSION;
	}
	else if (((quic_version >= MVFST_VERSION_00 && quic_version <= MVFST_VERSION_0F) ||
			  (quic_version >= GQUIC_VERSION_Q049 && quic_version <= GQUIC_VERSION_Q059) ||
			  (quic_version >= GQUIC_VERSION_T050 && quic_version <= GQUIC_VERSION_T059) ||
			  (quic_version >= GQUIC_VERSION_T050 && quic_version <= GQUIC_VERSION_T059) ||
			  (quic_version >= IQUIC_VERSION_I022 && quic_version <= IQUIC_VERSION_I029) ||
			  (quic_version == IQUIC_VERSION_RFC9000)) &&
			 g_quic_plugin_env->decrypted_switch > 0)
	{
		return quic_decrypting_payload(qcontext, (unsigned char *)payload, payload_len);
	}
	else
	{
		return PARSE_RESULT_VERSION;
	}

	return PARSE_RESULT_VERSION;
}

static void quic_info_clear(struct quic_info *qinfo)
{
	if(qinfo->sni.iov_base){
		free(qinfo->sni.iov_base);
		qinfo->sni.iov_base = NULL;
		qinfo->sni.iov_len = 0;
	}
	if(qinfo->user_agent.iov_base){
		free(qinfo->user_agent.iov_base);
		qinfo->user_agent.iov_base = NULL;
		qinfo->user_agent.iov_len = 0;
	}
	if(qinfo->payload.iov_base){
		free(qinfo->payload.iov_base);
		qinfo->payload.iov_base = NULL;
		qinfo->payload.iov_len = 0;
	}
}

static void quic_buffer_clear(struct quic_buffer *qbuf)
{
	if(qbuf->buffer != NULL && qbuf->is_completed == 1){
		free(qbuf->buffer);
		qbuf->buffer = NULL;
		qbuf->datalen = 0;
		qbuf->max_size = 0;
		qbuf->is_completed = 0;
	}
}

void quic_analyze_entry(struct session *sess, const struct quic_param *quic_plugin_env, struct quic_context *qcontext, int thread_seq, const char *payload, size_t payload_len)
{
	struct quic_message *qmsg;
	enum PARSE_RESULT res;

	quic_info_clear(&qcontext->quic_info);
	quic_buffer_clear(&qcontext->quic_buf);

	res = parse_quic_all_version(quic_plugin_env, qcontext, payload, payload_len);
	if (res == PARSE_RESULT_UNKNOWN){
		stellar_session_plugin_dettach_current_session(sess);
		return;
	}

	if(res == PARSE_RESULT_PAYLOAD){
		qmsg = quic_create_message(QUIC_PROTECTED_PAYLOAD, qcontext);
		quic_session_mq_publish_message_safe(sess, quic_plugin_env->quic_topic_id, qmsg);
		return;
	}

	if(qcontext->quic_info.sni.iov_base || qcontext->quic_info.user_agent.iov_base){
		qmsg = quic_create_message(QUIC_CLIENT_HELLO, qcontext);
		quic_session_mq_publish_message_safe(sess, quic_plugin_env->quic_topic_id, qmsg);
	}
	return;
}

void quic_session_mq_publish_message_safe(struct session *sess, int topic_id, void *msg)
{
	int ret = session_mq_publish_message(sess, topic_id, msg);
	if(ret < 0){
		FREE(msg);
	}
	return;
}
struct quic_message *quic_create_message(enum quic_message_type mtype, struct quic_context *context)
{
	struct quic_message *msg = (struct quic_message *)CALLOC(1, sizeof(struct quic_message));
	msg->magic = QUIC_MSG_HDR_MAGIC;
	msg->type = mtype;
	msg->qctx = context;
	return msg;
}

#ifdef __cplusplus
extern "C"
{
#endif
enum quic_message_type quic_message_type_get(const struct quic_message *msg)
{
	assert(QUIC_MSG_HDR_MAGIC == msg->magic);
	if(QUIC_MSG_HDR_MAGIC != msg->magic){
		return QUIC_MSG_MAX;
	}
	return msg->type;
}

unsigned int quic_message_version_get(const struct quic_message *msg)
{
	assert(QUIC_MSG_HDR_MAGIC == msg->magic);
	return msg->qctx->quic_info.quic_version;
}

const char *quic_message_readable_version_get0(const struct quic_message *msg)
{
	assert(QUIC_MSG_HDR_MAGIC == msg->magic);
	quic_version_int2string(msg->qctx->quic_info.quic_version, msg->qctx->quic_info.quic_version_str, QUIC_VERSION_STRING_MAX_SIZE);
	return msg->qctx->quic_info.quic_version_str;
}

const char *quic_message_readable_ja3hash_get0(const struct quic_message *msg)
{
	//todo
	return NULL;
}

void quic_message_sni_get0(const struct quic_message *msg, char **result, size_t *len)
{
	assert(QUIC_MSG_HDR_MAGIC == msg->magic);
	if(result){
		*result = (char *)msg->qctx->quic_info.sni.iov_base;
	}
	if(len){
		*len = msg->qctx->quic_info.sni.iov_len;
	}
}
void quic_message_user_agent_get0(const struct quic_message *msg, char **result, size_t *len)
{
	assert(QUIC_MSG_HDR_MAGIC == msg->magic);
	if(result){
		*result = (char *)msg->qctx->quic_info.user_agent.iov_base;
	}
	if(len){
		*len = msg->qctx->quic_info.user_agent.iov_len;
	}
}

void quic_message_protected_payload_get0(const struct quic_message *msg, char **result, size_t *len)
{
	assert(QUIC_MSG_HDR_MAGIC == msg->magic);
	if(result){
		*result = (char *)msg->qctx->quic_info.payload.iov_base;
	}
	if(len){
		*len = msg->qctx->quic_info.payload.iov_len;
	}

}

#ifdef __cplusplus
}
#endif
