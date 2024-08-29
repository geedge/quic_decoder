#include <stdio.h>
#include <assert.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "quic_decoder.h"
#include "quic_entry.h"
#include "quic_process.h"
#include "quic_deprotection.h"
#include "quic_util.h"

static const char *g_quic_proto_conffile="./conf/quic/main.conf";
// static const char *g_quic_regionname_conffile="./conf/quic/quic.conf";
static const char *g_quic_log_path = "./log/quic/quic";
#ifdef __cplusplus
extern "C"
{
#endif
#include <stellar/stellar.h>
#include <stellar/session.h>
#include <stellar/session_mq.h>
#include <stellar/session_exdata.h>

#define GIT_VERSION_CATTER(v) __attribute__((__used__)) const char * GIT_VERSION_##v = NULL
#define GIT_VERSION_EXPEND(v) GIT_VERSION_CATTER(v)

/* VERSION TAG */
#ifdef GIT_VERSION
GIT_VERSION_EXPEND(GIT_VERSION);
#else
static __attribute__((__used__)) const char * GIT_VERSION_UNKNOWN = NULL;
#endif
#undef GIT_VERSION_CATTER
#undef GIT_VERSION_EXPEND

#ifdef __cplusplus
}
#endif

static int parse_quic_port(char *port_list, unsigned short *quic_port, int quic_port_num)
{
	int	i=0,ret=0;
	int port_num=0;
	int range_len=0,used_len=0;
	char buf[256]={0};
	unsigned short s_port=0,e_port=0;
	char *begin=NULL,*end=NULL,*pchr=NULL;

	if(port_list==NULL)
	{
		return 0;
	}
	
	begin=port_list;
	end=NULL;
	range_len=strlen(port_list);
	
	while(range_len>used_len)
	{
		end=index(begin, ';');
		if(end==NULL)
		{
			end=begin+range_len-used_len;
		}

		if(end==begin)
		{
			break;
		}
		
		memset(buf, 0, sizeof(buf));
		strncpy(buf, begin, end-begin);
		used_len+=end-begin+1;
		if(range_len>used_len)
		{			
			begin=end+1;
		}
		
		pchr=strchr(buf, '-');
		if(pchr == NULL)
		{
			s_port=(unsigned short)atoi(buf);
			e_port=s_port;

		}
		else
		{
			ret=sscanf(buf, "%hu-%hu", &s_port, &e_port);
			if(ret!=2)
			{
				continue;
			}
		}
		
		for(i=s_port; i<=e_port && port_num<quic_port_num; i++)
		{
			quic_port[port_num++]= htons((unsigned short)i);
		}
	}

	return port_num;
}

static void free_quicinfo(struct quic_info *quic_info)
{
	if(quic_info->sni.iov_base)
		FREE(quic_info->sni.iov_base);

	if(quic_info->user_agent.iov_base)
		FREE(quic_info->user_agent.iov_base);
	return ;
}

extern "C" void quic_on_session_msg_cb(struct session *sess, int topic_id, const void *msg, void *per_session_ctx, void *plugin_env)
{
	struct quic_param *quic_plugin_env = (struct quic_param *)plugin_env;
	struct quic_context *context = (struct quic_context *)per_session_ctx;

	int thread_seq = session_get_current_thread_id(sess);
	const char *payload = NULL;
	size_t payload_len = -1;

	enum session_state sstate = session_get_current_state(sess);
	if(sstate == SESSION_STATE_CLOSING)
	{
		return;
	}

	payload = session_get0_current_payload(sess, &payload_len);
	if(NULL == payload || payload_len <= 0)
	{
		return;
	}
	quic_analyze_entry(sess, quic_plugin_env, context, thread_seq, payload, payload_len);

	return;
}

void *quic_session_ctx_new_cb(struct session *sess, void *plugin_env)
{
	struct quic_param *quic_plugin_env = (struct quic_param *)plugin_env;
	if(0 == quic_protocol_identify(sess, quic_plugin_env))
	{
		stellar_session_plugin_dettach_current_session(sess);
		return NULL;
	}
	size_t payload_len = 0;
	const char * payload = session_get0_current_payload(sess, &payload_len);
	if(NULL == payload || payload_len <= 0)
	{
		stellar_session_plugin_dettach_current_session(sess);
		return NULL;
	}	
	int payload_offset = 0;
	enum QUIC_VERSION_T quic_ver = is_quic_protocol(payload, payload_len, &payload_offset);
	if(QUIC_VERSION_UNKNOWN == quic_ver || (size_t)payload_offset > payload_len)
	{
		stellar_session_plugin_dettach_current_session(sess);
		return NULL;
	}
	struct quic_context *qcontext = (struct quic_context *)CALLOC(1, sizeof(struct quic_context));
	qcontext->quic_info.quic_version = (unsigned int )quic_ver;
	return (void *)qcontext;
}

void quic_session_ctx_free_cb(struct session *sess, void *session_ctx, void *plugin_env)
{
	if(session_ctx){
		struct quic_context *qcontext = (struct quic_context *)session_ctx;
		free_quicinfo(&qcontext->quic_info);
		if(qcontext->quic_buf.buffer){
			free(qcontext->quic_buf.buffer);
		}
		FREE(session_ctx);
	}
	return;
}

void quic_session_exdata_free_cb(struct session *sess, int idx, void *ex_ptr, void *arg)
{
	return;
}

void quic_msg_free_cb(struct session *sess, void *msg, void *msg_free_arg)
{
	FREE(msg);
}

extern "C" void *QUIC_ONLOAD(struct stellar *st)
{
	char buff[2048]={0};

	struct quic_param *quic_plugin_env = (struct quic_param *)CALLOC(1, sizeof(struct quic_param));
	quic_plugin_env->st = st;

	MESA_load_profile_int_def(g_quic_proto_conffile, "QUIC", "LOG_LEVEL", &quic_plugin_env->level, RLOG_LV_FATAL);
	MESA_load_profile_string_def(g_quic_proto_conffile, "QUIC", "LOG_PATH", quic_plugin_env->log_path, sizeof(quic_plugin_env->log_path), g_quic_log_path);
	
	MESA_load_profile_int_def(g_quic_proto_conffile, "QUIC", "DECRYPTED_SWITCH", &quic_plugin_env->decrypted_switch, 2);
	// MESA_load_profile_int_def(g_quic_proto_conffile, "QUIC", "MAX_PARSE_PKT_NUM", &quic_plugin_env->max_parse_pkt_num, 3);
	MESA_load_profile_int_def(g_quic_proto_conffile, "QUIC", "MAX_CHLO_SIZE", &quic_plugin_env->max_chlo_size, 4096);

	MESA_load_profile_string_def(g_quic_proto_conffile, "QUIC", "QUIC_PORT_LIST", buff, sizeof(buff), "443;8443;");
	quic_plugin_env->quic_port_num=parse_quic_port(buff, quic_plugin_env->quic_port_list, SUPPORT_QUIC_PORT_NUM);

	quic_plugin_env->logger=MESA_create_runtime_log_handle(quic_plugin_env->log_path, quic_plugin_env->level);
	if(quic_plugin_env->logger==NULL)
	{
		fprintf(stderr, "MESA_create_runtime_log_handle failed, level: %d log_path: %s", quic_plugin_env->level, quic_plugin_env->log_path);
		return NULL;
	}

	quic_plugin_env->quic_plugid = stellar_session_plugin_register(st, quic_session_ctx_new_cb, quic_session_ctx_free_cb, quic_plugin_env);
	assert(quic_plugin_env->quic_plugid >= 0);

	quic_plugin_env->exdata_id=stellar_session_exdata_new_index(st, "QUIC_EXDATA", quic_session_exdata_free_cb, quic_plugin_env);
	assert(quic_plugin_env->exdata_id >= 0);
	quic_plugin_env->udp_topic_id=stellar_session_mq_get_topic_id(st, TOPIC_UDP);
	assert(quic_plugin_env->udp_topic_id >= 0);
	stellar_session_mq_subscribe(st, quic_plugin_env->udp_topic_id, quic_on_session_msg_cb, quic_plugin_env->quic_plugid);

	quic_plugin_env->quic_topic_id=stellar_session_mq_create_topic(st, QUIC_DECODER_TOPIC, quic_msg_free_cb, quic_plugin_env);
	assert(quic_plugin_env->quic_topic_id >= 0);
	return (void *)quic_plugin_env;
}

extern "C" void QUIC_UNLOAD(void *plugin_env)
{
	struct quic_param *quic_plugin_env = (struct quic_param *)plugin_env;
	MESA_destroy_runtime_log_handle(quic_plugin_env->logger);
	FREE(plugin_env);
	return;
}