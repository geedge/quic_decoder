/*
 *  author:yangwei
 *  create time:2021-8-21
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "quic_decoder.h"
#include <stellar/stellar.h>
#include <stellar/session.h>
#include <stellar/session_mq.h>
#include <stellar/session_exdata.h>

extern "C" int commit_test_result_json(cJSON *node, const char *name);
extern int quic_version_int2string(unsigned int version, char *buff, int buff_len);

static int g_result_count = 1;

#if 0
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)  
#endif

struct quic_gtest_context
{
    cJSON *json_root;
    int version_get;
    int tuple4_get;
};

static void cJSON_Add_QStringToObject(cJSON * object, const char *name, const char* qstring, size_t len)
{
    char *tmp = (char *)calloc(1, len + 1);
    memcpy(tmp, qstring, len);
    cJSON_AddStringToObject(object, name, tmp);
}

extern "C" void QUIC_TEST_PLUG_ENTRY(struct session *sess, int topic_id, const void *msg, void *per_session_ctx, void *plugin_env)
{
    struct quic_gtest_context *qctx = (struct quic_gtest_context *)per_session_ctx;
    struct quic_message *qmsg = (struct quic_message *)msg;
    enum quic_message_type mtype = quic_message_type_get(qmsg);
    char *result = NULL;
    size_t res_len = 0;
    enum session_state sstate = session_get_current_state(sess);

    DEBUG_PRINT("### QUIC_TEST_PLUG_ENTRY: msg type=%d\n", (int)mtype);

    if(QUIC_CLIENT_HELLO == mtype){
        if(qctx->tuple4_get == 0){
            cJSON_AddStringToObject(qctx->json_root, "Tuple4", session_get0_readable_addr(sess));
            qctx->tuple4_get = 1;
        }

        if(qctx->version_get == 0){
            const char *version_str = quic_message_readable_version_get0(qmsg);
            if(version_str){
                cJSON_AddStringToObject(qctx->json_root, "VERSION", version_str);
                qctx->version_get = 1;
            }
        }

        quic_message_sni_get0(qmsg, &result, &res_len);
        if(result){
            cJSON_Add_QStringToObject(qctx->json_root, "SNI", result, res_len);
        }
        
        quic_message_user_agent_get0(qmsg, &result, &res_len);
        if(result){
            cJSON_Add_QStringToObject(qctx->json_root, "UA", result, res_len);
        }
    }

    if(sstate == SESSION_STATE_CLOSING){
        //some sapp version not support SESSION_STATE_CLOSING, do this in free_cb()
    }

    return ;
}

extern "C" void *quic_gtest_plug_session_ctx_new_cb(struct session *sess, void *plugin_env)
{
    struct quic_gtest_context *ctx = (struct quic_gtest_context *)calloc(1, sizeof(struct quic_gtest_context));
    ctx->json_root = cJSON_CreateObject();
    return ctx;
}

extern "C" void quic_gtest_session_ctx_free_cb(struct session *sess, void *session_ctx, void *plugin_env)
{
    struct quic_gtest_context *qctx = (struct quic_gtest_context *)session_ctx;
    if(qctx->tuple4_get || qctx->version_get){
        char result_name[16]="";
        sprintf(result_name,"QUIC_RESULT_%d", g_result_count);
        commit_test_result_json(qctx->json_root, result_name);
        g_result_count+=1;   
    }
    free(session_ctx);
}

extern "C" void *QUIC_TEST_PLUG_INIT(struct stellar *st)
{
    void *fake_quic_gtest_plugin_env = (void *)"_fake_plugin_env_";
    int quic_gtest_plug_id = stellar_session_plugin_register(st, quic_gtest_plug_session_ctx_new_cb, quic_gtest_session_ctx_free_cb, fake_quic_gtest_plugin_env);
    int quic_topic_id = stellar_session_mq_get_topic_id(st, QUIC_DECODER_TOPIC);
    assert(quic_topic_id >= 0);
    stellar_session_mq_subscribe(st, quic_topic_id, QUIC_TEST_PLUG_ENTRY, quic_gtest_plug_id);

    return fake_quic_gtest_plugin_env;
}

extern "C" void QUIC_TEST_PLUG_DESTROY(void *plugin_env)
{
    return ;
}

#ifdef __cplusplus
}
#endif



