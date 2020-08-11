/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ngx_snmp.h
 * Author: wangyuying
 *
 * Created on 2018年5月19日, 上午10:52
 */

#ifndef NGX_SNMP_H
#define NGX_SNMP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>
#include <ngx_http.h>

#ifndef INT32_MAX
#   define INT32_MAX 2147483647
#endif

#ifndef INT32_MIN
#   define INT32_MIN (0 - INT32_MAX - 1)
#endif

#ifndef UINT32_MAX
#define UINT32_MAX      (4294967295U)
#endif
    

#define NGX_SNMP_MODULE                0x504D4E53          /*  "SNMP" */    
#define NGX_SNMP_MAIN_CONF             0x02000000
#define NGX_SNMP_GROUP_CONF            0x04000000
#define NGX_SNMP_ITEM_CONF             0x08000000
#define NGX_SNMP_OBJECT_CONF           0x10000000
#define NGX_SNMP_KEYWORD_TYPE_FUN      0
#define NGX_SNMP_KEYWORD_TYPE_KEYWORD  1
#define NGX_SNMP_KEYWORD_TYPE_OBJ      2 
#define NGX_SNMP_VALUE_STATS_OK        0
#define NGX_SNMP_VALUE_STATS_ERROR     1
    
#define NGX_SNMP_MAIN_CONF_OFFSET  offsetof(ngx_snmp_conf_ctx_t, main_conf)
#define NGX_SNMP_GROUP_CONF_OFFSET  offsetof(ngx_snmp_conf_ctx_t, group_conf)
#define NGX_SNMP_ITEM_CONF_OFFSET  offsetof(ngx_snmp_conf_ctx_t, item_conf)
#define NGX_SNMP_OBJECT_CONF_OFFSET  offsetof(ngx_snmp_conf_ctx_t, object_conf)

extern ngx_module_t  ngx_snmp_module;
    
#define ngx_snmp_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_snmp_module.index] ?                                 \
        ((ngx_snmp_conf_ctx_t *) cycle->conf_ctx[ngx_snmp_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)

#define ngx_snmp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_snmp_get_module_group_conf(s, module)  (s)->group_conf[module.ctx_index]
#define ngx_snmp_get_module_item_conf(s, module)  (s)->item_conf[module.ctx_index]
#define ngx_snmp_get_module_object_conf(s, module)  (s)->object_conf[module.ctx_index]

#define ngx_snmp_conf_get_module_main_conf(cf, module)                        \
    ((ngx_snmp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_snmp_conf_get_module_group_conf(cf, module)                         \
    ((ngx_snmp_conf_ctx_t *) cf->ctx)->group_conf[module.ctx_index]
#define ngx_snmp_conf_get_module_item_conf(cf, module)                         \
    ((ngx_snmp_conf_ctx_t *) cf->ctx)->item_conf[module.ctx_index]    
#define ngx_snmp_conf_get_module_object_conf(cf, module)                         \
    ((ngx_snmp_conf_ctx_t *) cf->ctx)->object_conf[module.ctx_index]    

    
/**SNMP constant variables */
#define SNMP_DIRECTION_MORE 0
#define SNMP_DIRECTION_LESS 1
#define SNMP_OBJECT_VALUETYPE_INT  0
#define SNMP_OBJECT_VALUETYPE_FLOAT 1
#define SNNP_BUFFER_LENGTH  512
#define SNMP_POOL_SIZE 4096
#define DATA_TYPE_ZERO  0x00
#define DATA_TYPE_ONE  0x01
#define DATA_TYPE_BOOL  0x01
#define DATA_TYPE_INT   0x02
#define DATA_TYPE_BITSTR  0x03
#define DATA_TYPE_OCTSTR  0x04
#define DATA_TYPE_NULL  0x05
#define DATA_TYPE_OBJID  0x06
#define DATA_TYPE_SEQUENCE  0x10
#define DATA_TYPE_ENUM  0x0A
#define DATA_TYPE_SEQ  0x30
#define DATA_TYPE_IPADDRESS 0x40
#define DATA_TYPE_COUNTER 0x41
#define DATA_TYPE_UNSIGNED 0x42
#define DATA_TYPE_TIMETICKS 0x43
#define DATA_TYPE_COUNTER64 0x46
#define DATA_TYPE_NOSUCHOBJECT  0x80
#define DATA_TYPE_NOSUCHINSTANCE  0x81
#define DATA_TYPE_ENDOFMIBVIEW 0x82
#define SNMP_GET_REQUEST 0xA0
#define SNMP_GET_NEXT_REQUEST 0xA1
#define SNMP_GET_RESPONSE 0xA2
#define SNMP_SET_REQUEST 0xA3
#define SNMP_TRAP 0xA4
#define SNMP_VERSION_NUM 4
#define SNMP_STRING_END '\0'
#define SNMP_TIMER_INTERVAL 1
    

/**Default Value */
#define DEFAULT_INTERVAL 30
#define SERVER_STATUS_CHECK_INTERVAL  60
#define DEFAULTFALL 3
#define DEFAULTPORT 161    
#define DEFAULTDIRCTION  SNMP_DIRECTION_MORE         
#define DEFAULTMOST  80

#if (NGX_PTR_SIZE == 4)
#define CHECK_OVERFLOW_S(x,y) do {                                           \
            if (x > INT32_MAX) {                                            \
                x &= 0xffffffff;                                            \
            } else if (x < INT32_MIN) {                                     \
                x = 0 - (x & 0xffffffff);                                   \
            }                                                               \
    } while(0)

#  define CHECK_OVERFLOW_U(x,y) do {                                    \
            if (x > UINT32_MAX) {                                           \
                x &= 0xffffffff;                                            \
            }                                                               \
    } while(0)
    
#else
#define CHECK_OVERFLOW_S(x,y)
#define CHECK_OVERFLOW_U(x,y)
#endif


extern ngx_module_t                         ngx_snmp_core_module;
    
ngx_uint_t  ngx_snmp_max_module;    

ngx_int_t 
ngx_snmp_build_integer(ngx_int_t value, u_char *buf);
ngx_int_t
ngx_snmp_move_oct(ngx_str_t *str,ngx_int_t num);
ngx_int_t ngx_snmp_fun_last(void *data);
ngx_int_t
ngx_snmp_fun_change(void *data);
ngx_int_t
ngx_snmp_fun_rate(void *data);
ngx_int_t
ngx_snmp_get_keyword_value(void *data);

typedef enum {
    SNMP_VERSION_1 = 0,
    SNMP_VERSION_2C,
    SNMP_VERSION_2U,
    SNMP_VERSION_3     
}ngx_snmp_versions;

typedef struct{
    ngx_int_t                   version_no;
    ngx_str_t                   version_str; 
} ngx_snmp_version_t;

typedef struct ngx_snmp_core_object_session_s ngx_snmp_core_object_session_t;
typedef struct ngx_snmp_server_data_queue_s   ngx_snmp_server_data_queue_t;
typedef ngx_int_t (*ngx_snmp_handler_pt)(ngx_snmp_core_object_session_t *s);

typedef enum {
    NGX_SNMP_BUILD_REQUESTID_PHASE = 0,
    NGX_SNMP_BUILD_HEAD_PHASE,
    NGX_SNMP_BUILD_REQUESTPDU_PHASE,
    NGX_SNMP_BUILD_FINISHPDU_PHASE,
   
    NGX_SNMP_PRESEND_PDU_PHASE,
    NGX_SNMP_SENT_PDU_PHASE,
            
    NGX_SNMP_PRERECEIVE_PDU_PHASE,
    NGX_SNMP_RECEIVEED_PDU_PHASE,
            
    NGX_SNMP_PREPARSE_PDU_PHASE,
    NGX_SNMP_PARSE_PDU_PHASE,
    NGX_SNMP_PARSED_PDU_PHASE,
            
    NGX_SNMP_PRECONTROL_PHASE,
    NGX_SNMP_BUILD_RESPONSE_PHASE,
    NGX_SNMP_CONTROL_PHASE,
    
    NGX_SNMP_LOG_PHASE
} ngx_snmp_phases;

typedef  float                         ngx_snmp_float_t;

typedef struct {
    void                               **main_conf;
    void                                **group_conf;
    void                                **item_conf;
    void                                **object_conf;
    
} ngx_snmp_conf_ctx_t;

typedef struct {
    ngx_int_t             (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_group_conf)(ngx_conf_t *cf);
    char                 *(*merge_group_conf)(ngx_conf_t *cf, void *prev,
                                    void *conf);

    void                 *(*create_item_conf)(ngx_conf_t *cf);
    char                 *(*merge_item_conf)(ngx_conf_t *cf, void *pre,
                                    void *conf);
    void                 *(*create_object_conf)(ngx_conf_t *cf);
    char                 *(*merge_object_conf)(ngx_conf_t *cf, void *pre,
                                    void *conf);
} ngx_snmp_module_t;

typedef struct {
    ngx_array_t                handlers;                                        //ngx_snmp_phase_handler_t
} ngx_snmp_phase_t;

typedef struct {
    ngx_int_t                           is_start;                               //0 SNMP function not start 1 have start
    ngx_int_t                           running_process_num;
    ngx_pid_t                           pid;
}ngx_snmp_timer_start_status_t;

typedef struct {
    ngx_array_t                         groups;    /* ngx_snmp_core_group_t */
    ngx_int_t                           log_level;
    ngx_array_t                         upstream_group;    /* ngx_snmp_core_upstream_group_t */
    ngx_snmp_phase_t                    phases[NGX_SNMP_LOG_PHASE + 1];
    ngx_rbtree_t                        snmp_rbtree; 
    ngx_rbtree_node_t                   ngx_snmp_event_timer_sentinel;
    ngx_snmp_timer_start_status_t       *start_status;
    ngx_shm_zone_t                      *shm_zone; 
    ngx_queue_t                         server_data_queue;     
} ngx_snmp_core_main_conf_t;

typedef struct {
    ngx_snmp_handler_pt                 requid_handler; 
    ngx_snmp_handler_pt                 head_handler; 
    ngx_snmp_handler_pt                 request_hanlder; 
    ngx_snmp_handler_pt                 finish_pdu_hander; 
    ngx_snmp_handler_pt                 parse_pdu_handler;
}ngx_snmp_pdu_handler_t;


typedef struct {
    ngx_str_t                            name;
    ngx_int_t                            interval;
    ngx_int_t                            recover_check_interval;
    ngx_int_t                            fall;                                     //一台服务器连接发生几次错误，标记这台服务器为down状态
    ngx_int_t                            version; 
    ngx_int_t                            port;
    ngx_array_t                          items;                                   //ngx_snmp_item_t  
    ngx_snmp_pdu_handler_t               pdu_handler;
    ngx_snmp_conf_ctx_t                  *ctx;
} ngx_snmp_core_group_t;

typedef struct {
    ngx_str_t                           upstream_name;                          //one upstream can only related to one ngx_snmp_core_group_t
    ngx_str_t                           group_name;                             //But one ngx_snmp_core_group_t can  related to more upstream
    void                                *uscf;                                  // ngx_http_upstream_srv_conf_t
    ngx_snmp_core_group_t               *group;                                 //ngx_snmp_core_group_t
    ngx_array_t                         *server_data;                           //ngx_snmp_core_server_data_t
} ngx_snmp_core_upstream_group_t;

typedef struct {
   ngx_str_t                          name;             // If only one object in a item then name is object name OR object name was specified by express
   ngx_snmp_float_t                   most; 
   ngx_int_t                          direction;        // MORE or LESS MACRO
   ngx_int_t                          weight; 
   ngx_str_t                          express; 
   ngx_array_t                        objects;         //ngx_snmp_object_t
   ngx_snmp_core_group_t              *group; 
   ngx_snmp_pdu_handler_t             *pdu_handler;
   ngx_snmp_conf_ctx_t                *ctx;
} ngx_snmp_core_item_t;


typedef struct {
    ngx_str_t                               name;
    ngx_snmp_core_group_t                   *group; 
    ngx_snmp_core_item_t                    *item;
    ngx_snmp_core_upstream_group_t          *uscf;
    ngx_str_t                               oid; 
    ngx_int_t                               type; 
    ngx_pool_t                              *pool; 
    ngx_str_t                               *pdu_reqid;
    ngx_str_t                               *pdu_head;
    ngx_str_t                               *pdu_obj;
    ngx_snmp_pdu_handler_t                  *pdu_handler;
    ngx_snmp_conf_ctx_t                     *ctx;
}ngx_snmp_core_object_t;

typedef struct {
    void                                *uscf;                                  //ngx_http_upstream_srv_conf_t
    void                                *server;                                //ngx_http_upstream_server_t
    ngx_str_t                            name;
    ngx_addr_t                          *addrs;                                
    ngx_uint_t                          naddrs;
    ngx_addr_t                          *snmp_addrs;
    int                                 family;                                 
    ngx_int_t                           last_down_time;
    ngx_snmp_pdu_handler_t              *pdu_handler;
    ngx_snmp_core_group_t               *group;
    ngx_array_t                         *item_value;                            //ngx_snmp_item_value_t
    ngx_int_t                           flag;                                   //用于判断是否所有对象都完成本次数据的发送与接收，以便决定是否设置下一次定时任务0 未全部完成接收，1已经全部完成
    ngx_int_t                           last_error_request_id;                  //The last request id of error request  on this server 
    ngx_int_t                           error_count;                            //连续发生错误的次数，成功时清零
    unsigned                            down:1;                                 //0 up 1 down
    ngx_pool_t                          *pool;
    ngx_log_t                           *log;
    ngx_cycle_t                         *cycle;
}ngx_snmp_core_server_data_t;

typedef struct {
    ngx_snmp_core_item_t                 *item;
    ngx_snmp_core_group_t                *group;
    ngx_http_upstream_server_t           *server;
    ngx_http_upstream_srv_conf_t         *uscf;
    ngx_snmp_core_server_data_t          *server_data;
    ngx_int_t                            sent_sn;                               //if sent_sn == received_sn meanings data has calculated
    ngx_int_t                            received_sn;                           //if received_sns of all object sessions are equal to received_sn meanings get the response of all objects 
    ngx_int_t                            error_sn;
    ngx_snmp_float_t                     last_value; 
    ngx_int_t                            last_updatetime;
    ngx_int_t                            last_stats;                             //0 ok 1 error
    ngx_snmp_float_t                     value;                                  //Float should be convert into INT, before fill it 
    ngx_int_t                            updatetime;                             
    ngx_int_t                            stats;
    ngx_int_t                            error_count;                           //连续发生错误的次数，成功时清零
    ngx_array_t                          *object_session;                        //ngx_snmp_core_object_session_t
    ngx_snmp_pdu_handler_t               *pdu_handler;
}ngx_snmp_item_value_t;

struct ngx_snmp_core_object_session_s{
    ngx_snmp_core_object_t              *core_object; 
    ngx_snmp_core_server_data_t         *server_data; 
    ngx_snmp_item_value_t               *item_value;
    ngx_str_t                           tmp_buf;
    ngx_int_t                           data_type;
    ngx_int_t                           value_type;
    ngx_str_t                           send_buf; 
    ngx_str_t                           recv_buf;
    ngx_int_t                           last_value;                             //Float should be convert into INT, before fill it 
    ngx_int_t                           last_updatetime;                        //second
    ngx_int_t                           last_stats;                             //0 ok 1 error
    ngx_int_t                           sent_sn;                        
    ngx_int_t                           received_sn;                             //if sent_sn == received_sn meangins has received response from server
    ngx_int_t                           value;                                  //Float should be convert into INT, before fill it 
    ngx_int_t                           updatetime;   
    ngx_int_t                           stats;
    ngx_int_t                           error_count;                            //连续发生错误的次数，成功时清零
    ngx_pool_t                          *pool;                                  
    ngx_connection_t                    *connection;
    ngx_peer_connection_t               *pc;
    void                                **main_conf;
    void                                **group_conf;
    void                                **item_conf;
    void                                **object_conf;                          
    ngx_snmp_pdu_handler_t              *pdu_handler;
};

typedef struct{
    ngx_snmp_handler_pt        handler;
    ngx_int_t                  flag;                                            //0:pdu handler  1 other
}ngx_snmp_phase_handler_t;

typedef ngx_int_t (*ngx_snmp_fun_pt)(void *data);

typedef struct {
    ngx_str_t                                 key_world;
    ngx_int_t                                 keyword_type;
    ngx_snmp_fun_pt                           ngx_snmp_fun_pt;  
}ngx_snmp_core_express_fun_handler_t;

struct ngx_snmp_server_data_queue_s {
    ngx_snmp_core_server_data_t                 *server_data;
    ngx_queue_t                                 queue;
};

char *
ngx_snmp_core_getKeepworld(ngx_str_t value, ngx_snmp_core_express_fun_handler_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* NGX_SNMP_H */

