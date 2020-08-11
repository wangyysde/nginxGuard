/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ngx_snmp_module.h
 * Author: wangyuying
 *
 * Created on 2018年5月16日, 下午9:48
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#ifndef NGX_SNMP_MODULE_H
#define NGX_SNMP_MODULE_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>
#include <ngx_http.h>
#endif

/** Module parameters  */ 
#define NGX_SNMP_MODULE                0x504D4E53          /*  "SNMP" */
#define NGX_SNMP_MAIN_CONF             0x02000000
#define NGX_SNMP_GROUP_CONF            0x04000000
#define NGX_SNMP_ITEM_CONF             0x08000000
#define NGX_SNMP_OBJECT_CONF           0x10000000



/**SNMP constant variables */
#define SNMP_VERSION_1 0x00
#define SNMP_VERSION_2C 0x01
#define SNMP_VERSION_2 0x02
#define SNMP_VERSION_3 0x03


/**Default Value */
#define DEFAULT_INTERVAL   30
#define DEFAULTFALL 3
#define DEFAULTPORT 161
#define DEFAULTCOMMUNITY  ngx_string("public");



typedef struct {
   ngx_str_t                          name;             // If only one object in a item then name is object name OR object name was specified by express
   ngx_int_t                          most; 
   ngx_int_t                          direction;        // MORE or LESS MACRO
   ngx_int_t                          weight; 
   ngx_str_t                          express; 
   ngx_array_t                        *objects;         //ngx_snmp_object_t
   ngx_snmp_parameter_t               *parameter;  
}ngx_snmp_item_t;

typedef struct {
    ngx_str_t                          name;
    ngx_snmp_parameter_t               *parameter; 
    ngx_snmp_item_t                    *item;
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_str_t                          oid; 
    ngx_int_t                          type; 
    ngx_str_t                          *pdu_reqid;
    ngx_str_t                          *pdu_head;
    ngx_str_t                          *pdu_obj;
}ngx_snmp_object_t;

typedef struct {
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_http_upstream_server_t          *server;
    ngx_snmp_parameter_t                *parameter;
    ngx_snmp_item_t                     *item;
    ngx_int_t                           last_requestid;
    ngx_int_t                           current_requestid;                      //If all boject_value.receive_id == this.current_requestid ,then caculate this value         
    ngx_array_t                         *object_value;                          //ngx_snmp_object_value_t
    ngx_int_t                           last_update_time;
    ngx_int_t                           last_value; 
    ngx_int_t                           update_time;
    ngx_int_t                           value; 
}ngx_snmp_item_value_t;

typedef struct {
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_snmp_parameter_t                *parameter;
    ngx_snmp_item_t                     *item;
    ngx_snmp_object_t                   *object;
    ngx_http_upstream_server_t          *server;
    ngx_str_t                           server_ip;
    ngx_pool_t                          *pool;
    ngx_snmp_item_value_t               *item_value;
    ngx_int_t                           last_update_time;
    ngx_int_t                           last_value; 
    ngx_int_t                           update_time;
    ngx_int_t                           value; 
    ngx_int_t                           request_id; 
    ngx_int_t                           receive_id;
     ngx_str_t                          *pdu;
    ngx_str_t                           *receive_buf; 
    ngx_connection_t                    *c;
    ngx_peer_connection_t               *pc;
    ngx_addr_t                          *peer;
    ngx_log_t                           *log;
}ngx_snmp_object_value_t;



typedef struct {
    ngx_array_t                         groups;    /* ngx_snmp_core_group_t */
    ngx_int_t                           log_level;
    ngx_array_t                         upstream_group;    /* ngx_snmp_core_upstream_group_t */
} ngx_snmp_core_main_conf_t;    

typedef struct {
    ngx_str_t                         name;
    ngx_int_t                         interval;
    ngx_int_t                         fall;                                     //一台服务器连接发生几次错误，标记这台服务器为down状态
    ngx_int_t                         version; 
    ngx_int_t                         port;

//下面这些内容计划放在不同的版本中实现
//    ngx_str_t                         community;
//    ngx_str_t                         context_name;
//    ngx_str_t                         security_name;
//    ngx_str_t                         security_level;
//    ngx_str_t                         auth_protocol;
//    ngx_str_t                         auth_phrase;
//    ngx_str_t                         privacy_protocol;
//    ngx_str_t                         privacy_phrase;
    ngx_array_t                         *items;                                   //ngx_snmp_item_t
    ngx_snmp_conf_ctx_t                 *ctx;
}ngx_snmp_core_group_t;


typedef struct {
    ngx_str_t                           upstream_name;                          //one upstream can only related to one parameter
    ngx_str_t                           parameter_name;                         //But one parameter can  related to more upstream
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_snmp_core_group_t                *group;
    ngx_array_t                         *server_data;                           //ngx_snmp_core_server_data_t
}ngx_snmp_core_upstream_group_t;

typedef struct {
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_http_upstream_server_t          *server; 
    ngx_snmp_core_group_t                *group;
    ngx_array_t                         *item_value;                            //ngx_snmp_item_value_t
    ngx_int_t                           request_id;                             //成功接收到数据的最新的request_id ,用于判断同一台服务器上的所有item都已经接收到最新的数据
    ngx_int_t                           last_error_request_id;                  //The last request id of error request  on this server 
    ngx_int_t                           error_count;                            //连续发生错误的次数，成功时清零
    unsigned                            down:1;
    ngx_pool_t                          *pool;
    ngx_log_t                           *log;
}ngx_snmp_core_server_data_t;



typedef struct {
    ngx_int_t                           log_level; 
    ngx_array_t                         *parameters;                             //ngx_snmp_parameter_t   
    ngx_array_t                         *upstream_parameter;                    //ngx_snmp_upstream_parameter_t
}ngx_snmp_main_t;

typedef struct {
    void        **main_conf;
    void        **group_conf;
    void        **item_conf;
    void        **object_conf;
} ngx_snmp_conf_ctx_t;

typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

    void       *(*create_main_conf)(ngx_conf_t *cf);
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void       *(*create_group_conf)(ngx_conf_t *cf);
    char       *(*merge_group_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void       *(*create_item_conf)(ngx_conf_t *cf);
    char       *(*merge_item_conf)(ngx_conf_t *cf, void *prev, void *conf);
    
    void       *(*create_object_conf)(ngx_conf_t *cf);
    char       *(*merge_object_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_snmp_module_t;

static char *
ngx_snmp_snmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);



/*

#define SNMP_SOCKET_TCP 0x00
#define SNMP_SOCKET_UDP 0x01
#define SNMP_SECURITY_LEVEL_NOAUTHNOPRIV    0x00     //For noAuthNoPriv
#define SNMP_SECURITY_LEVEL_AUTHNOPRIV      0x01     //For AuthNoPriv
#define SNMP_SECURITY_LEVEL_AUTHPRIV        0x02     // For AuthPriv
#define SNMP_AUTH_PROTOCOL_MD5              0x00     //MD5
#define SNMP_AUTH_PROTOCOL_SHA              0x01
#define SNMP_AUTH_PRIVACY_DES               0x00
#define SNMP_AUTH_PRIVACY_AES               0x01
#define SNMP_LOAD_OID                       "1.3.6.1.4.1.2021.10.1.3.1"
#define SNMP_SWAP_SIZE_OID                  "1.3.6.1.4.1.2021.4.3.0"
#define SNMP_SWAP_AVAILABLE_OID             "1.3.6.1.4.1.2021.4.4.0"
#define SNMP_MEM_SIZE_OID                   "1.3.6.1.4.1.2021.4.5.0"
#define SNMP_MEM_FREE_OID                   "1.3.6.1.4.1.2021.4.6.0"
#define SNMP_MEM_BUFFER_OID                 "1.3.6.1.4.1.2021.4.14.0"
#define SNMP_MEM_CACHED_OID                 "1.3.6.1.4.1.2021.4.15.0"

#define NGX_SNMP_MODULE                0x504D4E53          /*  "SNMP" */
/*
#define NGX_SNMP_MAIN_CONF             0x02000000

#define ngx_snmp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]

#define ngx_snmp_get_module_main_conf(s, module)                             \
    (s)[module.ctx_index]
#define ngx_snmp_conf_get_module_main_conf(cf, module)                       \
    &((ngx_snmp_main_conf_t *)cf->ctx)[module.ctx_index]


static void *
ngx_snmp_create_conf(ngx_cycle_t *cycle);
static char *
ngx_snmp_init_conf(ngx_cycle_t *cycle,void *conf);
static char *
ngx_snmp_groups(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);  
static char *
ngx_snmp_parameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);



#endif /* NGX_SNMP_MODULE_H */

