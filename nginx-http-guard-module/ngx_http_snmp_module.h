/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ngx_http_snmp_module.h
 * Author: wangyuying
 *
 * Created on 2018年4月3日, 下午4:44
 */

#ifndef NGX_HTTP_SNMP_MODULE_H
#define NGX_HTTP_SNMP_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>
#include <ngx_http.h>

#define SNMP_OBJ_NUM    7       
#define SNMP_MAX_PDU_LENGTH  512
#define SNMP_REQUEST_ID_LEN  4
#define SNMP_DATA_TYPE_SEQ  0x30
#define SNMP_DATA_TYPE_INT   0x02
#define SNMP_DATA_TYPE_OCTSTR  0x04
#define SNMP_DATA_TYPE_OBJID  0x06
#define SNMP_GET_REQUEST 0xA0

#define DATA_ZERO  0x00
#define SNMP_VERSION_1 0x00
#define SNMP_VERSION_2C 0x01
#define SNMP_VERSION_2 0x02
#define SNMP_VERSION_3 0x03
#define SNMP_SOCKET_TCP 0x00
#define SNMP_SOCKET_UDP 0x01
#define SNMP_SECURITY_LEVEL_NOAUTHNOPRIV    0x00     //For noAuthNoPriv
#define SNMP_SECURITY_LEVEL_AUTHNOPRIV      0x01     //For AuthNoPriv
#define SNMP_SECURITY_LEVEL_AUTHPRIV        0x02     // For AuthPriv
#define SNMP_AUTH_PROTOCOL_MD5              0x00     //MD5
#define SNMP_AUTH_PROTOCOL_SHA              0x01
#define SNMP_AUTH_PRIVACY_DES               0x00
#define SNMP_AUTH_PRIVACY_AES               0x01
#define SNMP_DEFAULT_INTERVAL               30
#define SNMP_DEFAULT_PORT                   161
#define SNMP_DEFAULT_COMMUNITY              "public"
#define SNMP_DEFAULT_CONTEXTNAME            "context_name"
#define SNMP_DEFAULT_AUTHPHRASE             "auth_phrase"
#define SNMP_DEFAULT_PRIVACYPHRASE          "privacy_phrase"
/*
#define SNMP_LOAD_OID                       "1.3.6.1.4.1.2021.10.1.3.1"
#define SNMP_SWAP_SIZE_OID                  "1.3.6.1.4.1.2021.4.3.0"
#define SNMP_SWAP_AVAILABLE_OID             "1.3.6.1.4.1.2021.4.4.0"
#define SNMP_MEM_SIZE_OID                   "1.3.6.1.4.1.2021.4.5.0"
#define SNMP_MEM_FREE_OID                   "1.3.6.1.4.1.2021.4.6.0"
#define SNMP_MEM_BUFFER_OID                 "1.3.6.1.4.1.2021.4.14.0"
#define SNMP_MEM_CACHED_OID                 "1.3.6.1.4.1.2021.4.15.0"
#define CPU_LOAD_MAX                        8
#define CPU_LOAD_WEIGHT                     80        //80%
#define SWAPRATIO_MAX                       80
#define SWAPRATIO_WEIGHT                    5         //5%
#define FREEMEM_MIN                         10485760   //1M
#define FREEMEM_WEIGHT                      15       //15%
*/
#define NGX_SNMP_MAIN_CONF             0x04000000

 
 typedef struct{
    ngx_int_t                  id; 
    ngx_str_t                  obj_name; 
    ngx_str_t                  default_oid;
    ngx_str_t                  conf_oid;  
 }ngx_snmp_oid_t;   
 
 ngx_snmp_oid_t snmp_oids[] = {
     {0,ngx_string("load"),ngx_string("1.3.6.1.4.1.2021.10.1.3.1"),ngx_string("")},
     {1,ngx_string("swap_size"),ngx_string("1.3.6.1.4.1.2021.4.3.0"),ngx_string("")},
     {2,ngx_string("swap_free"),ngx_string("1.3.6.1.4.1.2021.4.4.0"),ngx_string("")},
     {3,ngx_string("mem_size"),ngx_string("1.3.6.1.4.1.2021.4.5.0"),ngx_string("")},
     {4,ngx_string("mem_free"),ngx_string("1.3.6.1.4.1.2021.4.6.0"),ngx_string("")},
     {5,ngx_string("buffer"),ngx_string("1.3.6.1.4.1.2021.4.14.0"),ngx_string("")},
     {6,ngx_string("cached"),ngx_string("1.3.6.1.4.1.2021.4.15.0"),ngx_string("")}
 };
 
 typedef struct{
     ngx_int_t                      id;
     ngx_str_t                      obj_name; 
     ngx_int_t                      default_max; 
     ngx_int_t                      default_weight;
     ngx_int_t                      conf_max; 
     ngx_int_t                      conf_weight; 
 }ngx_snmp_perf_t;
 
 ngx_snmp_perf_t  snmp_perfs[] = {
     {0,ngx_string("perf_load"),8,80,8,80},
     {1,ngx_string("perf_swapratio"),80,5,80,5},
     {2,ngx_string("pref_memfree"),10485760,15,10485760,15}
 };
 
 typedef struct{
     ngx_str_t                  perf_group;                      //group name;
     ngx_array_t                *snmp_perfs;                     //ngx_snmp_perf_t             
 }ngx_snmp_perf_group_t;
 
 typedef struct {
     ngx_str_t                      obj_name;
     ngx_str_t                      perf_name; 
 }obj_perf_t;
 
 obj_perf_t obj_perf_relation[] = {
    {ngx_string("load"),ngx_string("perf_load")},
    {ngx_string("swap_size"),ngx_string("perf_swapratio")},
    {ngx_string("mem_free"),ngx_string("pref_memfree")}
 };
 
 typedef struct {
    ngx_str_t       name;
    ngx_uint_t      snmp_interval;                      //interval of gathering data
    ngx_uint_t      snmp_ver;
    ngx_uint_t      snmp_port;
    ngx_uint_t      snmp_socket_type;
    ngx_str_t       snmp_community; 
    ngx_str_t       snmp_context_name;                  //The following for SNMPv3
    ngx_str_t       snmp_security_name;
    ngx_uint_t      snmp_security_level;
    ngx_uint_t      snmp_auth_protocol;
    ngx_str_t       snmp_auth_phrase; 
    ngx_uint_t      snmp_privacy_protocol; 
    ngx_str_t       snmp_privacy_phrase; 
    ngx_array_t     *snmp_oids;                         //ngx_snmp_oid_t
}ngx_snmp_paras_t;
 
typedef struct {
    ngx_str_t                       server_ip;
    ngx_str_t                       name;
    ngx_pool_t                      *pool;
    ngx_array_t                     *obj_data;                      //ngx_snmp_obj_data_t
    ngx_http_upstream_srv_conf_t    *uscf;
    ngx_snmp_paras_t                *snmp_paras;
}ngx_snmp_server_data_t;
 
 typedef struct{
    ngx_int_t                         obj_id;                
    ngx_snmp_oid_t                    *snmp_obj;
    ngx_snmp_perf_t                   *snmp_perf; 
    ngx_int_t                          last_update_time;
    ngx_int_t                          last_value; 
    ngx_int_t                          update_time;
    ngx_int_t                          value; 
    ngx_int_t                          request_id; 
    ngx_int_t                          receive_id;
    ngx_str_t                          *pdu_reqid;
    ngx_str_t                          *pdu_head;
    ngx_str_t                          *pdu_obj;
    ngx_str_t                          *pdu;
    ngx_str_t                          *receive_buf; 
    ngx_connection_t                   *c;
    ngx_peer_connection_t              *pc;
    ngx_log_t                          *log;
    ngx_addr_t                         *peer;
    ngx_snmp_server_data_t             *server_data; 
 }ngx_snmp_obj_data_t;

typedef struct {
    ngx_str_t                       upstream_name;
    ngx_str_t                       para_name; 
    ngx_str_t                       perf_group_name; 
    ngx_http_upstream_srv_conf_t    *uscf;
    ngx_snmp_paras_t                *snmp_paras; 
    ngx_snmp_perf_group_t           *snmp_perf_group;                      
    ngx_array_t                     *snmp_server_data;                               //ngx_snmp_server_data_t
    ngx_str_t                       redirect_uri;                
}ngx_guard_upstream_t;

typedef struct {
    ngx_array_t                     *snmp_paras;                                //ngx_snmp_paras_t
    ngx_array_t                     *snmp_perfs;                                //ngx_snmp_perf_group_t
    ngx_array_t                     *guard_upstream;                            //ngx_guard_upstream_t
}ngx_snmp_main_conf_t;

static void *
ngx_http_snmp_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_snmp_paras_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_parameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_snmp_server_performance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_perf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_snmp_post_conf(ngx_conf_t *cf);
static ngx_uint_t 
ngx_array_remove(ngx_array_t *a, ngx_uint_t no);
static ngx_int_t
ngx_http_snmp_initate_server_data(ngx_conf_t *cf);
static ngx_int_t 
ngx_http_snmp_init_process (ngx_cycle_t *cycle);
static ngx_int_t
ngx_http_snmp_get_server_ip(ngx_http_upstream_server_t *us,ngx_str_t **server_ip);
static ngx_int_t
ngx_http_snmp_init_obj_data(ngx_conf_t *cf,ngx_snmp_server_data_t *server_data);
static ngx_int_t 
ngx_http_snmp_build_2c_oct(ngx_snmp_server_data_t *server_data);
static ngx_int_t 
ngx_http_snmp_build_ber(ngx_uint_t nodeoid, ngx_str_t *pdup,ngx_int_t objlen);
static ngx_int_t 
ngx_http_snmp_build_request_id(ngx_snmp_server_data_t *server_data);
static ngx_int_t 
ngx_http_snmp_build_2c_pdu_head(ngx_snmp_server_data_t *server_data,ngx_snmp_paras_t *sp);
static void 
ngx_http_snmp_event_handler(ngx_event_t *ev);
static ngx_int_t
ngx_http_snmp_complete_pdu(ngx_snmp_obj_data_t *obj_data);
static ngx_int_t 
ngx_http_snmp_build_pdu(ngx_snmp_server_data_t *server_data,ngx_snmp_paras_t *sp);
static ngx_int_t
ngx_http_snmp_initate_str(ngx_conf_t *cf,ngx_str_t **str,ngx_int_t len);
static ngx_int_t
ngx_http_snmp_send_pdu(ngx_snmp_obj_data_t *obj_data);
static ngx_int_t 
ngx_http_snmp_rebuild_request_id(ngx_snmp_obj_data_t *obj_data);
static ngx_int_t
ngx_http_snmp_get_peer(ngx_peer_connection_t *pc, void *data);
static void
ngx_http_snmp_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state);
static void ngx_http_snmp_dummy_send(ngx_event_t *wev);
static void
ngx_http_snmp_send(ngx_snmp_obj_data_t *obj_data);
static void
ngx_http_snmp_recv(ngx_event_t *rev);


static ngx_command_t  ngx_http_snmp_commands[] = {
    { 
        ngx_string("snmp"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_http_snmp_paras_group,
        0,
        0,
        NULL 
    },
    { 
        ngx_string("server_performance"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_http_snmp_server_performance,
        0,
        0,
        NULL 
    },
    {
        ngx_string("param"),
        NGX_SNMP_MAIN_CONF|NGX_CONF_TAKE2,
        ngx_snmp_parameters,
        0,
        0,
        NULL
    },
    {
        ngx_string("perf"),
        NGX_HTTP_MAIN_CONF|NGX_MAIN_CONF|NGX_CONF_TAKE3,
        ngx_snmp_perf,
        0,
        0,
        NULL
    },
    {
        ngx_string("guard_upstream"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
        ngx_guard_upstream,
        0,
        0,
        NULL
    },
    
    ngx_null_command
};

#ifdef __cplusplus
}
#endif

#endif /* NGX_HTTP_SNMP_MODULE_H */

