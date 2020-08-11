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

#define NGX_SNMP_MAIN_CONF             0x11000000

 
 typedef struct{
    ngx_int_t                  id; 
    ngx_str_t                  obj_name; 
    ngx_str_t                  default_oid;
    ngx_str_t                  conf_oid;
    ngx_int_t                  max_value; 
    ngx_int_t                  weight;    
 }ngx_snmp_obj_t;   
 
 ngx_snmp_obj_t snmp_objs[] = {
     {0,"load","1.3.6.1.4.1.2021.10.1.3.1","",8,80},
     {0,"swap_size","1.3.6.1.4.1.2021.4.3.0","",80,5},
     {0,"swap_free","1.3.6.1.4.1.2021.4.4.0","",0,0},
     {0,"mem_size","1.3.6.1.4.1.2021.4.5.0","",10485760,15},
     {0,"mem_free","1.3.6.1.4.1.2021.4.6.0","",0,0},
     {0,"buffer","1.3.6.1.4.1.2021.4.14.0","",0,0},
     {0,"cached","1.3.6.1.4.1.2021.4.15.0","",0,0}
 }
 
 
typedef struct {
    
    ngx_int_t                  last_update_time;
    ngx_int_t                  last_value; 
    ngx_int_t                  update_time;
    ngx_int_t                  value; 
    ngx_int_t                  request_id; 
    ngx_int_t                  receive_id;
    
    
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
    ngx_str_t       snmp_cpu_load_oid;                      //OID for load average 1M
    ngx_str_t       snmp_swap_size_oid;                     //OID for swap size
    ngx_str_t       snmp_swap_available_oid;                //OID for used size of swap 
    ngx_str_t       snmp_mem_size_oid;                      //OID for total size of memory
    ngx_str_t       snmp_mem_free_oid;                      //OID for free size of memory
    ngx_str_t       snmp_mem_buffer_oid;                    //OID for buffer size of memory 
    ngx_str_t       snmp_mem_cached_oid;                    //OID for cached size of memory  Memfree = free+buffer+cached    
}ngx_snmp_paras_t;

typedef struct {
    ngx_str_t       name; 
    ngx_uint_t      cpu_load_max;                           //Max value allowed for load average 1M                  
    ngx_uint_t      cpu_load_weight;                        //Weight value for load average. (Two digital)
    ngx_uint_t      swapratio_max;                          //Max value allowd for swapratio swapratio = swapused/swaptotal*100%
    ngx_uint_t      swapratio_weight;                       //Weight value of swapratio
    ngx_uint_t      freemem_min;                            //Min. value allowd for free memory
    ngx_uint_t      freemem_weight;                         //Weight value of free memory 
}ngx_server_data_settings_t;

typedef struct {
    ngx_uint_t                      load_update_time;
    ngx_uint_t                      swap_update_time;
    ngx_uint_t                      cpu_load_value; 
    ngx_uint_t                      swap_used_value;
    ngx_uint_t                      swapration_value; 
    ngx_uint_t                      freemem_value;
    ngx_uint_t                      freemem_update_time;
    ngx_uint_t                      buffered_value;
    ngx_uint_t                      buffered_update_time;
    ngx_uint_t                      cached_value; 
    ngx_uint_t                      cached_update_time;
    ngx_uint_t                      freemem_size; 
    ngx_uint_t                      freemem_update_time; 
}ngx_server_data_t;

typedef struct {
    ngx_str_t                        *cpu_load;
    ngx_str_t                        *swap_size;
    ngx_str_t                        *swap_free;
    ngx_str_t                        *mem_size;
    ngx_str_t                        *mem_free;
    ngx_str_t                        *mem_buffer;
    ngx_str_t                        *mem_cached;
}ngx_snmp_request_pdu_t;

typedef struct {
    ngx_str_t                       server_ip;
    ngx_str_t                       *pdu_reqid;
    ngx_snmp_request_pdu_t          *pdu_head;
    ngx_snmp_request_pdu_t          *pdu_obj;
    ngx_snmp_request_pdu_t          *pdu;
    ngx_server_data_t               server_data;
    ngx_connection_t                *c;
    ngx_uint_t                      last_request_id;
    ngx_uint_t                      last_receive_id; 
    u_char                          *receive_buf; 
    ngx_http_upstream_srv_conf_t    *uscf;
    ngx_server_data_settings_t      *server_data_settings;
    ngx_snmp_paras_t                *snmp_paras;
}ngx_snmp_session_t;

typedef struct {
    ngx_str_t                       upstream_name;
    ngx_str_t                       para_name; 
    ngx_str_t                       server_setting_name; 
    ngx_http_upstream_srv_conf_t    *uscf;
    ngx_snmp_paras_t                *snmp_paras; 
    ngx_server_data_settings_t      *server_data_settings;                      
    ngx_array_t                     *snmp_session;                               //ngx_snmp_session_t
    ngx_str_t                       redirect_uri;                
}ngx_guard_upstream_t;

typedef struct {
    ngx_array_t                     *snmp_paras;                                //ngx_snmp_paras_t
    ngx_array_t                     *server_data_settings;                      //ngx_server_data_settings_t
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
ngx_http_snmp_initate_session(ngx_conf_t *cf);
ngx_int_t 
ngx_http_snmp_init_process (ngx_cycle_t *cycle);
static ngx_int_t
ngx_http_snmp_get_server_ip(ngx_http_upstream_server_t *us,ngx_str_t **server_ip);
static ngx_int_t
ngx_http_snmp_init_server_data(ngx_server_data_t *sd);
static ngx_int_t
ngx_http_snmp_init_server_pdu(ngx_conf_t *cf,ngx_snmp_request_pdu_t *srp);
static ngx_int_t 
ngx_http_snmp_build_2c_oct(ngx_str_t *oid,ngx_str_t *pdup);
static ngx_int_t 
ngx_http_snmp_build_ber(ngx_uint_t nodeid,ngx_str_t *pdup,ngx_uint_t objlen);
static ngx_int_t 
ngx_http_snmp_build_request_id(ngx_snmp_session_t *ss);
static ngx_int_t 
ngx_http_snmp_build_2c_pdu_head(ngx_snmp_session_t *ss,ngx_snmp_paras_t *sp);
static ngx_int_t 
ngx_http_snmp_init_str_for_pdu(ngx_conf_t *cf,ngx_snmp_request_pdu_t *srp,ngx_int_t len);
static void ngx_http_snmp_event_handler(ngx_event_t *ev);
static ngx_int_t
ngx_http_snmp_complete_pdu(ngx_snmp_session_t *ss);




static ngx_command_t  ngx_http_snmp_commands[] = {
    { 
        ngx_string("snmp"),
        NGX_HTTP_MAIN_CONF|NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_http_snmp_paras_group,
        0,
        0,
        NULL 
    },
    { 
        ngx_string("server_performance"),
        NGX_HTTP_MAIN_CONF|NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
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
        NGX_SNMP_MAIN_CONF|NGX_CONF_TAKE2,
        ngx_snmp_perf,
        0,
        0,
        NULL
    },
    {
        ngx_string("guard_upstream"),
        NGX_MAIN_CONF|NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
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

