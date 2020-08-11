/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ngx_snmp_module.h
 * Author: wangyuying
 *
 * Created on 2018年3月15日, 下午9:48
 */

#ifndef NGX_SNMP_MODULE_H
#define NGX_SNMP_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

//#ifndef _NGX_CORE_H_INCLUDED_
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>
//#endif

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

#define NGX_SNMP_MODULE                0x504D4E53          /*  "SNMP" */
#define NGX_SNMP_MAIN_CONF             0x02000000

typedef struct {
    
};

typedef struct {
    ngx_str_t                           name;              
    ngx_str_t                           oid;
    ngx_int_t                           type; 
    ngx_int_t                           last_update_time;
    ngx_int_t                           last_value; 
    ngx_int_t                           update_time;
    ngx_int_t                           value; 
    ngx_int_t                           request_id; 
    ngx_int_t                           receive_id;
    ngx_str_t                           *pdu_reqid;
    ngx_str_t                           *pdu_head;
    ngx_str_t                           *pdu_obj;
    ngx_str_t                           *pdu;
    ngx_str_t                           *receive_buf; 
    ngx_connection_t                    *c;
    ngx_peer_connection_t               *pc;
    ngx_log_t                           *log;
    ngx_addr_t                          *peer;
}ngx_snmp_object_t;





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
    ngx_str_t       snmp_cpu_load_oid;                      //OID for load average 1M
    ngx_str_t       snmp_swap_size_oid;                     //OID for swap size
    ngx_str_t       snmp_swap_available_oid;                //OID for used size of swap 
    ngx_str_t       snmp_mem_size_oid;                      //OID for total size of memory
    ngx_str_t       snmp_mem_free_oid;                      //OID for free size of memory
    ngx_str_t       snmp_mem_buffer_oid;                    //OID for buffer size of memory 
    ngx_str_t       snmp_mem_cached_oid;                    //OID for cached size of memory  Memfree = free+buffer+cached    
}ngx_snmp_paras_t;

static ngx_str_t snmp_paras_name[] = {
    ngx_string("interval"),
    ngx_string("version"),
    ngx_string("port"),
    ngx_string("commnunity"),
    ngx_string("context_name"),
    ngx_string("security_name"),
    ngx_string("security_level"),
    ngx_string("auth_protocol"),
    ngx_string("auth_phrase"),
    ngx_string("privacy_protocol"),
    ngx_string("load_oid"),
    ngx_string("swap_size_oid"),
    ngx_string("swap_used_size_oid"),
    ngx_string("mem_size_oid"),
    ngx_string("mem_free_oid"),
    ngx_string("mem_buffer_oid"),
    ngx_string("cached_oid")
}

/*
  For a Server weight：
 *  Initation weight   cpu_load_weight+swapratio_weight+freemem_weight=100
 *  Running weight:    If a item value reached max(Or Min) value then the weight value for this item is set to 0. Then:
 *                     cpu_load_value/cpu_load_max*cpu_load_weight+swapration_value/swapratio_max*swapratio_weight+(1 or 0)*freemem_weight<100     
 *  
 */
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
    ngx_str_t                       server_ip;
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
    ngx_uint_t                      server_weight; 
}ngx_server_data_t;

typedef struct {
    ngx_array_t                     *snmp_paras;                                 //ngx_snmp_paras_t
    ngx_array_t                     *server_data_settings;                        //ngx_server_data_settings_t
}ngx_snmp_main_conf_t;

typedef struct {
    ngx_str_t                       upstream_name;
    ngx_snmp_paras_t                *snmp_paras; 
    ngx_server_data_settings_t      *server_data_settings;                      
    ngx_array_t                     *server_data;                               //ngx_server_data_t
    ngx_str_t                       redirect_uri;                
}ngx_snmp_loc_t;

static ngx_command_t  ngx_snmp_module_commands[] = {
    { 
        ngx_string("snmp"),
        NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_snmp_parameters,
        0,
        0,
        NULL 
    },
    
    {
        ngx_string("param"),
        NGX_SNMP_MAIN_CONF|NGX_CONF_TAKE2,
        ngx_snmp_parameters,
        0,
        0
        NULL
    }
    ngx_null_command
};

static void *
ngx_snmp_create_conf(ngx_cycle_t *cycle);
static void *
ngx_snmp_init_conf(ngx_cycle_t *cycle,void *conf);
static char *
ngx_snmp_parameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* NGX_SNMP_MODULE_H */

