/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ngx_snmp_http_control_module.h
 * Author: wangyuying
 *
 * Created on 2018年9月4日, 上午11:29
 */

#ifndef NGX_SNMP_HTTP_CONTROL_MODULE_H
#define NGX_SNMP_HTTP_CONTROL_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

#define NGX_SNMP_GUARD_ON    1
#define NGX_SNMP_GUARD_OFF   0
#define NGX_SNMP_GUARD_MODE_OR 0
#define NGX_SNMP_GUARD_MODE_AND 1

typedef struct ngx_snmp_http_control_server_conf_s  ngx_snmp_http_control_server_conf_t ;
typedef struct ngx_snmp_http_control_loc_conf_s ngx_snmp_http_control_loc_conf_t;
       
typedef struct {
    ngx_array_t                     server_conf;                                //ngx_snmp_http_control_server_conf_t
}ngx_snmp_http_control_main_conf_t;
    
struct ngx_snmp_http_control_server_conf_s {
    ngx_str_t                                      *server_name;
    ngx_snmp_http_control_server_conf_t            *shcscf;
    ngx_array_t                                    loc_conf;                    //ngx_snmp_http_control_loc_conf_t
};    
    
struct ngx_snmp_http_control_loc_conf_s{
    ngx_str_t                           guard_upstream;                         //upstream name
    ngx_str_t                           snmp_group;
    ngx_int_t                           guard_mode;                             // OR or AND  OR: Don't redirect new request to a server when ANY item's value of the server reached; AND:Don't redirect new request to a server when ALL item's value of the server reached 
    ngx_str_t                           action_url;                             //当upstream里所有的服务器的被监控值都达到指定值时，跳转到action_url /action or http://www.domain.com/action
    ngx_str_t                           action_msg;                             //当upstream里所有的服务器的被监控值都达到指定值时，输出action_msg
    ngx_snmp_core_upstream_group_t      *scug; 
    ngx_snmp_http_control_loc_conf_t    *shclcf;
    ngx_str_t                           *loc_name;
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_int_t                           isdown;
    ngx_http_core_loc_conf_t            *clcf;
    ngx_http_handler_pt                 org_http_handler;
};



#ifdef __cplusplus
}
#endif

#endif /* NGX_SNMP_HTTP_CONTROL_MODULE_H */

