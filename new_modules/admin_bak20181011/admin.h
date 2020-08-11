/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   admin.h
 * Author: wangyuying
 *
 * Created on 2018年10月10日, 下午2:50
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>


#ifndef ADMIN_H
#define ADMIN_H

#ifdef __cplusplus
extern "C" {
#endif

#define ADMIN_MODULE                   0x4E494D4441                             /* ADMIN */    
#define ADMIN_MAIN_CONF                0x02000000   
#define ADMIN_CORE_DEFAULT_PORT        8080

extern ngx_module_t                         admin_core_module;

ngx_uint_t  admin_max_module;


typedef struct {
    void                               **main_conf;
//    void                                **group_conf;
//    void                                **item_conf;
//    void                                **object_conf;
    
} admin_conf_ctx_t;

typedef struct {
    ngx_int_t             (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);
    
} admin_module_t;

typedef struct {
    ngx_array_t             listen;                                             /* admin_listen_t */
    
}admin_core_main_conf_t;

typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    admin_conf_ctx_t       *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
    unsigned                proxy_protocol:1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} admin_listen_t;

typedef struct {
    void                   *addrs;
    ngx_uint_t              naddrs;
} admin_port_t;

typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of admin_conf_addr_t */
} admin_conf_port_t;

typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    admin_conf_ctx_t       *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
    unsigned                proxy_protocol:1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} admin_conf_addr_t;

typedef struct {
    admin_conf_ctx_t        *ctx;
    ngx_str_t               addr_text;
    unsigned                proxy_protocol:1;
} admin_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    admin_addr_conf_t       conf;
} admin_in_addr_t;


#define ngx_admin_conf_get_module_main_conf(cf, module)                       \
    ((admin_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]


void
admin_init_connection(ngx_connection_t *c);

#ifdef __cplusplus
}
#endif

#endif /* ADMIN_H */

