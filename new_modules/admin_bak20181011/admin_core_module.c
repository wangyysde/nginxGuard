/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include"admin.h"

static char *
admin_core_command_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) ;
static void *
admin_core_create_conf(ngx_conf_t *cf);

static admin_module_t admin_core_module_ctx = {
    NULL,                                                                       /* preconfiguration */    
    NULL,                                                                       /* postconfiguration */
    admin_core_create_conf,                                                     /* create main configuration */
    NULL                                                                        /* init main configuration */
};

static ngx_command_t admin_core_commands[] = {
    { 
        ngx_string("listen"),
        ADMIN_MAIN_CONF|NGX_CONF_TAKE1,   
        admin_core_command_listen, 
        0,
        0,
        NULL 
    },
   
    ngx_null_command
};

ngx_module_t  admin_core_module = {
    NGX_MODULE_V1,
    &admin_core_module_ctx,                                                     /* module context */
    admin_core_commands,                                                        /* module directives  */
    ADMIN_MODULE,                                                               /* module type  */
    NULL,                                                                       /* init master */
    NULL,                                                                       /* init module */
    NULL,                                                                       /* init process */
    NULL,                                                                       /* init thread */
    NULL,                                                                       /* exit thread */
    NULL,                                                                       /* exit process */
    NULL,                                                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
admin_core_command_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)   
{
    ngx_str_t                                        *value;
    ngx_url_t                                        u;
    admin_core_main_conf_t                           *acmcf;
    admin_listen_t                                   *als;
    ngx_uint_t                                       i;
    struct sockaddr                                  *sa;
    size_t                                           len, off;
    in_port_t                                        port;
    struct sockaddr_in                               *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                              *sin6;
#endif
    
    
    value = cf->args->elts;
    
    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = ADMIN_CORE_DEFAULT_PORT;
    
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }
    
    acmcf = ngx_admin_conf_get_module_main_conf(cf, admin_core_module);
    if(acmcf == NULL){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "Can not get admin core module main conf on cf");
        return NGX_CONF_ERROR;
    }
    
    als = acmcf->listen.elts;
    
    for (i = 0; i < acmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) als[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = (struct sockaddr_in6 *) sa;
            port = sin6->sin6_port;
            break;
#endif

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = (struct sockaddr_in *) sa;
            port = sin->sin_port;
            break;
        }

        if (ngx_memcmp(als[i].sockaddr + off, (u_char *) &u.sockaddr + off, len)
            != 0)
        {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }
    
    als = ngx_array_push(&acmcf->listen);
    if (als == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ngx_memzero(als, sizeof(admin_listen_t));
    
    ngx_memcpy(als->sockaddr, (u_char *) &u.sockaddr, u.socklen);
    
    als->socklen = u.socklen;
    als->wildcard = u.wildcard;
    als->ctx = cf->ctx;
        
    return NGX_CONF_OK;
}

static void *
admin_core_create_conf(ngx_conf_t *cf){
    admin_core_main_conf_t                           *acmcf;
    
    acmcf = ngx_pcalloc(cf->pool, sizeof(admin_core_main_conf_t));
    if(acmcf == NULL){
        return NULL;
    }
    
    if (ngx_array_init(&acmcf->listen,cf->pool,1,sizeof(admin_listen_t))
        != NGX_OK)
    {
        return NULL;
    }
        
    return acmcf;
}