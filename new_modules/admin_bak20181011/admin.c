/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "admin.h"

static char *
admin_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
admin_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    admin_listen_t *listen);
static ngx_int_t
admin_cmp_conf_addrs(const void *one, const void *two);


static ngx_core_module_t  admin_module_ctx = {
    ngx_string("admin"),
    NULL,
    NULL
};

static ngx_command_t  admin_commands[] = {

    { ngx_string("admin"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      admin_block,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_module_t  admin_module = {
    NGX_MODULE_V1,
    &admin_module_ctx,                     /* module context */
    admin_commands,                        /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process  */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
admin_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    admin_conf_ctx_t                                *ctx;
    ngx_uint_t                                      m, mi,i;
    ngx_module_t                                    **modules;
    admin_module_t                                  *module;
    ngx_conf_t                                      pcf;
    char                                            *rv;
    admin_core_main_conf_t                          *acmcf;
    ngx_array_t                                     ports;
    admin_listen_t                                 *listen;
        
    ctx = ngx_pcalloc(cf->pool, sizeof(admin_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    
    *(admin_conf_ctx_t **) conf = ctx;
    
    #if (nginx_version >= 1009011)

    admin_max_module = ngx_count_modules(cf->cycle, ADMIN_MODULE);

#else

    admin_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_SNMP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = admin_max_module++;
    }

#endif

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * admin_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    #if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif
    
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != ADMIN_MODULE) {
            continue;
        }
        
        module = modules[m]->ctx;
        mi = modules[m]->ctx_index;
        
        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        else{
            ctx->main_conf[mi] = NULL;
        }
    }
    
    pcf = *cf;
    cf->ctx = ctx;
    
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != ADMIN_MODULE) {
            continue;
        }

        module = modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }
    
    cf->module_type = ADMIN_MODULE;
    cf->cmd_type = ADMIN_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);
    
    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }
    
    acmcf = ctx->main_conf[admin_core_module.ctx_index];
    
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != ADMIN_MODULE) {
            continue;
        }
        
        module = modules[m]->ctx;
        mi = modules[m]->ctx_index;
        
        cf->ctx = ctx;
        
        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }
    }
    
    cf->ctx = ctx; 
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != ADMIN_MODULE) {
            continue;
        }

        module = modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                *cf = pcf;
                return NGX_CONF_ERROR;
            }
        }
    }
    
    *cf = pcf;
    
    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(admin_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    listen = acmcf->listen.elts;
    
    for (i = 0; i < acmcf->listen.nelts; i++) {
        if (admin_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    
    return admin_optimize_servers(cf, &ports);
    //return NGX_CONF_OK;
}

static ngx_int_t
admin_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    admin_listen_t *listen)
{
    struct sockaddr                              *sa;
    in_port_t                                    p;
    struct sockaddr_in                           *sin;
    admin_conf_port_t                            *port;
    admin_conf_addr_t                            *addr;
    
    
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
#endif
    
    sa = (struct sockaddr *) &listen->sockaddr;
    
    switch(sa->sa_family){

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        p = sin6->sin6_port;
        break;
#endif
    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        p = sin->sin_port;
        break;    
    }
    
    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }
    
     /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(admin_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    
found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
    addr->socklen = listen->socklen;
    addr->ctx = listen->ctx;
    addr->bind = listen->bind;
    addr->wildcard = listen->wildcard;
    addr->so_keepalive = listen->so_keepalive;
    addr->proxy_protocol = listen->proxy_protocol;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    addr->tcp_keepidle = listen->tcp_keepidle;
    addr->tcp_keepintvl = listen->tcp_keepintvl;
    addr->tcp_keepcnt = listen->tcp_keepcnt;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    addr->ipv6only = listen->ipv6only;
#endif

    return NGX_OK;
    
}

static char *
admin_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
    ngx_uint_t                                     i, p, last, bind_wildcard;
    ngx_listening_t                                *ls;
    admin_port_t                                   *mport;
    admin_conf_port_t                              *port;
    admin_conf_addr_t                              *addr;
    
    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(admin_conf_addr_t), admin_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].wildcard) {
            addr[last - 1].bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].bind) {
                i++;
                continue;
            }

            ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = admin_init_connection;
            ls->pool_size = 4096;

            /* TODO: error_log directive */
            ls->logp = &cf->cycle->new_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            ls->keepalive = addr[i].so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].tcp_keepidle;
            ls->keepintvl = addr[i].tcp_keepintvl;
            ls->keepcnt = addr[i].tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].ipv6only;
#endif

            mport = ngx_palloc(cf->pool, sizeof(admin_port_t));
            if (mport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = mport;

            if (i == last - 1) {
                mport->naddrs = last;

            } else {
                mport->naddrs = 1;
                i = 0;
            }

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (admin_add_addrs6(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (admin_add_addrs(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }     
}

static ngx_int_t
admin_cmp_conf_addrs(const void *one, const void *two)
{
    admin_conf_addr_t  *first, *second;

    first = (admin_conf_addr_t *) one;
    second = (admin_conf_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}

static ngx_int_t
admin_add_addrs(ngx_conf_t *cf, admin_port_t *hport,
    admin_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    admin_in_addr_t         *addrs;
    struct sockaddr_in        *sin;
  //  ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(admin_in_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin = &addr[i].opt.u.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_V2)
        addrs[i].conf.http2 = addr[i].opt.http2;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }
/*
        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }
*/
    return NGX_OK;
}