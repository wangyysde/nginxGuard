
/*
 * Copyright (C) Maxim Dounin
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define CONNECT_NUM_PER_SERVER     10
#define TRANSACTION_TIME           60
#define RESPONSE_MSG               "Servers are very busy ,please waiting for a short time"

typedef struct {
    ngx_flag_t         guard_flag;
    ngx_int_t          connect_num;
    ngx_int_t          reset_time;
    ngx_str_t          resp_msg; 
    ngx_str_t          redi_url;
    ngx_array_t                guards;
    ngx_uint_t                 log_level;
    ngx_uint_t                 status_code;
} ngx_http_guard_conf_t;


static void *ngx_http_guard_create_conf(ngx_conf_t *cf);
static char *ngx_http_guard_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_guard_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_guard_handler(ngx_http_request_t *r);
static char *ngx_http_guard_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_guard_commands[] = {

    { ngx_string("guard_switch"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conf_t, guard_flag),
      NULL },

      {  ngx_string("connect_num"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conf_t, connect_num),        
      NULL },
      
      {  ngx_string("reset_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conf_t, reset_time),        
      NULL },
      
     {  ngx_string("response_msg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conf_t, resp_msg),       
      NULL },
      
      {  ngx_string("redirect_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conf_t, redi_url),         
      NULL },
    
    { ngx_string("guard_conn_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_guard_conn_zone,
      0,
      0,
      NULL },
      
      ngx_null_command
};


static ngx_http_module_t  ngx_http_guard_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_guard_init,          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_guard_create_conf, /* create location configuration */
    ngx_http_guard_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_guard_module = {
    NGX_MODULE_V1,
    &ngx_http_guard_module_ctx,     /* module context */
    ngx_http_guard_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;


static ngx_int_t
ngx_http_guard(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                      *p;
    ngx_chain_t                 *cl;
    ngx_http_guard_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_guard_module);
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0, "Configurated connect_num is: %i",conf->connect_num);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0, "Configurated reset time  is: %i",conf->reset_time);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0, "Configurated redirect url   is: %V",&(conf->redi_url));
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0, "Configurated response message   is: %V",&(conf->resp_msg));
    
    
    if (!conf->guard_flag) {
        return ngx_http_next_request_body_filter(r, in);
    }
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "catch request body filter");

    for (cl = in; cl; cl = cl->next) {

        p = cl->buf->pos;

        for (p = cl->buf->pos; p < cl->buf->last; p++) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "catch body in:%02Xd:%c", *p, *p);

            if (*p == 'X') {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "catch body: found");

                /*
                 * As we return NGX_HTTP_FORBIDDEN, the r->keepalive flag
                 * won't be reset by ngx_http_special_response_handler().
                 * Make sure to reset it to prevent processing of unread
                 * parts of the request body.
                 */

                r->keepalive = 0;

                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    return ngx_http_next_request_body_filter(r, in);
}


static void *
ngx_http_guard_create_conf(ngx_conf_t *cf)
{
    ngx_http_guard_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_guard_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->guard_flag = NGX_CONF_UNSET;
    conf->connect_num = NGX_CONF_UNSET;
    conf->reset_time = NGX_CONF_UNSET; 
    conf->log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;
    
    return conf;
}


static char *ngx_http_guard_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_guard_conf_t *prev = parent;
    ngx_http_guard_conf_t *conf = child;

    ngx_conf_merge_value(conf->guard_flag, prev->guard_flag, 0);
    ngx_conf_merge_value(conf->connect_num,prev->connect_num,CONNECT_NUM_PER_SERVER);
    ngx_conf_merge_value(conf->reset_time,prev->reset_time,TRANSACTION_TIME);
    ngx_conf_merge_str_value(conf->resp_msg,prev->resp_msg,RESPONSE_MSG);
    ngx_conf_merge_str_value(conf->redi_url,prev->redi_url,NULL);
    if (conf->guards.elts == NULL) {
        conf->guards = prev->guards;
    }
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);
    
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_guard_init(ngx_conf_t *cf)
{

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_guard_handler;
    
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_guard;

    return NGX_OK;
}

static ngx_int_t
ngx_http_guard_handler(ngx_http_request_t *r)
{
   /*
    ngx_http_guard_conf_t lccf ;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_guard_module);
  //  limits = lccf->limits.elts;
    */
     return NGX_OK;
}

static char *
ngx_http_guard_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
   
    ngx_uint_t                        i;
    ngx_str_t                         *value, name, s;
    u_char                            *p;
    ngx_shm_zone_t                    *shm_zone;
    ssize_t                           size;
    
    value = cf->args->elts;
    size = 0;
    name.len = 0;
   
    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            name.data = value[i].data + 5;
            p = (u_char *) ngx_strchr(name.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            name.len = p - name.data;
            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;
            size = ngx_parse_size(&s);
            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_guard_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    
    if (shm_zone->data) {
       // ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key",
                           &cmd->name, &name);
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}