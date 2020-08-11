/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp.h"
#include <ngx_http.h>
#include "ngx_snmp_rpn.h"
#include "ngx_snmp_http_control_module.h"

static void *
ngx_snmp_http_control_conf_main_create(ngx_conf_t *cf);
static void *
ngx_snmp_http_control_conf_server_create(ngx_conf_t *cf);
static void *
ngx_snmp_http_control_conf_loc_create(ngx_conf_t *cf);

static char *
ngx_snmp_http_control_conf_loc_merge(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t 
ngx_snmp_http_control_init_process(ngx_cycle_t *cycle);
static ngx_int_t
ngx_snmp_http_control_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_snmp_http_control_post_conf(ngx_conf_t *cf);
static char *
ngx_conf_snmp_http_control_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_conf_enum_t  ngx_snmp_http_guard_mode[] = {
    { ngx_string("or"), NGX_SNMP_GUARD_MODE_OR },
    { ngx_string("and"), NGX_SNMP_GUARD_MODE_AND },
    { ngx_null_string, 0 }
};

static ngx_http_module_t  ngx_snmp_http_control_module_ctx = {     // 
    NULL,                                                                      /* preconfiguration */
    ngx_snmp_http_control_post_conf,                                           /* postconfiguration */

    ngx_snmp_http_control_conf_main_create,                                    /* create main configuration */
    NULL,                                                                      /* init main configuration */

    ngx_snmp_http_control_conf_server_create,                                  /* create server configuration */
    NULL,                                                                      /* merge server configuration */

    ngx_snmp_http_control_conf_loc_create,                                     /* create location configuration */
    ngx_snmp_http_control_conf_loc_merge                                       /* merge location configuration */
};

static ngx_command_t  ngx_snmp_http_control_commands[] = {
    
    { ngx_string("guard_upstream"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_snmp_http_control_guard_upstream,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("guard_mode"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_snmp_http_control_loc_conf_t, guard_mode),
      &ngx_snmp_http_guard_mode },  
    
    { ngx_string("action_url"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_snmp_http_control_loc_conf_t, action_url),
      NULL },
      
    { ngx_string("action_msg"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_snmp_http_control_loc_conf_t, action_msg),
      NULL },
      
    { ngx_string("action_code"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_snmp_http_control_loc_conf_t, action_code),
      NULL },
      
    ngx_null_command
};


ngx_module_t  ngx_snmp_http_control_module = {
    NGX_MODULE_V1,
    &ngx_snmp_http_control_module_ctx,             /* module context */
    ngx_snmp_http_control_commands,                /* module directives */
    NGX_HTTP_MODULE,                               /* module type  */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    ngx_snmp_http_control_init_process,            /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_snmp_http_control_conf_main_create(ngx_conf_t *cf){
    ngx_snmp_http_control_main_conf_t               *shcmcf;
    
    shcmcf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_http_control_main_conf_t));
    if (shcmcf == NULL) {
        return "Alloc memory for control main conf error";
    }
    
    if (ngx_array_init(&shcmcf->server_conf,cf->pool,1,sizeof(ngx_snmp_http_control_server_conf_t *))
        != NGX_OK)
    {
        return "Initate control main conf server error";
    }
    
    return shcmcf;
}

static void *
ngx_snmp_http_control_conf_server_create(ngx_conf_t *cf){
    ngx_snmp_http_control_server_conf_t             *shcscf;
         
    shcscf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_http_control_server_conf_t));
    if (shcscf == NULL) {
        return "Alloc memory for HTTP control sever conf error";
    }

    shcscf->server_name = NGX_CONF_UNSET_PTR;
    shcscf->shcscf = NGX_CONF_UNSET_PTR;
    
    if(ngx_array_init(&shcscf->loc_conf,cf->pool,1,sizeof(ngx_snmp_http_control_loc_conf_t *))
            != NGX_OK){
        return "Initate locate conf on HTTP control server conf error";
    }
    
    return shcscf;
    
} 

static void *
ngx_snmp_http_control_conf_loc_create(ngx_conf_t *cf){
    ngx_snmp_http_control_loc_conf_t                *shclcf;
     
    shclcf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_http_control_loc_conf_t));
    if (shclcf == NULL) {
        return "Alloc memory for HTTP control locate conf error";
    }
    
    ngx_str_null(&shclcf->guard_upstream);
    shclcf->guard_mode = NGX_CONF_UNSET;
    ngx_str_null(&shclcf->action_url);
    ngx_str_null(&shclcf->action_msg);
    shclcf->action_code = NGX_CONF_UNSET;
    shclcf->scug = NGX_CONF_UNSET_PTR;
    shclcf->shclcf = NGX_CONF_UNSET_PTR;
    shclcf->loc_name = NGX_CONF_UNSET_PTR;
    
    return shclcf;
}



static char *
ngx_snmp_http_control_conf_loc_merge(ngx_conf_t *cf, void *parent, void *child){
    ngx_snmp_http_control_loc_conf_t                    *prev = parent;
    ngx_snmp_http_control_loc_conf_t                    *conf = child,**shclcfp;
    ngx_snmp_http_control_main_conf_t                   *shcmcf;
    ngx_http_core_srv_conf_t                            *hcscf;
    ngx_snmp_http_control_server_conf_t                 **shcscfp,*shcscf,**found_svr,*shcsconf;
    ngx_str_t                                           server_name;
    ngx_uint_t                                          i,found;
    ngx_http_core_loc_conf_t                            *hclcf;
    
    if(conf->guard_upstream.len == 0 && prev->guard_upstream.len != 0){
        conf->guard_upstream = prev->guard_upstream;
    }
    
    if(conf->guard_upstream.len == 0){
        return NGX_CONF_OK; 
    }
    
    shcmcf = ngx_http_conf_get_module_main_conf(cf,ngx_snmp_http_control_module);
    if(shcmcf ==  NULL){
        return "Can not got HTTP control  main conf at cf";
    }
    
    shcsconf = ngx_http_conf_get_module_srv_conf(cf,ngx_snmp_http_control_module);
    if(shcsconf == NULL){
        return "Can not got HTTP control  server conf at cf";
    }
    
    hcscf = ngx_http_conf_get_module_srv_conf(cf,ngx_http_core_module);
    if(hcscf == NULL){
        return "Can not got HTTP core  server conf at cf";
    }
    
    hclcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
    if(hclcf == NULL){
        return "Can not got HTTP core loc conf at cf";
    }
    
    server_name = hcscf->server_name;
    
    shcscfp = shcmcf->server_conf.elts;
    found  = 0;
    for(i=0;i<shcmcf->server_conf.nelts;i++){
        shcscf = shcscfp[i];
        if(server_name.len ==  shcscf->server_name->len &&
            ngx_strncmp(server_name.data,shcscf->server_name->data,server_name.len) == 0){
            found = 1;
            found_svr = &shcscf;
        }
    }
    
    if(found == 0){
        found_svr = ngx_array_push(&shcmcf->server_conf);
        if(found_svr == NULL){
            return "Push Server conf to main conf error";
        }
        *found_svr = shcsconf;
        shcsconf->shcscf = shcsconf;
        shcsconf->server_name = &hcscf->server_name;
    }
    
    shclcfp = ngx_array_push(&((*found_svr)->loc_conf));
    if(shclcfp == NULL){
        return "Push LOC conf to server conf error";
    }
    
    *shclcfp = conf;
    conf->shclcf = conf;
    
    if(conf->guard_mode == NGX_CONF_UNSET && prev->guard_mode != NGX_CONF_UNSET){
        conf->guard_mode = prev->guard_mode;
    }
    
    if(conf->guard_mode == NGX_CONF_UNSET){
        conf->guard_mode = NGX_SNMP_GUARD_MODE_OR;
    }
    
    if(conf->action_url.len == 0 && prev->action_url.len != 0){
        conf->action_url = prev->action_url;
    }
    
    if(conf->action_msg.len == 0 && prev->action_msg.len != 0){
        conf->action_msg = prev->action_msg;
    }
    
    if(conf->action_code == 0 && prev->action_code != 0){
        conf->action_code = prev->action_code;
    }
    
    conf->loc_name = &hclcf->name;
    
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_snmp_http_control_post_conf(ngx_conf_t *cf){
    ngx_http_handler_pt                         *h;
    ngx_http_core_main_conf_t                   *hcmcf;
    
    hcmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (hcmcf == NULL) {
        return NGX_ERROR;
    }
    
    h = ngx_array_push(&hcmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    
    *h = ngx_snmp_http_control_handler;
    return NGX_OK;
    
}

static ngx_int_t
ngx_snmp_http_control_handler(ngx_http_request_t *r){
    ngx_snmp_http_control_loc_conf_t                    *shclcf;
    ngx_snmp_core_upstream_group_t                      *scug; 
    ngx_snmp_core_server_data_t                         *scsds,scsd;
    ngx_snmp_item_value_t                               *sivs,siv;
    ngx_uint_t                                          i,j,unhealthy_svr_num;
    ngx_snmp_core_item_t                                *scitem;
    ngx_snmp_float_t                                    most,total_itemvalue;
    ngx_int_t                                           direction,weight,valueover_flag,svr_unhealthy_flag;
    ngx_http_upstream_server_t                          *upstream_server; 
    
    shclcf = ngx_http_get_module_loc_conf(r,ngx_snmp_http_control_module);
    if(shclcf == NULL){
        return NGX_OK;
    }
    
    if(shclcf->guard_upstream.len == 0){
        return NGX_OK;
    }
    
    scug = shclcf->scug;
    scsds = scug->server_data->elts;
    unhealthy_svr_num = 0;
    for(i=0;i<scug->server_data->nelts;i++){
        scsd = scsds[i];
        sivs = scsd.item_value->elts;
        total_itemvalue = 0;
        svr_unhealthy_flag = 0;
        for(j=0;j<scsd.item_value->nelts;j++){
            siv = sivs[j];
            if(siv.received_sn == 0 || siv.sent_sn != siv.received_sn){
                continue;
            }
            
            if(siv.stats == 1){
                continue;
            }
            
            valueover_flag = 0;
            scitem = siv.item;
            most = scitem->most;
            direction = scitem->direction;
            weight = scitem->weight;
            if(siv.value > most && direction == SNMP_DIRECTION_MORE){
                valueover_flag = 1;
                total_itemvalue = total_itemvalue + siv.value/most*weight*0.01;
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Value:%2f of item:\"%V\" on Server:\"%V\" MORE than the most value",
                        siv.value,&scitem->name,&scsd.name);
            }
            
            if(siv.value < most && direction == SNMP_DIRECTION_LESS){
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Value:%2f of item:\"%V\" on Server:\"%V\" LESS than the most value",
                        siv.value,&scitem->name,&scsd.name);
                valueover_flag = 1;
                total_itemvalue = total_itemvalue + most/siv.value*weight*0.01;
            }
            
            if(valueover_flag == 1){
                if(shclcf->guard_mode == NGX_SNMP_GUARD_MODE_OR){
                    svr_unhealthy_flag = 1;
                    break;
                }
            }
        }
        
        if(shclcf->guard_mode == NGX_SNMP_GUARD_MODE_AND &&
                valueover_flag > 1){
            svr_unhealthy_flag = 1;
        }
        
        if(svr_unhealthy_flag == 1){
            unhealthy_svr_num++;
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Server:\"%V\" is unhealthy",&scsd.name);
            upstream_server = scsd.server;
            upstream_server->weight = 0;
        }
    }
    
    if(unhealthy_svr_num >= scug->server_data->nelts){
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "All  server: are unhealthy ");
        return NGX_ERROR;
    }
    
    
    return NGX_OK;
}

static ngx_int_t 
ngx_snmp_http_control_init_process(ngx_cycle_t *cycle){
    ngx_snmp_http_control_main_conf_t           *shcmcf;
    ngx_snmp_core_main_conf_t                   *scmcf;
    ngx_snmp_http_control_server_conf_t         **shcscfp,*shcscf;
    ngx_uint_t                                  i,j,k,found;
    ngx_snmp_core_upstream_group_t              *scugp,scug;
    ngx_snmp_http_control_loc_conf_t            **shclcfp,*shclcf;
    
       
    shcmcf = ngx_http_cycle_get_module_main_conf(cycle,ngx_snmp_http_control_module);
    if(shcmcf ==  NULL){
        ngx_log_error(NGX_LOG_ERR,cycle->log, 0, "Can not got HTTP control  main conf at cycle");
        return NGX_ERROR;
    }
    
    scmcf = ngx_snmp_cycle_get_module_main_conf(cycle,ngx_snmp_core_module);
    if (scmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR,cycle->log, 0, "Can not got SNMP core main conf at cycle");
        return NGX_ERROR;
    }
    
    scugp = scmcf->upstream_group.elts;
    shcscfp = shcmcf->server_conf.elts;
    for(i=0;i<shcmcf->server_conf.nelts;i++){
        shcscf = shcscfp[i];
        shclcfp = shcscf->loc_conf.elts;
        for(j=0;j<shcscf->loc_conf.nelts;j++){
            shclcf = shclcfp[j];
            if(shclcf->guard_upstream.len != 0){
                found = 0;
                for(k=0;k<scmcf->upstream_group.nelts;k++){
                    scug = scugp[k];
                    if( shclcf->guard_upstream.len == scug.upstream_name.len &&
                        ngx_strncmp(shclcf->guard_upstream.data,scug.upstream_name.data,scug.upstream_name.len) ==0){
                        shclcf->scug = ngx_alloc(sizeof(ngx_snmp_core_upstream_group_t),cycle->log);
                        if(shclcf->scug == NULL){
                             ngx_log_error(NGX_LOG_ERR,cycle->log, 0, "Alloc memory error");
                             return NGX_ERROR;
                        }
                        *shclcf->scug = scug;
                        found  = 1;
                        break;
                    }
                }
                if(found == 0){
                    ngx_log_error(NGX_LOG_ERR,cycle->log, 0, "Can not found upstream group with upstream name:\"%V\" in location:\"%V\"",
                            &shclcf->guard_upstream,shclcf->loc_name);
                    return NGX_ERROR;
                }
            }
        }
    }
    
    return NGX_OK;
    
}

static char *
ngx_conf_snmp_http_control_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                                   *values,upstream_name;
    ngx_snmp_http_control_loc_conf_t            *shclcf;
   
    values =  cf->args->elts;
    upstream_name = values[1];
    
    shclcf = (ngx_snmp_http_control_loc_conf_t *)conf;
    
    shclcf->guard_upstream = upstream_name;
        
    return NGX_CONF_OK;
}