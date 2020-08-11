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
static char *
ngx_conf_snmp_http_control_snmp_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_http_upstream_srv_conf_t *
ngx_snmp_getUpstreamSrvFromMain(ngx_http_upstream_main_conf_t *upmcf,ngx_str_t upstream_name);
static ngx_snmp_core_group_t *
ngx_snmp_getGroupByNameFromMain(ngx_snmp_core_main_conf_t *scmcf,ngx_str_t group_name);
static ngx_int_t 
ngx_snmp_initate_server_data(ngx_conf_t *cf,ngx_snmp_core_group_t *scg,
        ngx_http_upstream_srv_conf_t *upsvr,ngx_snmp_core_upstream_group_t *scug);
static ngx_int_t
ngx_snmp_http_control_get_item_name_from_shmname(ngx_str_t shmname,ngx_str_t *item_name);
static ngx_int_t
ngx_snmp_http_control_init_share_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t
ngx_snmp_http_control_content_handler(ngx_http_request_t *r);
ngx_int_t
ngx_snmp_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);

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
    
    { ngx_string("snmp_group"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_snmp_http_control_snmp_group,
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
    
    ngx_str_null(&shclcf->snmp_group);
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
    
    if(conf->snmp_group.len == 0 && prev->snmp_group.len != 0){
        conf->snmp_group = prev->snmp_group;
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
    ngx_snmp_http_control_main_conf_t           *shcmcf;
    ngx_snmp_core_main_conf_t                   *scmcf;
    ngx_snmp_http_control_server_conf_t         **shcscfp,*shcscf;
    ngx_snmp_http_control_loc_conf_t            **shclcfp,*shclcf;
    ngx_snmp_core_upstream_group_t              *scugp,scug,*newscugp;
    ngx_http_upstream_main_conf_t               *upmcf;
    ngx_http_upstream_srv_conf_t                *upsvr;
    ngx_snmp_core_group_t                       *scg;
    ngx_uint_t                                  i,j,k,found_flag;
    ngx_str_t                                   upstream_name,group_name;
    ngx_array_t                                 *server_data;
    
    shcmcf = ngx_http_conf_get_module_main_conf(cf, ngx_snmp_http_control_module);
    if (shcmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Can not get SNMP http control module main conf");
        return NGX_ERROR;
    }
    
    scmcf = ngx_snmp_cycle_get_module_main_conf(cf->cycle,ngx_snmp_core_module);
    if (scmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Can not get SNMP core module main conf");
        return NGX_ERROR;
    }

    
    upmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    if(upmcf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Can not get UPSTREAM module main conf");
        return NGX_ERROR;
    }

    
    shcscfp = shcmcf->server_conf.elts;
    scugp = scmcf->upstream_group.elts;
    
    for(i=0;i<shcmcf->server_conf.nelts;i++){
        shcscf = shcscfp[i];
        shclcfp = shcscf->loc_conf.elts;
        for(j=0;j<shcscf->loc_conf.nelts;j++){
            shclcf = shclcfp[j];
            if(shclcf->guard_upstream.len == 0){
                continue;
            }
            
            if(shclcf->snmp_group.len == 0){
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "You should specify a snmp group for guard");
                return NGX_ERROR;
            }
            
            found_flag = 0;
            for(k=0;k<scmcf->upstream_group.nelts;k++){
                scug = scugp[k];
                if(shclcf->guard_upstream.len == scug.upstream_name.len  &&
                    ngx_strncmp(shclcf->guard_upstream.data,scug.upstream_name.data,shclcf->guard_upstream.len) == 0){
                    found_flag = 1;
                    break;
                }
            }
            
            if(found_flag == 1){
                continue;
            }
            
            group_name = shclcf->snmp_group;
            scg = ngx_snmp_getGroupByNameFromMain(scmcf,group_name);
            if(scg ==  NULL){
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "The group you specified by snmp_group was not found");
                return NGX_ERROR;
            }
            
            upstream_name = shclcf->guard_upstream;
            upsvr = ngx_snmp_getUpstreamSrvFromMain(upmcf,upstream_name);
            if(upsvr ==  NULL){
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "The upstream you specified by snmp_upstream was not found");
                return NGX_ERROR;
            }   
            shclcf->uscf = upsvr;

            newscugp = ngx_array_push(&scmcf->upstream_group);
            if (newscugp == NULL) {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Push upstream group into snmp core main conf error");
                return NGX_ERROR;
            }
            newscugp->upstream_name = upstream_name;
            newscugp->group_name = group_name;
            newscugp->uscf = upsvr;
            newscugp->group = scg; 
            
            server_data = ngx_array_create(cf->pool, 4,sizeof(ngx_snmp_core_server_data_t));
            if ((newscugp->server_data =  server_data) == NULL){
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Create snmp core server data error");
                return NGX_ERROR;
            }
            
            if(ngx_snmp_initate_server_data(cf,scg,upsvr,newscugp) != NGX_OK){
                return NGX_ERROR;
            }          
        }
    }
    
    
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
    ngx_snmp_item_value_t                               **sivs,*siv;
    ngx_uint_t                                          i,j,unhealthy_svr_num;
    ngx_snmp_core_item_t                                *scitem;
    ngx_snmp_float_t                                    most,total_itemvalue;
    ngx_int_t                                           direction,weight,valueover_flag,svr_unhealthy_flag;
    ngx_http_upstream_srv_conf_t                        *uscf;
    
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
        uscf = (ngx_http_upstream_srv_conf_t *)scsd.uscf;
        sivs = scsd.item_value->elts;
        total_itemvalue = 0;
        svr_unhealthy_flag = 0;
        for(j=0;j<scsd.item_value->nelts;j++){
            siv = sivs[j];
            if(siv->received_sn == 0 || siv->sent_sn != siv->received_sn){
                continue;
            }
          
            if(siv->stats == 1){
                continue;
            }
            
            valueover_flag = 0;
            scitem = siv->item;
            most = scitem->most;
            direction = scitem->direction;
            weight = scitem->weight;
            if(siv->value > most && direction == SNMP_DIRECTION_MORE){
                valueover_flag = 1;
                total_itemvalue = total_itemvalue + siv->value/most*weight*0.01;
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Value:%2f of item:\"%V\" on Server:\"%V\" MORE than the most value",
                        siv->value,&scitem->name,&scsd.name);
            }
            
            if(siv->value < most && direction == SNMP_DIRECTION_LESS){
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Value:%2f of item:\"%V\" on Server:\"%V\" LESS than the most value",
                        siv->value,&scitem->name,&scsd.name);
                valueover_flag = 1;
                total_itemvalue = total_itemvalue + most/siv->value*weight*0.01;
            }
            
            if(valueover_flag == 1){
                if(shclcf->guard_mode == NGX_SNMP_GUARD_MODE_OR){
                    svr_unhealthy_flag = 1;
                    break;
                }
            }
        }
        
        if(shclcf->guard_mode == NGX_SNMP_GUARD_MODE_AND ){
            if(total_itemvalue > most && direction == SNMP_DIRECTION_MORE){
                svr_unhealthy_flag = 1;
            }
            
            if(total_itemvalue < most && direction == SNMP_DIRECTION_LESS){
                svr_unhealthy_flag = 1;
            }
        }
        
        if(svr_unhealthy_flag == 1){
            unhealthy_svr_num++;
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Server:\"%V\" is unhealthy",&scsd.name);
            if(scsds[i].unhealthy == 0){
                scsds[i].unhealthy = 1;
            }
        }
        
        if(svr_unhealthy_flag == 0){
            if(unhealthy_svr_num > 0){
                unhealthy_svr_num--;
            }
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "Server:\"%V\" is healthy",&scsd.name);
            if(scsds[i].unhealthy == 1){
                scsds[i].unhealthy = 0;
            }
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
    ngx_http_core_loc_conf_t                    *clcf;
       
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
                        clcf = shclcf->clcf;
                        shclcf->org_http_handler = clcf->handler;
                        clcf->handler = ngx_snmp_http_control_content_handler;
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
    ngx_http_core_loc_conf_t                    *clcf;
   
    values =  cf->args->elts;
    upstream_name = values[1];
    
    shclcf = (ngx_snmp_http_control_loc_conf_t *)conf;
    
    shclcf->guard_upstream = upstream_name;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    shclcf->clcf = clcf;

    return NGX_CONF_OK;
}

static char *
ngx_conf_snmp_http_control_snmp_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
     ngx_str_t                                   *values,snmp_group;
    ngx_snmp_http_control_loc_conf_t             *shclcf;
   
    values =  cf->args->elts;
    snmp_group = values[1];
    
    shclcf = (ngx_snmp_http_control_loc_conf_t *)conf;
    
    shclcf->snmp_group = snmp_group;
        
    return NGX_CONF_OK;
    
}

static ngx_http_upstream_srv_conf_t *
ngx_snmp_getUpstreamSrvFromMain(ngx_http_upstream_main_conf_t *upmcf,ngx_str_t upstream_name)
{
    ngx_uint_t                                     i; 
    ngx_http_upstream_srv_conf_t                   **upsvrs,*upsvr; 
    
    if(upmcf == NULL || upstream_name.data == NULL)
    {
        return NULL;
    }
    
    upsvrs = upmcf->upstreams.elts;
    for(i=0;i<upmcf->upstreams.nelts;i++)
    {
        upsvr = upsvrs[i];
        if(upsvr->host.len ==  upstream_name.len &&
                ngx_strncmp(upsvr->host.data,upstream_name.data,upstream_name.len) == 0)
        {
            return upsvr;
        }
    }
    
    return NULL; 
}

static ngx_snmp_core_group_t *
ngx_snmp_getGroupByNameFromMain(ngx_snmp_core_main_conf_t *scmcf,ngx_str_t group_name)
{
    ngx_uint_t                              i; 
    ngx_snmp_core_group_t                   **scgp,*scg; 
    if(scmcf == NULL || group_name.data == NULL)
    {
        return NULL;
    }
    
    scgp = scmcf->groups.elts;
    for(i=0;i<scmcf->groups.nelts;i++)
    {
        scg = scgp[i];
        if(ngx_strncmp( scg->name.data,group_name.data,group_name.len) == 0)
        {
            return (scg);
        }
    }
    
    return NULL; 
}


static ngx_int_t 
ngx_snmp_initate_server_data(ngx_conf_t *cf,ngx_snmp_core_group_t *scg,
        ngx_http_upstream_srv_conf_t *upsvr,ngx_snmp_core_upstream_group_t *scug)
{
    ngx_uint_t                                       i,j,k;
    ngx_int_t                                        shmname_len;
    ngx_http_upstream_server_t                       *svrs,svr;
    ngx_snmp_core_item_t                             **scis,*sci;
    ngx_snmp_core_server_data_t                      *server_data;
    ngx_array_t                                      *a_item_value;
    ngx_str_t                                        shmname;
    u_char                                           *p;
    ngx_shm_zone_t                                   *shm_zone;
    
    svrs = upsvr->servers->elts;
    scis = scg->items.elts;
    
    for(i=0;i<upsvr->servers->nelts;i++){
        svr = svrs[i];
        for(k=0;k<svr.naddrs;k++)
        {
            server_data = ngx_array_push(scug->server_data);
            if(server_data == NULL)
            {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Initate server data error");
                return NGX_ERROR;
            }
            server_data->addrs = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
            if(server_data->addrs == NULL)
            {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Create memory for addrs error");
                return NGX_ERROR;
            }
            server_data->unhealthy = 0;
            server_data->uscf = upsvr;
            server_data->server = &svr;
            server_data->addrs[0] = svr.addrs[k];
            server_data->naddrs = 1;
            server_data->name = svr.name;
            server_data->group = scg; 
            server_data->flag = 1;
            server_data->last_down_time = 0;
            server_data->last_error_request_id = 0;
            server_data->error_count = 0;
            server_data->down = 0;
            server_data->pool = cf->pool;
            server_data->log = cf->log;
            server_data->cycle = cf->cycle;
            server_data->pdu_handler = &scg->pdu_handler;
            server_data->snmp_addrs = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
            if(server_data->snmp_addrs ==  NULL)
            {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Create memory for snmp addr error");
                return NGX_ERROR;
            }
        
    
            a_item_value = ngx_array_create(cf->pool, 1,sizeof(ngx_snmp_item_value_t *));
            if ((server_data->item_value = a_item_value) == NULL)
            {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Create array for item value error");
                return NGX_ERROR;
            }
            for(j=0;j<scg->items.nelts;j++)
            {
                sci = scis[j];
                shmname_len = upsvr->host.len + svr.name.len + scg->name.len + sci->name.len + 3;
                p = ngx_alloc(sizeof(u_char) * shmname_len,cf->log);
                if(p == NULL){
                    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Alloc memory error");
                    return NGX_ERROR;
                }
                shmname.data = p;
                ngx_memcpy(p,upsvr->host.data,upsvr->host.len);
                shmname.len = upsvr->host.len;
                p += upsvr->host.len;
                ngx_memcpy(p,"-",1);
                shmname.len++;
                p++;
                ngx_memcpy(p,svr.name.data,svr.name.len);
                shmname.len += svr.name.len;
                p += svr.name.len;
                ngx_memcpy(p,"-",1);
                shmname.len++;
                p++;
                ngx_memcpy(p,scg->name.data,scg->name.len);
                shmname.len += scg->name.len;
                p += scg->name.len;
                ngx_memcpy(p,"-",1);
                shmname.len++;
                p++;
                ngx_memcpy(p,sci->name.data,sci->name.len);
                shmname.len += sci->name.len;
                p += sci->name.len;

                shm_zone = ngx_shared_memory_add(cf,&shmname,(2 * ngx_pagesize),&ngx_snmp_http_control_module);
                if(shm_zone == NULL){
                    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Add share memory for item error");
                    return NGX_ERROR; 
                }
               
                shm_zone->init = ngx_snmp_http_control_init_share_zone;
                shm_zone->data = server_data;
            }
        }
    }
    return NGX_OK; 
}

static ngx_int_t
ngx_snmp_http_control_init_share_zone(ngx_shm_zone_t *shm_zone, void *data){
    ngx_snmp_core_server_data_t                      *server_data,*oserver_data;
    ngx_slab_pool_t                                  *shpool;
    ngx_str_t                                        shmname,item_name;
    ngx_snmp_item_value_t                            **item_valuep,**oitem_values,*oitem_value,**nitem_values,*nitem_value,*item_value;
    ngx_snmp_core_group_t                            *scg;
    ngx_snmp_core_item_t                             **scis,*sci;
    ngx_uint_t                                       i,j,found_flag; 
    ngx_array_t                                      *a_object_session;
    
    oserver_data = (ngx_snmp_core_server_data_t *)data;
    server_data = (ngx_snmp_core_server_data_t *) shm_zone->data;
    
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    shmname = shm_zone->shm.name;
    if(ngx_snmp_http_control_get_item_name_from_shmname(shmname,&item_name) == NGX_ERROR){
        ngx_log_error(NGX_LOG_ERR,server_data->log, 0, "Can not get item name in SHM name");
        return NGX_ERROR;
    }
    
    scg = server_data->group;
    scis = scg->items.elts;
    found_flag = 0;
    for(i=0;i<scg->items.nelts;i++){
        sci = scis[i];
        if(item_name.len ==  sci->name.len &&
            ngx_strncmp(item_name.data,sci->name.data,item_name.len) == 0){
            found_flag = 1;
            break;
        }
    }
                
    if(oserver_data){
        oitem_values =oserver_data->item_value->elts;
        found_flag = 0;
        for(j=0;j<oserver_data->item_value->nelts;j++){
            oitem_value = oitem_values[j];
            if(oitem_value->item->name.len == item_name.len &&
                ngx_strncmp(oitem_value->item->name.data,item_name.data,item_name.len) == 0){
                found_flag = 1;
                break;
            }
        }
        
        nitem_values = server_data->item_value->elts;
        for(j=0;j<server_data->item_value->nelts;j++){
            nitem_value = nitem_values[j];
            if(nitem_value->item->name.len == item_name.len &&
                ngx_strncmp(nitem_value->item->name.data,item_name.data,item_name.len) == 0){
                return NGX_OK;
            }
        }
        
        if(found_flag == 1){
            item_valuep = ngx_array_push(server_data->item_value);
            if(item_valuep == NULL){
                ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Push item value into server data error");
                return NGX_ERROR;
            }
            *item_valuep = oitem_value;
            shpool->data = oitem_value;
            return NGX_OK;
        }
        goto init_item_value;
    }
    
    if(shm_zone->shm.exists) {
        item_value = (ngx_snmp_item_value_t *)shpool->data;
        nitem_values = server_data->item_value->elts;
        for(j=0;j<server_data->item_value->nelts;j++){
            nitem_value = nitem_values[j];
            if(nitem_value->item->name.len == item_name.len &&
                ngx_strncmp(nitem_value->item->name.data,item_name.data,item_name.len) == 0){
                return NGX_OK;
            }
        }

        item_valuep = ngx_array_push(server_data->item_value);
        if(item_valuep == NULL){
            ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Push item value into server data error");
            return NGX_ERROR;
        }
        *item_valuep = item_value;
        shpool->data = item_value;
        
        return NGX_OK;
    }
    
    goto init_item_value;

init_item_value:    
    item_value = ngx_slab_alloc(shpool,sizeof(ngx_snmp_item_value_t));
    if(item_value == NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Alloc slab  share memory for item value error");
        return NGX_ERROR;
    }
    
    item_valuep = ngx_array_push(server_data->item_value);
    if(item_valuep == NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Push item value into server data error");
        return NGX_ERROR;
    }
    
    *item_valuep = item_value;
    shpool->data = item_value;
    item_value->shm_zone = shm_zone;
    
    item_value->item = sci;
    item_value->group = scg;
    item_value->server = server_data->server;
    item_value->uscf = server_data->uscf;
    item_value->server_data = server_data;
    item_value->sent_sn = 0;
    item_value->error_sn = 0;
    item_value->received_sn = 0;
    item_value->last_value = 0;
    item_value->last_updatetime = 0;
    item_value->last_stats = 0;
    item_value->value = 0;
    item_value->updatetime = 0;
    item_value->stats = 0;
    item_value->error_count = 0;
    item_value->pdu_handler = server_data->pdu_handler;
    a_object_session = ngx_array_create(server_data->pool,1,sizeof(ngx_snmp_core_object_session_t));
    if((item_value->object_session = a_object_session) == NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Create array for object session  error");
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_snmp_http_control_get_item_name_from_shmname(ngx_str_t shmname,ngx_str_t *item_name){
    u_char                      *shm_data;
    ngx_int_t                   i;
    
    shm_data = shmname.data;
    for(i=shmname.len;i>0; i--){
        if(shm_data[(i-1)] == '-'){
            item_name->data = &shm_data[i];
            item_name->len = shmname.len - i + 1;
            return NGX_OK;
        }
    }
    
    return NGX_ERROR;
}

static ngx_int_t
ngx_snmp_http_control_content_handler(ngx_http_request_t *r){
    ngx_snmp_http_control_loc_conf_t                        *shclcf;
    ngx_http_upstream_srv_conf_t                            *us;
    ngx_http_upstream_server_t                              *upsvrs;
     ngx_uint_t                                             i,nelts;
    ngx_http_upstream_srv_conf_t                            *uscf, **uscfp;
    ngx_http_upstream_main_conf_t                           *umcf;
    
    
    shclcf = ngx_http_get_module_loc_conf(r,ngx_snmp_http_control_module);
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "This is runing");
    
    us = shclcf->uscf;
    upsvrs = us->servers->elts;
    nelts = us->servers->nelts;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    
    uscfp = umcf->upstreams.elts;
    nelts = umcf->upstreams.nelts;
    for(i=0;i<nelts;i++){
        uscf = uscfp[i];
        uscf->peer.init = ngx_snmp_http_upstream_init_round_robin_peer;
    }
    shclcf->org_http_handler(r);
    return NGX_OK;
}

  
ngx_int_t
ngx_snmp_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us){
    ngx_http_upstream_rr_peer_data_t                        *rrp;
    ngx_http_upstream_rr_peer_t                             *peer;
    ngx_http_upstream_rr_peers_t                            *peers;
    ngx_uint_t                                              i,j,n;        
    uintptr_t                                               m;
    ngx_snmp_http_control_loc_conf_t                        *shclcf;
    ngx_snmp_core_upstream_group_t                          *scug; 
    ngx_snmp_core_server_data_t                             *scsds,scsd;
    ngx_http_upstream_server_t                              *upstream_server;
    
    if(ngx_http_upstream_init_round_robin_peer(r,us) != NGX_OK){
        return NGX_ERROR;
    }
    
    shclcf = ngx_http_get_module_loc_conf(r,ngx_snmp_http_control_module);
    if(shclcf == NULL){
        return NGX_ERROR;
    }
    scug = shclcf->scug;
    scsds = scug->server_data->elts;
    
    rrp = r->upstream->peer.data;
    peers = rrp->peers;
    ngx_http_upstream_rr_peers_wlock(peers);
    if (peers->single) {
        peer = peers->peer; 
        for(j=0;j<scug->server_data->nelts;j++){
            scsd = scsds[j];
            upstream_server = (ngx_http_upstream_server_t *)scsd.server;
            if(peer->name.len == scsd.name.len  
                        && ngx_strncmp(peer->name.data,scsd.name.data,peer->name.len) == 0
                        && peer->socklen == scsd.addrs->socklen
                        && peer->sockaddr == scsd.addrs->sockaddr){
                peer->down = scsd.unhealthy;
            }
        }
    }
    else{
        for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }
            for(j=0;j<scug->server_data->nelts;j++){
                scsd = scsds[j];
                upstream_server = (ngx_http_upstream_server_t *)scsd.server;
                if(peer->name.len == scsd.name.len  
                        && ngx_strncmp(peer->name.data,scsd.name.data,peer->name.len) == 0
                        && peer->socklen == scsd.addrs->socklen
                        && peer->sockaddr == scsd.addrs->sockaddr){
                    peer->down = scsd.unhealthy;
                }
            }
        }
    }
    
    ngx_http_upstream_rr_peers_unlock(peers);
    
    return NGX_OK;
}
