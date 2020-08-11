/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp.h"
//ngx_rbtree_t                            *ngx_snmp_event_timer_rbtree;
//static ngx_rbtree_node_t                ngx_snmp_event_timer_sentinel;
extern volatile  ngx_msec_t             ngx_current_msec;
//extern ngx_int_t                        ngx_last_process;
//extern ngx_process_t                    ngx_processes[NGX_MAX_PROCESSES];
//ngx_log_t                               *cycle_log; 
//static ngx_event_t                      ngx_snmp_send_pdu_event;
//static ngx_connection_t                 dumb;

ngx_snmp_version_t snmp_versions[] = {
    {SNMP_VERSION_1,ngx_string("1")},
    {SNMP_VERSION_2,ngx_string("2")},
    {SNMP_VERSION_2C,ngx_string("2c")},
    {SNMP_VERSION_3,ngx_string("3")}
};


static char *
ngx_snmp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *
ngx_snmp_merge_item(ngx_conf_t *cf, ngx_snmp_core_group_t *group_conf,ngx_uint_t m);
static char *
ngx_snmp_initate_phase(ngx_conf_t *cf,ngx_snmp_core_main_conf_t *cmcf);
static ngx_int_t 
ngx_snmp_init_process(ngx_cycle_t *cycle);
static ngx_snmp_core_group_t *
ngx_snmp_getGroupByNameFromMain(ngx_snmp_core_main_conf_t *scmcf,ngx_str_t group_name);
static ngx_http_upstream_srv_conf_t *
ngx_snmp_getUpstreamSrvFromMain(ngx_http_upstream_main_conf_t *upmcf,ngx_str_t upstream_name);
static ngx_int_t
ngx_snmp_initate_server_data(ngx_cycle_t *cycle,ngx_snmp_core_group_t *scg,
        ngx_http_upstream_srv_conf_t *upsvr,ngx_snmp_core_upstream_group_t *scug);
static ngx_int_t
ngx_snmp_initate_object_session(ngx_cycle_t *cycle,ngx_snmp_core_item_t *scis,ngx_snmp_item_value_t *item_value);
static ngx_int_t
ngx_snmp_initate_object_pdus(ngx_cycle_t *cycle,ngx_snmp_core_object_session_t *oss);
static ngx_int_t 
ngx_snmp_call_phase_handler(ngx_int_t phase, ngx_snmp_core_object_session_t *oss);
//static ngx_int_t
//ngx_snmp_process_timer_for_server(ngx_snmp_core_server_data_t  *server_data); 
ngx_int_t
ngx_snmp_initate_timer_for_server(ngx_snmp_core_server_data_t  *server_data);
//static void 
//ngx_snmp_start_send_data_for_server(ngx_snmp_core_server_data_t *server_data);
static ngx_int_t
ngx_snmp_insert_server_data_into_timer_queue(ngx_snmp_core_server_data_t  *server_data);
//static ngx_int_t
//ngx_snmp_handle_object_session_error(ngx_snmp_core_object_session_t *oss);
//static ngx_int_t
//ngx_snmp_check_server_if_down(ngx_snmp_core_server_data_t  *server_data);
//static ngx_int_t
//ngx_snmp_get_peer(ngx_peer_connection_t *pc, void *data);
//static void
//ngx_snmp_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state);
//static void
//ngx_snmp_oss_recv(ngx_event_t *rev);
//static void
//ngx_snmp_oss_dummy_send(ngx_event_t *wev);
//ngx_int_t
//ngx_snmp_event_timer_init(ngx_log_t *log);
//static ngx_int_t 
//ngx_snmp_start_timer(ngx_log_t  *log);
//static void
//ngx_snmp_send_query_event_handler(ngx_event_t *ev);
//static void 
//ngx_snmp_exit_process(ngx_cycle_t *cycle);


static ngx_core_module_t  ngx_snmp_module_ctx = {
    ngx_string("snmp"),
    NULL,
    NULL
};

static ngx_command_t  ngx_snmp_commands[] = {

    { ngx_string("snmp"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_snmp_block,
      0,
      0,
      NULL },

      ngx_null_command
};

ngx_module_t  ngx_snmp_module = {
    NGX_MODULE_V1,
    &ngx_snmp_module_ctx,                  /* module context */
    ngx_snmp_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_snmp_init_process,                 /* init process  */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                 /* exit process  ngx_snmp_exit_process*/
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



static char *
ngx_snmp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_snmp_conf_ctx_t         *ctx;
    ngx_uint_t                  m, mi, s;
    ngx_module_t                **modules;
    ngx_snmp_module_t           *module;
    ngx_conf_t                   pcf;
    ngx_snmp_core_group_t        **cgcfp;
    ngx_snmp_core_main_conf_t   *cmcf;
    
    
    
    
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_snmp_conf_ctx_t **) conf = ctx;

#if (nginx_version >= 1009011)

    ngx_snmp_max_module = ngx_count_modules(cf->cycle, NGX_SNMP_MODULE);

#else

    ngx_snmp_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_SNMP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_snmp_max_module++;
    }

#endif

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_snmp_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->group_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_snmp_max_module);
    if (ctx->group_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->item_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_snmp_max_module);
    if (ctx->item_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->object_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_snmp_max_module);
    if (ctx->object_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif
    
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_SNMP_MODULE) {
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
        
        if (module->create_group_conf) {
            ctx->group_conf[mi] = module->create_group_conf(cf);
            if (ctx->group_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        
        if (module->create_item_conf) {
            ctx->item_conf[mi] = module->create_item_conf(cf);
            if (ctx->item_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        
        if (module->create_object_conf) {
            ctx->object_conf[mi] = module->create_object_conf(cf);
            if (ctx->object_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        
    }
    
    pcf = *cf;
    cf->ctx = ctx;
    
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_SNMP_MODULE) {
            continue;
        }

        module = modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }
    
    cf->module_type = NGX_SNMP_MODULE;
    cf->cmd_type = NGX_SNMP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);
    
    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }
    
    cmcf = ctx->main_conf[ngx_snmp_core_module.ctx_index];
    cgcfp = cmcf->groups.elts;
   
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_SNMP_MODULE) {
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
        
        for (s = 0; s < cmcf->groups.nelts; s++) {
            
            cf->ctx = cgcfp[s]->ctx;
            
            if (module->merge_group_conf) {
                rv = module->merge_group_conf(cf,
                                            ctx->group_conf[mi],
                                            cgcfp[s]->ctx->group_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
            
            if (module->merge_item_conf) {
                rv = ngx_snmp_merge_item(cf,cgcfp[s]->ctx->group_conf[mi],m);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
            
        }
    }
    
    cmcf = ctx->main_conf[ngx_snmp_core_module.ctx_index];
    if(ngx_snmp_initate_phase(cf,cmcf) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_SNMP_MODULE) {
            continue;
        }

        module = modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }
    
    return NGX_CONF_OK;
}

static char *
ngx_snmp_merge_item(ngx_conf_t *cf, ngx_snmp_core_group_t *group_conf,ngx_uint_t m)
{
    ngx_module_t                **modules;
    ngx_snmp_module_t           *module;
    ngx_uint_t                  mi,i,j;
    ngx_snmp_core_item_t        **scicfp,*scicf;
    ngx_snmp_core_object_t      **scocfp,*scocf;
    ngx_snmp_conf_ctx_t         *ctx,*obj_ctx; 
    char                        *rv;
    
    
#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif
    
    module = modules[m]->ctx;
    mi = modules[m]->ctx_index;
    
    
    scicfp = group_conf->items.elts;
    for(i=0;i<group_conf->items.nelts;i++){
        scicf = scicfp[i];
        ctx = scicf->ctx;
        if (module->merge_item_conf){
            rv = module->merge_item_conf(cf,group_conf,scicf,mi);
            if (rv != NGX_CONF_OK) 
            {
                return rv; 
            }
        }
        if (module->merge_object_conf)
        {
            scocfp = scicf->objects.elts;
            for(j=0;j<scicf->objects.nelts;j++){
                scocf = scocfp[j];
                obj_ctx = scocf->ctx;
                rv = module->merge_object_conf(cf,obj_ctx->item_conf[mi],scocf,mi);
                if (rv != NGX_CONF_OK) 
                {
                    return rv; 
                }
            }
        }
    }
    
    return NGX_CONF_OK; 
    
}

static char *
ngx_snmp_initate_phase(ngx_conf_t *cf,ngx_snmp_core_main_conf_t *cmcf)
{
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_BUILD_REQUESTID_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_BUILD_HEAD_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_BUILD_REQUESTPDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_BUILD_FINISHPDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PRESEND_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_SENT_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PRERECEIVE_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_RECEIVEED_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PREPARSE_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PARSE_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PARSED_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PARSED_PDU_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_PRECONTROL_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_BUILD_RESPONSE_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_CONTROL_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if(ngx_array_init(&cmcf->phases[NGX_SNMP_LOG_PHASE].handlers,cf->pool,
            1,sizeof(ngx_snmp_phase_handler_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_snmp_init_process(ngx_cycle_t *cycle)
{
    ngx_snmp_core_main_conf_t               *scmcf;
    ngx_http_upstream_main_conf_t           *upmcf;
    ngx_http_upstream_srv_conf_t            *upsvr;
    ngx_snmp_core_upstream_group_t          *scugs,scug;
    ngx_str_t                               upstream_name,group_name;
    ngx_uint_t                              i;
    ngx_snmp_core_group_t                   *scg; 
   // ngx_slab_pool_t                         *shpool;
   // ngx_snmp_timer_start_status_t           *start_status;
    
  //  dumb.fd = (ngx_socket_t) -1;
  //  ngx_memzero(&ngx_snmp_send_pdu_event, sizeof(ngx_event_t));

  //  ngx_snmp_send_pdu_event.handler = ngx_snmp_send_query_event_handler;
  //  ngx_snmp_send_pdu_event.log = cycle->log;
  //  ngx_snmp_send_pdu_event.data = &dumb;
   // ngx_add_timer(&ngx_snmp_send_pdu_event, 1000);
    //dumb.fd = (ngx_socket_t) -1;
   // if (!ngx_snmp_send_pdu_event.timer_set) {
    //    ngx_add_timer(&ngx_snmp_send_pdu_event, 1000);
    //    ngx_snmp_send_pdu_event.timer_set = 1;
  //  }
    
    scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(cycle,ngx_snmp_core_module);
    if(scmcf == NULL)
    {
        ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Can not get SNMP module main conf");
        return NGX_ERROR;
    }
   /*
    shpool = (ngx_slab_pool_t *) scmcf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    shscmcf = scmcf->shm_zone->data;
    start_status = shscmcf->start_status;
   
    if(start_status->is_start){
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }
    start_status->is_start = 1; 
    start_status->pid = ngx_getpid();
    ngx_shmtx_unlock(&shpool->mutex);
    
    ngx_snmp_event_timer_rbtree = &scmcf->snmp_rbtree;
    ngx_snmp_event_timer_init(cycle->log);
    */
    
    scugs = scmcf->upstream_group.elts;
    upmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_module);
    if(upmcf == NULL)
    {
        ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Can not get UPSTREAM module main conf");
        return NGX_ERROR;
    }
    
    for(i=0;i<scmcf->upstream_group.nelts;i++)
    {
        scug = scugs[i];
        upstream_name = scug.upstream_name;
        group_name = scug.group_name;
        scg = ngx_snmp_getGroupByNameFromMain(scmcf,group_name);
        if(scg ==  NULL){
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "The group you specified by snmp_upstream was not found");
            return NGX_ERROR;
        }
        scug.group = scg; 
        
        upsvr = ngx_snmp_getUpstreamSrvFromMain(upmcf,upstream_name);
        if(upsvr ==  NULL){
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "The upstream you specified by snmp_upstream was not found");
            return NGX_ERROR;
        }
        scug.uscf = upsvr;
        if(ngx_snmp_initate_server_data(cycle,scg,upsvr,&scug) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    /*
    if(ngx_snmp_start_timer(cycle->log) != NGX_OK)
    {
        return NGX_ERROR;
    }
    */
    return NGX_OK;
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
        if(ngx_strncmp(upsvr->host.data,upstream_name.data,upstream_name.len) == 0)
        {
            return upsvr;
        }
    }
    
    return NULL; 
    
    
}

static ngx_int_t 
ngx_snmp_initate_server_data(ngx_cycle_t *cycle,ngx_snmp_core_group_t *scg,
        ngx_http_upstream_srv_conf_t *upsvr,ngx_snmp_core_upstream_group_t *scug)
{
    ngx_uint_t                                       i,j,k;
    ngx_http_upstream_server_t                       *svrs,svr;
    ngx_snmp_core_item_t                             **scis,*sci;
    ngx_snmp_core_server_data_t                      *server_data;
    ngx_snmp_item_value_t                            *item_value;
    ngx_array_t                                      *a_item_value,*a_object_session;
    
    svrs = upsvr->servers->elts;
    scis = scg->items.elts;
    
    for(i=0;i<upsvr->servers->nelts;i++){
        svr = svrs[i];
        for(k=0;k<svr.naddrs;k++)
        {
            server_data = ngx_array_push(scug->server_data);
            if(server_data == NULL)
            {
                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Initate server data error");
                return NGX_ERROR;
            }
            server_data->addrs = ngx_pcalloc(cycle->pool, sizeof(ngx_addr_t));
            if(server_data->addrs == NULL)
            {
                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Create memory for addrs error");
                return NGX_ERROR;
            }
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
            server_data->pool = cycle->pool;
            server_data->log = cycle->log;
            server_data->cycle = cycle;
            server_data->pdu_handler = &scg->pdu_handler;
            server_data->snmp_addrs = ngx_pcalloc(cycle->pool, sizeof(ngx_addr_t));
            if(server_data->snmp_addrs ==  NULL)
            {
                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Create memory for snmp addr error");
                return NGX_ERROR;
            }
        
            a_item_value = ngx_array_create(cycle->pool, 1,sizeof(ngx_snmp_item_value_t));
            if ((server_data->item_value = a_item_value) == NULL)
            {
                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Create array for item value error");
                return NGX_ERROR;
            }
            for(j=0;j<scg->items.nelts;j++)
            {
                sci = scis[j];
                item_value = ngx_array_push(server_data->item_value);
                if(item_value == NULL)
                {
                    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Push item value error");
                    return NGX_ERROR;
                }
                item_value->item = sci;
                item_value->group = scg;
                item_value->server = &svr;
                item_value->uscf = upsvr;
                item_value->server_data = server_data;
                item_value->sent_sn = 0;
                item_value->error_sn = 0;
                item_value->received_sn = 0;
                item_value->last_value = 0;
                item_value->last_updatetime = 0;
                item_value->last_stats = 0;
                item_value->value = 0;
                item_value->updatetime = 0;
                item_value->error_count = 0;
                item_value->pdu_handler = server_data->pdu_handler;
                a_object_session = ngx_array_create(cycle->pool,1,sizeof(ngx_snmp_core_object_session_t));
                if((item_value->object_session = a_object_session) == NULL)
                {
                    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Create array for object session  error");
                    return NGX_ERROR;
                }
                if(ngx_snmp_initate_object_session(cycle,sci,item_value) != NGX_OK)
                {
                    return NGX_ERROR;
                }   
            }
            if(ngx_snmp_initate_timer_for_server(server_data) != NGX_OK){
                return NGX_ERROR; 
            }
        }
    }
    return NGX_OK; 
}

static ngx_int_t 
ngx_snmp_initate_object_session(ngx_cycle_t *cycle,ngx_snmp_core_item_t *scis,ngx_snmp_item_value_t *item_value)
{
    ngx_uint_t                                 i;
    ngx_int_t                                  ret;
    ngx_snmp_core_object_t                     **scocfs,*scocf;
    ngx_snmp_core_object_session_t             *oss;
    ngx_snmp_core_group_t                      *scg;
    ngx_snmp_pdu_handler_t                      pdu_handler; 
    ngx_snmp_handler_pt                         handler;
    ngx_snmp_conf_ctx_t                         *object_ctx;
    ngx_str_t                                   *tmp_str;
    
    scocfs = scis->objects.elts;
    for(i=0;i<scis->objects.nelts;i++)
    {
        scocf = scocfs[i];
        object_ctx = scocf->ctx;
        oss = ngx_array_push(item_value->object_session);
        if(oss == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Push object session error");
            return NGX_ERROR;
        }
        
        oss->core_object = scocf;
        oss->server_data = item_value->server_data;
        oss->item_value = item_value;
        oss->pool = ngx_create_pool(SNMP_POOL_SIZE,cycle->log);
        if(oss->pool == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Create pool for object session  error");
            return NGX_ERROR;
        }
        if((tmp_str= ngx_palloc(oss->pool,sizeof(ngx_str_t))) == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for send buffer error");
            return NGX_ERROR;
        }
        oss->send_buf= *tmp_str;
        oss->send_buf.data = ngx_alloc(sizeof(u_char) * SNNP_BUFFER_LENGTH,oss->pool->log);
        oss->pdu_handler = item_value->pdu_handler;
        if(oss->send_buf.data == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for send buffer error");
            return NGX_ERROR;
        }
        oss->send_buf.len = 0;
        if((tmp_str= ngx_palloc(oss->pool,sizeof(ngx_str_t))) == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for receive buffer error");
            return NGX_ERROR;
        }
        oss->recv_buf = *tmp_str;
        oss->recv_buf.data = ngx_alloc(sizeof(u_char) * SNNP_BUFFER_LENGTH,oss->pool->log);
        if(oss->recv_buf.data == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for receive buffer error");
            return NGX_ERROR;
        }
        oss->recv_buf.len = 0;
        if((tmp_str= ngx_palloc(oss->pool,sizeof(ngx_str_t))) == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for tmp_buf buffer error");
            return NGX_ERROR;
        }
        oss->tmp_buf = *tmp_str;
        oss->tmp_buf.data =  ngx_alloc( sizeof(u_char) * SNNP_BUFFER_LENGTH,oss->pool->log);
        if(oss->tmp_buf.data == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for temp buffer error");
            return NGX_ERROR;
        }
        oss->tmp_buf.len = 0;
        oss->last_value = 0;
        oss->last_updatetime = 0;
        oss->last_stats = 0; 
        oss->sent_sn = 0;
        oss->received_sn = 0;
        oss->value = 0;
        oss->updatetime = 0;
        oss->error_count = 0;
        oss->connection = NULL;
        oss->pc = ngx_palloc(oss->pool, sizeof(ngx_peer_connection_t));
        if(oss->pc == NULL)
        {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Alloc memory for PC error");
            return NGX_ERROR;
        }
        oss->pc->name = NULL;
        oss->main_conf = (void **)object_ctx->main_conf;
        oss->group_conf = (void **)object_ctx->group_conf;
        oss->item_conf = (void **)object_ctx->item_conf;
        oss->object_conf = (void **)object_ctx->object_conf;
        if(ngx_snmp_initate_object_pdus(cycle,oss) != NGX_OK)
        {
            return NGX_ERROR;
        }
        scg = ngx_snmp_get_module_group_conf(oss,ngx_snmp_core_module);
        pdu_handler = scg->pdu_handler;
        handler = pdu_handler.request_hanlder;
        if(handler != NGX_CONF_UNSET_PTR)
        {
            ret = (*handler)(oss);
            if(ret != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        
        handler = pdu_handler.requid_handler;
        if(handler != NGX_CONF_UNSET_PTR)
        {
            ret = (*handler)(oss);
            if(ret != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        
        handler = pdu_handler.head_handler;
        if(handler != NGX_CONF_UNSET_PTR)
        {
            ret = (*handler)(oss);
            if(ret != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        
        handler = pdu_handler.finish_pdu_hander;
        if(handler != NGX_CONF_UNSET_PTR)
        {
            ret = (*handler)(oss);
            if(ret != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_snmp_initate_object_pdus(ngx_cycle_t *cycle,ngx_snmp_core_object_session_t *oss)
{
    ngx_snmp_core_main_conf_t                  *scmcf; 
    
    scmcf = ngx_snmp_get_module_main_conf(oss,ngx_snmp_core_module);
    if(scmcf->phases[NGX_SNMP_BUILD_REQUESTID_PHASE].handlers.nelts > 0)
    {
        if(ngx_snmp_call_phase_handler(NGX_SNMP_BUILD_REQUESTID_PHASE,oss) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Ocured a error when execute NGX_SNMP_BUILD_REQUESTID_PHASE handler while initating object PDU  ");
            return NGX_ERROR;
        }
    }
    
    if(scmcf->phases[NGX_SNMP_BUILD_HEAD_PHASE].handlers.nelts > 0)
    {
        if(ngx_snmp_call_phase_handler(NGX_SNMP_BUILD_HEAD_PHASE,oss) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Ocured a error when execute NGX_SNMP_BUILD_HEAD_PHASE handler while initating object PDU  ");
            return NGX_ERROR;
        }
    }
    
    if(scmcf->phases[NGX_SNMP_BUILD_REQUESTPDU_PHASE].handlers.nelts > 0)
    {
        if(ngx_snmp_call_phase_handler(NGX_SNMP_BUILD_REQUESTPDU_PHASE,oss) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Ocured a error when execute NGX_SNMP_BUILD_REQUESTPDU_PHASE handler while initating object PDU  ");
            return NGX_ERROR;
        }
    }
    
    if(scmcf->phases[NGX_SNMP_BUILD_FINISHPDU_PHASE].handlers.nelts > 0)
    {
        if(ngx_snmp_call_phase_handler(NGX_SNMP_BUILD_FINISHPDU_PHASE,oss) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Ocured a error when execute NGX_SNMP_BUILD_FINISHPDU_PHASE handler while initating object PDU  ");
            return NGX_ERROR;
        }
    }
    
    return NGX_OK;
}

static ngx_int_t 
ngx_snmp_call_phase_handler(ngx_int_t phase, ngx_snmp_core_object_session_t *oss)
{
    ngx_snmp_core_main_conf_t                  *scmcf; 
    ngx_snmp_phase_handler_t                   *phase_handlers;
    ngx_uint_t                                  i;
    ngx_int_t                                   ret,flag;
    ngx_snmp_handler_pt                         handler;
    
    scmcf = ngx_snmp_get_module_main_conf(oss,ngx_snmp_core_module);
    if(scmcf->phases[phase].handlers.nelts > 0)
    {
        phase_handlers = scmcf->phases[phase].handlers.elts;
        for(i=0;i<scmcf->phases[phase].handlers.nelts;i++)
        {
            flag = 0;
            handler = phase_handlers[i].handler;
            ret = (*handler)(oss);
            switch(ret)
            {
                case NGX_OK:
                    continue;
                    break;
                case NGX_ERROR:
                    flag = 1; 
                    ret = NGX_ERROR;
                    break; 
                case NGX_AGAIN:
                    continue;
                    break;
                case NGX_DECLINED:
                    flag = 1; 
                    ret = NGX_OK;
                    break;
                case NGX_DONE:
                    ret = NGX_OK;
                    flag = 1;
                    break; 
                default:
                    ret = NGX_ERROR;
                    flag = 1;
                    break;
            }
            if(flag == 1)
            {
                break;
            }
        }
    }
    else
    {
        ret = NGX_OK;
    }
    
    return ret;
}

ngx_int_t 
ngx_snmp_build_integer(ngx_int_t value, u_char *buf)
{
    ngx_int_t           len;
    
    len = 0;
    if(value < 0x80){
        buf[len++] = value;
    }
    else if(value < 0x4000){
        buf[len++] = ((value >> 7) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    else if (value < 0x200000) {
        buf[len++] = ((value >> 14) | 0x80);
        buf[len++] = ((value >> 7 & 0x7f) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    else if (value < 0x10000000 ) {
        buf[len++] = ((value >> 21) | 0x80);
        buf[len++] = ((value >> 14 & 0x7f) | 0x80);
        buf[len++] = ((value >> 7 & 0x7f) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    else{
        buf[len++] = ((value >> 28) | 0x80);
        buf[len++] = ((value >> 21 & 0x7f) | 0x80);
        buf[len++] = ((value >> 14 & 0x7f) | 0x80);
        buf[len++] = ((value >> 7 & 0x7f) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    return len;
}


static ngx_int_t
ngx_snmp_insert_server_data_into_timer_queue(ngx_snmp_core_server_data_t  *server_data)
{
   ngx_snmp_server_data_queue_t                     *server_data_queue;
   ngx_snmp_core_main_conf_t                        *scmcf;
   
   
   server_data_queue = ngx_palloc(server_data->pool, sizeof(ngx_snmp_server_data_queue_t));
   if(server_data_queue ==  NULL)
   {
       ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Initate server data queue for server: \"%V\" error",&server_data->name);
       return NGX_ERROR;
   }
   
   server_data_queue->server_data = server_data;
   
   scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(server_data->cycle,ngx_snmp_core_module);
   if(scmcf == NULL)
   {
        ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Can not get SNMP module main conf");
        return NGX_ERROR;
   }
   
   ngx_queue_insert_tail(&scmcf->server_data_queue,&server_data_queue->queue);
   
   return NGX_OK; 
    
}

/*
static void 
ngx_snmp_start_send_data_for_server(ngx_snmp_core_server_data_t *server_data)
{
    //ngx_snmp_core_server_data_t                            *server_data; 
    ngx_peer_connection_t                                  *pc;
    ngx_snmp_core_group_t                                  *scg;
    ngx_array_t                                            *ar_item,*ar_oss;
    ngx_snmp_item_value_t                                  *sivp,siv;
    ngx_snmp_core_object_session_t                         *ossp,oss;
    ngx_uint_t                                             i,j,error_item_count;
    ngx_connection_t                                       *c;
    ngx_int_t                                              rc,send_sn,error_flag,ret;
    ngx_snmp_pdu_handler_t                                 pdu_handler; 
    ngx_snmp_handler_pt                                    handler;
    
    //server_data = ev->data;
    ar_item = server_data->item_value;
    sivp = ar_item->elts;
    send_sn = (ngx_int_t)ngx_time();
    error_item_count = 0; 
    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Now starting send SNMP PDUs to Server : \"%V\"",&server_data->name);
    for(i=0;i<ar_item->nelts;i++)
    {
        siv = sivp[i];
        error_flag = 0;
        siv.sent_sn = send_sn;
        siv.updatetime = (ngx_int_t)ngx_time();
        ar_oss = siv.object_session;
        ossp =  ar_oss->elts;
        ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Now starting send SNMP PDUs on Item : \"%V\" to Server : \"%V\"",&server_data->name,&siv.item->name);
        for(j=0;j<ar_oss->nelts;j++)
        {
            oss = ossp[j];
            oss.sent_sn = send_sn;
            pc = oss.pc;
            c = pc->connection;
            if(c->fd == (ngx_socket_t) -1)
            {                
                if(pc->name == NULL)
                {
                    pc->name = &server_data->snmp_addrs->name;
                    pc->local = NULL;
                    pc->sockaddr = server_data->snmp_addrs->sockaddr;
                    pc->socklen = server_data->snmp_addrs->socklen;
                    pc->log = server_data->log;
                    pc->data = server_data;
                    pc->get = ngx_snmp_get_peer;
                    pc->free = ngx_snmp_free_peer;
                    pc->type = SOCK_DGRAM;
                }
                rc = ngx_event_connect_peer(pc);
                if (rc != NGX_OK && rc != NGX_AGAIN )
                {
                    ngx_log_error(NGX_LOG_EMERG,server_data->log, 0,"Create snmp connection to server: \"%V\" failed",&server_data->name);
                    ngx_snmp_check_server_if_down(server_data);
                    return;
                }
            }
            c = pc->connection;
            c->data = &oss;
            c->pool = oss.pool;
            c->read->handler = ngx_snmp_oss_recv;
            c->write->handler = ngx_snmp_oss_dummy_send;
            scg = ngx_snmp_get_module_group_conf(&oss,ngx_snmp_core_module);
            pdu_handler = scg->pdu_handler;
            handler = pdu_handler.request_hanlder;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(&oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(&oss);
                    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Call request handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
        
            handler = pdu_handler.requid_handler;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(&oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(&oss);
                    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Call requid handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
            
            handler = pdu_handler.head_handler;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(&oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(&oss);
                    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Call head handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
        
            handler = pdu_handler.finish_pdu_hander;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(&oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(&oss);
                    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Call finish handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
            if(c->send(c,oss.send_buf.data,oss.send_buf.len) <(ssize_t)(oss.send_buf.len))
            {
                ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Sent request PDU to  Server: \"%V\" error",&server_data->name);
                ngx_snmp_handle_object_session_error(&oss);
                error_flag = 1;
                if(c->read->timer_set)
                {
                    ngx_del_timer(c->read);
                }
                break;
            }
        }
        if(error_flag == 1)
        {
            error_item_count++;
            siv.value = -1;
        } 
    }
    if(error_item_count >= ar_item->nelts)
    {
        server_data->error_count++;
        ngx_snmp_check_server_if_down(server_data);
    }
    
    
    return ;
    
}
*/

ngx_int_t
ngx_snmp_initate_timer_for_server(ngx_snmp_core_server_data_t  *server_data)
{
    ngx_str_t                               server_name; 
    u_char                                  *p;
    size_t                                  len;
    ngx_str_t                               *server_addr;
    struct sockaddr_in                      *sin;
    
    server_name = server_data->name;
    p = server_name.data;
    len =  server_name.len;
    
    if (len >= 5 && ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        server_addr = ngx_pcalloc(server_data->pool, sizeof(ngx_str_t));
        if(server_addr ==  NULL){
            return NGX_ERROR;
        }
        ngx_str_set(server_addr, "127.0.0.1");
        server_data->name.data = server_addr->data;
        server_data->name.len = server_addr->len;
        sin = ngx_pcalloc(server_data->pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = ngx_inet_addr(p, len);
        server_data->snmp_addrs[0].sockaddr = (struct sockaddr *)sin;
        server_data->snmp_addrs[0].socklen = sizeof(struct sockaddr_in);
        server_data->snmp_addrs->name = server_name;
        server_data->family = AF_INET;
    }
    else
    {
        if (len && p[0] == '[') {
            server_data->family = AF_INET6;
            server_data->snmp_addrs->sockaddr = ngx_pcalloc(server_data->pool, server_data->addrs->socklen);
            if (server_data->snmp_addrs->sockaddr == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(server_data->snmp_addrs[0].sockaddr,server_data->addrs[0].sockaddr,server_data->addrs[0].socklen);
            server_data->snmp_addrs[0].socklen = server_data->addrs[0].socklen;
            server_data->snmp_addrs->name = server_name;
        }
        else
        {
            server_data->family = AF_INET;
            server_data->snmp_addrs->sockaddr = ngx_pcalloc(server_data->pool, server_data->addrs->socklen);
            if (server_data->snmp_addrs->sockaddr == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(server_data->snmp_addrs[0].sockaddr,server_data->addrs[0].sockaddr,server_data->addrs[0].socklen);
            server_data->snmp_addrs[0].socklen = server_data->addrs[0].socklen;
            server_data->snmp_addrs->name = server_name;
        }
    }
    
    return(ngx_snmp_insert_server_data_into_timer_queue(server_data));
  //  return NGX_OK;
}

/*
static ngx_int_t
ngx_snmp_handle_object_session_error(ngx_snmp_core_object_session_t *oss)
{
    ngx_snmp_item_value_t                                   *siv;
    ngx_snmp_core_server_data_t                             *ssd;
    
    siv = oss->item_value;
    ssd = oss->server_data;
    
    oss->value = -1;
    oss->updatetime = (ngx_int_t)ngx_time();
    oss->error_count++;
    oss->last_stats = 1;
    if(siv->error_sn != oss->sent_sn)
    {
        siv->error_sn = oss->sent_sn;
        siv->value = -1;
        siv->updatetime = oss->updatetime;
        siv->error_count++;
    }
    
    return NGX_OK;
}
*/

/*
static ngx_int_t
ngx_snmp_check_server_if_down(ngx_snmp_core_server_data_t  *server_data)
{
    ngx_snmp_core_group_t                                  *scg;
    
    scg = server_data->group;
    server_data->flag = 1;
    server_data->error_count++;
    server_data->last_error_request_id = 0;
    if(server_data->error_count >= scg->fall)
    {
        server_data->down = 1;
        server_data->last_down_time = (ngx_int_t)ngx_time();
        server_data->flag = 1;
        ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Server: \"%V\" has been changed to down because of too many errors",&server_data->name);
    }
    
    return NGX_OK; 
}

static ngx_int_t
ngx_snmp_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}
static void
ngx_snmp_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state)
{
    return; 
}

static void
ngx_snmp_oss_recv(ngx_event_t *rev)
{
    return; 
}

static void
ngx_snmp_oss_dummy_send(ngx_event_t *wev)
{
    return;
}

ngx_int_t
ngx_snmp_event_timer_init(ngx_log_t *log)
{
    ngx_rbtree_init(ngx_snmp_event_timer_rbtree, &ngx_snmp_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

    return NGX_OK;
}


static ngx_int_t 
ngx_snmp_start_timer(ngx_log_t  *log)
{

    ngx_snmp_send_pdu_event.handler = ngx_snmp_send_query_event_handler;
    ngx_snmp_send_pdu_event.log = log;
    ngx_snmp_send_pdu_event.data = &dumb;
    dumb.fd = (ngx_socket_t) -1;
    if (!ngx_snmp_send_pdu_event.timer_set) {
        ngx_add_timer(&ngx_snmp_send_pdu_event, 1000);
        ngx_snmp_send_pdu_event.timer_set = 1;
    }
    
    
    struct sigaction  sa;
    struct itimerval  itv;
    cycle_log = log; 
    
    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = ngx_snmp_timer_signal_handler;
    sigemptyset(&sa.sa_mask);
        
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT,log, ngx_errno,
                    "sigaction(SIGALRM) failed");
            return NGX_ERROR;
    }
        
    itv.it_interval.tv_sec = SNMP_TIMER_INTERVAL;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = SNMP_TIMER_INTERVAL;
    itv.it_value.tv_usec = 0;
        
    if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
            "setitimer() failed");
    }
    
    return NGX_OK;
}

static void
ngx_snmp_send_query_event_handler(ngx_event_t *event)
{
    ngx_rbtree_node_t                       *node, *root, *sentinel;
    ngx_snmp_core_server_data_t             *server_data;
    ngx_event_t                             *ev;
    ngx_snmp_core_main_conf_t               *scmcf,*shscmcf;
    ngx_slab_pool_t                         *shpool;
    ngx_snmp_timer_start_status_t           *start_status;
    
   // if(signo == SIGALRM)
  //  {
  //      ngx_errno = 0;
        
        ngx_log_error(NGX_LOG_DEBUG,cycle_log, ngx_errno,
                    "Catched a SIGALRM");
        sentinel = ngx_snmp_event_timer_rbtree->sentinel;
        for( ;; ) {
            root = ngx_snmp_event_timer_rbtree->root;
            
            if (root == sentinel) {
                return;
            }
            
            node = ngx_rbtree_min(root, sentinel);
            
            if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
                return;
            }
            
            ngx_log_error(NGX_LOG_DEBUG,cycle_log,0,
                    "Get a SNMP query request");
            
            ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));
            server_data = (ngx_snmp_core_server_data_t *)ev->data;
            
            scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(server_data->cycle,ngx_snmp_core_module);
            if(scmcf == NULL)
            {
                ngx_log_error(NGX_LOG_DEBUG, server_data->cycle->log, 0, "Can not get SNMP module main conf");
                return ;
            }
            
            shpool = (ngx_slab_pool_t *) scmcf->shm_zone->shm.addr;
            ngx_shmtx_lock(&shpool->mutex);
            shscmcf = scmcf->shm_zone->data;
            start_status = shscmcf->start_status;
            if(start_status->is_start){
                start_status->is_start = 0; 
                start_status->pid = 0;
            }
            ngx_shmtx_unlock(&shpool->mutex);
            
            ngx_snmp_start_send_data_for_server(server_data);
            
            ngx_rbtree_delete(ngx_snmp_event_timer_rbtree, node);
            
            ngx_snmp_insert_server_data_into_timer_queue(server_data);
        }
  //  }

    return; 
}



static void 
ngx_snmp_exit_process(ngx_cycle_t *cycle)
{
    ngx_snmp_core_main_conf_t               *scmcf,*shscmcf;
    ngx_slab_pool_t                         *shpool;
    ngx_snmp_timer_start_status_t           *start_status;
    
    scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(cycle,ngx_snmp_core_module);
    if(scmcf == NULL)
    {
        ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Can not get SNMP module main conf");
        return ;
    }
    
    shpool = (ngx_slab_pool_t *) scmcf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    shscmcf = scmcf->shm_zone->data;
    start_status = shscmcf->start_status;
    if(start_status->is_start){
        start_status->is_start = 0; 
        start_status->pid = 0;
        
    }
    ngx_shmtx_unlock(&shpool->mutex);
    
    return;
}
*/