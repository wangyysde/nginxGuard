/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp.h"
#include "ngx_snmp_rpn.h"

extern ngx_snmp_version_t snmp_versions[];



static void *
ngx_snmp_core_create_main_conf(ngx_conf_t *cf);
static void *
ngx_snmp_core_create_group_conf(ngx_conf_t *cf);
static void *
ngx_snmp_core_create_item_conf(ngx_conf_t *cf);
static void *
ngx_snmp_core_create_object_conf(ngx_conf_t *cf);
static char *
ngx_snmp_core_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_item(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_object(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_group_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_version(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_direction(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_most(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_snmp_core_express(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_snmp_getObjectNameFromExpress(ngx_str_t value, ngx_str_t *object_name);
static char *
ngx_snmp_core_merge_group_conf(ngx_conf_t *cf, void *prev,void *conf);
static char *
ngx_snmp_core_merge_item_conf(ngx_conf_t *cf, void *pre,void *conf);
static ngx_int_t
ngx_snmp_getNameFromExpress(ngx_str_t value, ngx_str_t *name);
static char *
ngx_snmp_core_merge_object_conf(ngx_conf_t *cf, void *pre,void *conf);
static char *
ngx_snmp_core_initate_object_pdus(ngx_snmp_core_object_t **cocfp,ngx_conf_t *cf);
static ngx_int_t
ngx_snmp_core_init_share_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t 
ngx_snmp_core_post_conf(ngx_conf_t *cf);

ngx_snmp_core_express_fun_handler_t keepworlds[] = {
    {ngx_string("last"),NGX_SNMP_KEYWORD_TYPE_FUN,ngx_snmp_fun_last},
    {ngx_string("change"),NGX_SNMP_KEYWORD_TYPE_FUN,ngx_snmp_fun_change},
    {ngx_string("rate"),NGX_SNMP_KEYWORD_TYPE_FUN,ngx_snmp_fun_rate},
    {ngx_string("interval"),NGX_SNMP_KEYWORD_TYPE_KEYWORD,ngx_snmp_get_keyword_value}
};

static ngx_snmp_module_t  ngx_snmp_core_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_snmp_core_post_conf,                  /* postconfiguration */
    ngx_snmp_core_create_main_conf,           /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_snmp_core_create_group_conf,          /* create server configuration */
    ngx_snmp_core_merge_group_conf,           /* merge server configuration */
    ngx_snmp_core_create_item_conf,           /* create app configuration */
    ngx_snmp_core_merge_item_conf,            /* merge app configuration */
    ngx_snmp_core_create_object_conf,         /* create object configuration */
    ngx_snmp_core_merge_object_conf          /* merge object configuration */
};

static ngx_command_t  ngx_snmp_core_commands[] = {

    { ngx_string("group"),
      NGX_SNMP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_snmp_core_group,
      0,
      0,
      NULL },

    { ngx_string("item"),
      NGX_SNMP_GROUP_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_snmp_core_item,
      0,
      0,
      NULL },
      
    { ngx_string("object"),
      NGX_SNMP_ITEM_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_snmp_core_object,
      0,
      0,
      NULL },
    
    { ngx_string("snmp_upstream"),
      NGX_SNMP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_snmp_core_group_upstream,
      0,
      0,
      NULL },
    
    { ngx_string("snmp_log_level"),
      NGX_SNMP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_snmp_core_log_level,
      0,
      0,
      NULL },
    
    { ngx_string("interval"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SNMP_GROUP_CONF_OFFSET,
      offsetof(ngx_snmp_core_group_t, interval),
      NULL },
      
    { ngx_string("recover_check_interval"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SNMP_GROUP_CONF_OFFSET,
      offsetof(ngx_snmp_core_group_t, recover_check_interval),
      NULL },
      
    { ngx_string("fall"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SNMP_GROUP_CONF_OFFSET,
      offsetof(ngx_snmp_core_group_t, fall),
      NULL },
    
    { ngx_string("version"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_CONF_TAKE1,
      ngx_snmp_core_version,
      NGX_SNMP_GROUP_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("port"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SNMP_GROUP_CONF_OFFSET,
      offsetof(ngx_snmp_core_group_t, port),
      NULL },
    
    { ngx_string("most"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_SNMP_ITEM_CONF|NGX_CONF_TAKE1,
      ngx_snmp_core_most,
      NGX_SNMP_ITEM_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("direction"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_SNMP_ITEM_CONF|NGX_CONF_TAKE1,
      ngx_snmp_core_direction,
      NGX_SNMP_ITEM_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("weight"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_SNMP_ITEM_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SNMP_ITEM_CONF_OFFSET,
      offsetof(ngx_snmp_core_item_t, weight),
      NULL },  
    
    { ngx_string("oid"),
      NGX_SNMP_OBJECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_SNMP_OBJECT_CONF_OFFSET,
      offsetof(ngx_snmp_core_object_t, oid),
      NULL },
    
    { ngx_string("type"),
      NGX_SNMP_OBJECT_CONF|NGX_CONF_TAKE1,
      ngx_snmp_core_type,
      NGX_SNMP_OBJECT_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("express"),
      NGX_SNMP_ITEM_CONF|NGX_CONF_TAKE1,
      ngx_snmp_core_express,
      NGX_SNMP_ITEM_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
         
};

ngx_module_t  ngx_snmp_core_module = {
    NGX_MODULE_V1,
    &ngx_snmp_core_module_ctx,             /* module context */
    ngx_snmp_core_commands,                /* module directives */
    NGX_SNMP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};




typedef struct {
    ngx_int_t               id; 
    ngx_str_t               logname; 
    ngx_int_t               log_level;
}ngx_snmp_log_level_t;

static ngx_snmp_log_level_t log_levels[] = {
    {0,ngx_string("error"),NGX_LOG_ERR},
    {1,ngx_string("warn"),NGX_LOG_WARN},
    {2,ngx_string("notice"),NGX_LOG_NOTICE},
    {3,ngx_string("info"),NGX_LOG_INFO},
    {4,ngx_string("debug"),NGX_LOG_DEBUG}
};



ngx_snmp_core_main_conf_t      *ngx_snmp_core_main_conf;


static void *
ngx_snmp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_snmp_core_main_conf_t           *cmcf;
    ngx_str_t                           shmname;
    ngx_shm_zone_t                      *shm_zone;
 
    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }
    
    ngx_snmp_core_main_conf = cmcf;
    
    if (ngx_array_init(&cmcf->groups,cf->pool,4,sizeof(ngx_snmp_core_group_t *))
        != NGX_OK)
    {
        return NULL;
    }
    
    if (ngx_array_init(&cmcf->upstream_group,cf->pool, 4,sizeof(ngx_snmp_core_upstream_group_t))
        != NGX_OK)
    {
        return NULL;
    }
    

    cmcf->log_level = NGX_LOG_DEBUG;
    
    ngx_str_set(&shmname, "ngx_snmp_share_memory");
    shm_zone = ngx_shared_memory_add(cf,&shmname,(8 * ngx_pagesize),&ngx_snmp_core_module);
    if(shm_zone == NULL){
        return NULL; 
    }
    
    shm_zone->init = ngx_snmp_core_init_share_zone;
    shm_zone->data = cmcf;
    cmcf->shm_zone = shm_zone;
 
    ngx_rbtree_init(&cmcf->snmp_rbtree,&cmcf->ngx_snmp_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);
    
    ngx_queue_init(&cmcf->server_data_queue);
    
    return cmcf;
    
}

static void *
ngx_snmp_core_create_group_conf(ngx_conf_t *cf)
{
    ngx_snmp_core_group_t   *conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_core_group_t));
    if (conf == NULL) {
        return NULL;
    }
    
    if (ngx_array_init(&conf->items,cf->pool, 4,sizeof(ngx_snmp_core_item_t *))
        != NGX_OK)
    {
        return NULL;
    }
    
    conf->interval = NGX_CONF_UNSET;
    conf->fall = NGX_CONF_UNSET;
    conf->port = NGX_CONF_UNSET;
    conf->version = NGX_CONF_UNSET;
    conf->pdu_handler.request_hanlder = NGX_CONF_UNSET_PTR;
    conf->pdu_handler.requid_handler = NGX_CONF_UNSET_PTR;
    conf->pdu_handler.head_handler = NGX_CONF_UNSET_PTR;
    conf->pdu_handler.finish_pdu_hander =NGX_CONF_UNSET_PTR;
    conf->pdu_handler.parse_pdu_handler = NGX_CONF_UNSET_PTR;
    
    return conf;
    
}

static void *
ngx_snmp_core_create_item_conf(ngx_conf_t *cf){
    ngx_snmp_core_item_t         *conf; 
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_core_item_t));
    if (conf == NULL) {
        return NULL;
    }
    
    if (ngx_array_init(&conf->objects,cf->pool, 4,sizeof(ngx_snmp_core_object_t *))
        != NGX_OK)
    {
        return NULL;
    }
    conf->direction  = NGX_CONF_UNSET;
    conf->most = NGX_CONF_UNSET;
    conf->weight = NGX_CONF_UNSET;
    conf->express.data = NULL; 
    conf->express.len = 0; 
    conf->group = NULL; 
    return conf; 
}

static void *
ngx_snmp_core_create_object_conf(ngx_conf_t *cf){
    ngx_snmp_core_object_t         *conf; 
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_core_object_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->group = NULL; 
    conf->item = NULL; 
    conf->uscf = NULL; 
    conf->type = SNMP_OBJECT_VALUETYPE_INT;
    conf->pdu_reqid = NULL; 
    conf->pdu_head = NULL; 
    conf->pdu_obj = NULL; 
    conf->name.len = 0;
    conf->name.data = NULL;
    conf->oid.len = 0;
    conf->oid.data = NULL;
    conf->type = NGX_CONF_UNSET;
    return conf; 
}

static char *
ngx_snmp_core_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_snmp_conf_ctx_t        *ctx,*snmp_ctx;
    ngx_module_t              **modules;
    ngx_snmp_module_t          *module;
    ngx_uint_t                 m;
    void                       *mconf;
    ngx_snmp_core_group_t      *cgcf, **cgcfp, **cgp,*cg;
    ngx_snmp_core_main_conf_t  *cmcf;
    ngx_conf_t                  pcf;
    ngx_str_t                   name,groupname; 
    ngx_str_t                   *value;
    ngx_uint_t                   i;
    ngx_snmp_core_item_t         *scicf;
    ngx_snmp_core_object_t       *scocf;
    
    
    value = cf->args->elts;
    name = value[1];
    
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    snmp_ctx =  cf->ctx;
    ctx->main_conf = snmp_ctx->main_conf;
    
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
        
        if (module->create_group_conf) {
            mconf = module->create_group_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->group_conf[modules[m]->ctx_index] = mconf;
        }
        else{
            ctx->group_conf[modules[m]->ctx_index] = NULL;
        }
        
        if (module->create_item_conf) {
            mconf = module->create_item_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->item_conf[modules[m]->ctx_index] = mconf;
        }
        else{
            ctx->item_conf[modules[m]->ctx_index] = NULL;
        }
        
        if (module->create_object_conf) {
            mconf = module->create_object_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->object_conf[modules[m]->ctx_index] = mconf;
        }
        else{
            ctx->object_conf[modules[m]->ctx_index] = NULL;
        }
    }
     
    cgcf = ctx->group_conf[ngx_snmp_core_module.ctx_index];
    cgcf->ctx = ctx;
    
    scicf = ctx->item_conf[ngx_snmp_core_module.ctx_index];
    scicf->ctx = ctx;
    
    scocf = ctx->object_conf[ngx_snmp_core_module.ctx_index];
    scocf->ctx = ctx; 
    
    cmcf = ctx->main_conf[ngx_snmp_core_module.ctx_index];
    
    cgp =  cmcf->groups.elts;
    for(i=0;i<cmcf->groups.nelts;i++){
        cg = cgp[i];
        groupname = cg->name;
        if(ngx_strncmp(groupname.data,name.data,name.len) == 0){
            return "is duplicate";
        }
    }
    
    cgcfp = ngx_array_push(&cmcf->groups);
    if (cgcfp == NULL) {
        return NGX_CONF_ERROR;
    }
    
    
    *cgcfp = cgcf;
    cgcf->name = name; 
    
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_SNMP_GROUP_CONF;
    
    rv = ngx_conf_parse(cf, NULL);

    
    *cf = pcf;

    return rv;
    
}

static char *
ngx_snmp_core_item(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_snmp_conf_ctx_t        *ctx, *pctx;
    ngx_module_t              **modules;
    ngx_snmp_module_t          *module;
    ngx_snmp_core_item_t       *cicf, **cicfp;
    ngx_snmp_core_group_t      *cgcf;
    ngx_conf_t                  pcf;
    ngx_snmp_core_object_t       *scocf;
    
    
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    
    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->group_conf = pctx->group_conf;
    
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
    
    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_SNMP_MODULE) {
            continue;
        }
        
        module = modules[i]->ctx;
        
        if (module->create_item_conf) {
            ctx->item_conf[modules[i]->ctx_index] = module->create_item_conf(cf);
            if (ctx->item_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        else{
            ctx->item_conf[modules[i]->ctx_index] = NULL;
        }
        
        if (module->create_object_conf) {
            ctx->object_conf[modules[i]->ctx_index] = module->create_object_conf(cf);
            if (ctx->object_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        else{
            ctx->object_conf[modules[i]->ctx_index] = NULL;
        }
    }
    
    cicf = ctx->item_conf[ngx_snmp_core_module.ctx_index];
    cicf->ctx = ctx;
    
    scocf = ctx->object_conf[ngx_snmp_core_module.ctx_index];
    scocf->ctx = ctx;
    
    cgcf = pctx->group_conf[ngx_snmp_core_module.ctx_index];
    
    cicfp = ngx_array_push(&cgcf->items);
    if (cicfp == NULL) {
        return NGX_CONF_ERROR;
    }
    
    *cicfp = cicf;
    
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_SNMP_ITEM_CONF;
    
    rv = ngx_conf_parse(cf, NULL);
    
    *cf = pcf;

    return rv;
    
}

static char *
ngx_snmp_core_object(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_snmp_conf_ctx_t        *ctx, *pctx;
    ngx_module_t              **modules;
    ngx_snmp_module_t          *module;
    ngx_snmp_core_item_t       *cicf;
    ngx_snmp_core_object_t     *cocf, **cocfp;
    ngx_str_t                  *values,name;
    ngx_conf_t                  pcf;
    
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    
    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->group_conf = pctx->group_conf;
    ctx->item_conf = pctx->item_conf;
    
    ctx->object_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_snmp_max_module);
    if (ctx->object_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif
    
    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_SNMP_MODULE) {
            continue;
        }
        
        module = modules[i]->ctx;
     
        if (module->create_object_conf) {
            ctx->object_conf[modules[i]->ctx_index] = module->create_object_conf(cf);
            if (ctx->object_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        else{
            ctx->object_conf[modules[i]->ctx_index] = NULL;
        }
        
    }
    
    values = cf->args->elts;
    name = values[1];
    cocf = ctx->object_conf[ngx_snmp_core_module.ctx_index];
    cocf->ctx = ctx;
    
    cocf->name = name; 

    cicf = pctx->item_conf[ngx_snmp_core_module.ctx_index];
    
    cocfp = ngx_array_push(&cicf->objects);
    if (cocfp == NULL) {
        return NGX_CONF_ERROR;
    }
    
    *cocfp = cocf;
    
    if(ngx_snmp_core_initate_object_pdus(cocfp,cf) != NGX_CONF_OK)
    {
        return "Alloc memory for object PDUs Error";
    }
    
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_SNMP_OBJECT_CONF;
    
    rv = ngx_conf_parse(cf, NULL);
    
    *cf = pcf;

    return rv;
   
}

static char *
ngx_snmp_core_group_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,group_name,upstream_name; 
    ngx_snmp_conf_ctx_t             *ctx;
    ngx_snmp_core_main_conf_t       *cmcf;
    ngx_snmp_core_upstream_group_t  *upstream_groups, upstream_group; 
    ngx_uint_t                       i;
    ngx_array_t                      *server_data;
    
    values =  cf->args->elts;
    group_name = values[1];
    upstream_name = values[2];
    
    ctx = cf->ctx;
    cmcf =  ctx->main_conf[ngx_snmp_core_module.ctx_index];
    
    upstream_groups = cmcf->upstream_group.elts;
    for(i=0;i<cmcf->upstream_group.nelts;i++){
        upstream_group = upstream_groups[i];
        if(ngx_strncmp(upstream_group.upstream_name.data,upstream_name.data,upstream_name.len) == 0){
            return "is duplicate";
        }
    }
    
    upstream_groups = ngx_array_push(&cmcf->upstream_group);
    if (upstream_groups == NULL) {
        return NGX_CONF_ERROR;
    }
    upstream_groups->upstream_name = upstream_name;
    upstream_groups->group_name = group_name;
    
    server_data = ngx_array_create(cf->pool, 4,sizeof(ngx_snmp_core_server_data_t));
    if ((upstream_groups->server_data =  server_data) == NULL)
    {
        return NULL;
    }
    
    return NGX_OK;
}

static char *
ngx_snmp_core_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,value;
    ngx_snmp_conf_ctx_t             *ctx;
    ngx_snmp_core_main_conf_t       *cmcf;
    ngx_int_t                       i,num;                       
    
    values = cf->args->elts;
    value = values[1];
    
    ctx = cf->ctx;
    cmcf =  ctx->main_conf[ngx_snmp_core_module.ctx_index];
    
    num = sizeof(log_levels)/sizeof(ngx_snmp_log_level_t);
    for(i=0;i<num;i++){
        if(ngx_strncmp(value.data,log_levels[i].logname.data,value.len) == 0){
            cmcf->log_level = log_levels[i].log_level;
        }
    }
    
    return NGX_OK; 
}

static char *
ngx_snmp_core_version(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,value;
    ngx_snmp_core_group_t           *cgcf;
    ngx_int_t                       i,num;                       
    
    values = cf->args->elts;
    value = values[1];
    
    cgcf = (ngx_snmp_core_group_t *)conf;
    
    num =  SNMP_VERSION_NUM; 
    
    for(i=0;i<num;i++){
        if(ngx_strncmp(value.data,snmp_versions[i].version_str.data,value.len) == 0){
            cgcf->version = snmp_versions[i].version_no; 
        }
    }
    
    return NGX_CONF_OK; 
}

static char *
ngx_snmp_core_direction(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,value;
    ngx_snmp_core_item_t            *cicf;                     
    
    values = cf->args->elts;
    value = values[1];
    
    cicf = (ngx_snmp_core_item_t *)conf;
    
    if (ngx_strcasecmp(value.data, (u_char *) "MORE") == 0) {
        cicf->direction = SNMP_DIRECTION_MORE;
    }
    else{
        cicf->direction = SNMP_DIRECTION_LESS;
    }
    
    return NGX_CONF_OK; 
}

static char *
ngx_snmp_core_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,value;
    ngx_snmp_core_object_t          *cocf;                     
    
    values = cf->args->elts;
    value = values[1];
    
    cocf = (ngx_snmp_core_object_t *)conf;
    
    if (ngx_strcasecmp(value.data, (u_char *) "INT") == 0) {
        cocf->type = SNMP_OBJECT_VALUETYPE_INT;
    }
    else{
        cocf->type = SNMP_OBJECT_VALUETYPE_FLOAT;
    }
    
    return NGX_CONF_OK; 
}

static char *
ngx_snmp_core_most(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,value,numvalue;
    ngx_snmp_core_item_t            *cicf;  
    ngx_int_t                       n; 
    ngx_snmp_float_t                most_value;
    char                            unit; 
    
    values = cf->args->elts;
    value = values[1];
    
    n =  value.len -1;
    if(value.data[n]<'0' || value.data[n]>'9'){
        numvalue.data = value.data;
        numvalue.len = n;
        unit = value.data[n];
    }
    else{
        numvalue.data = value.data;
        numvalue.len = value.len;
        unit = 'N';
    }
    
    most_value = ngx_atofp(numvalue.data,numvalue.len,2)*0.01;
    
    if(unit != 'N'){
        switch(unit){
            case'T':
               most_value = most_value * 1024;
            case'G':
               most_value = most_value * 1024;
            case'M':
               most_value = most_value * 1024;
            case'K':
               most_value = most_value * 1024;
            default:
                break;
        }
        
        switch(unit){
            case't':
               most_value = most_value * 1000;
            case'g':
               most_value = most_value * 1000;
            case'm':
               most_value = most_value * 1000;
            case'k':
               most_value = most_value * 1000;
            default:
                break;
        }
    }
    
    cicf = (ngx_snmp_core_item_t *)conf;
    
    cicf->most = most_value;
        
    return NGX_CONF_OK; 
}

static char *
ngx_snmp_core_express(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *values,value,object_name,tmp_value;
    ngx_snmp_core_item_t            *cicf;
    ngx_snmp_core_object_t          **cocfp,*cocf;              
    ngx_int_t                       i,pos,found;
    ngx_uint_t                      j;
    u_char                          *c;
    ngx_snmp_conf_ctx_t             *ctx;
    
    values = cf->args->elts;
    value = values[1];
    
    ctx = cf->ctx;
    cicf = ctx->item_conf[ngx_snmp_core_module.ctx_index];
        
    cocfp = cicf->objects.elts;
    tmp_value = value; 
    i=0;
    while((pos=ngx_snmp_getObjectNameFromExpress(tmp_value,&object_name))>0){
        if((ngx_snmp_core_getKeepworld(object_name,NULL)) ==  NGX_CONF_OK)
        {
            c = tmp_value.data;
            tmp_value.data = &c[pos];
            tmp_value.len = tmp_value.len - pos;
            continue; 
        }
        found = 0;
        for(j=0;j<cicf->objects.nelts;j++){
            cocf = cocfp[j];
            if(ngx_strncmp(cocf->name.data,object_name.data,object_name.len) == 0){
                found = 1; 
                break;
            }
        }
        if(found == 0){
            return "Not found object which fill in the express";
            break;
        }
        c = tmp_value.data;
        tmp_value.data = &c[pos];
        tmp_value.len = tmp_value.len - pos;
    }
    
    cicf->express = value; 
    
    return NGX_CONF_OK; 
}

static ngx_int_t
ngx_snmp_getObjectNameFromExpress(ngx_str_t value, ngx_str_t *object_name){
    ngx_int_t              start,isnum,ret;
    ngx_uint_t              i,j,len;
    u_char                 *c,*data;
    
    data =  value.data;
    
    ret = 0;
    len = 0;
    c = NULL;
    for(i=0;i<value.len;i++)
    {
        if(data[i] == '='){
            c = &data[i];
            c++;
            len =  value.len - i -1;
            ret = i;
            break; 
        }
        continue; 
    } 
    
    if(c == NULL){
        c = value.data;
        len = value.len;
    }
    
    start =0;
    for(i=0;i<len;i++){
        ret++;
        if(start == 0){
            if(c[i] == ')'|| c[i] == '(' || c[i] == ' ' || c[i] =='+' || c[i] =='-' || c[i] =='*' || c[i] =='/' || c[i] ==')'){
                continue;
            }
            object_name->data = &c[i];
            start = 1;
            continue;
        }
        else{
            if(c[i] !='(' && c[i] !=')' && c[i] !=' ' && c[i] !='+' && c[i] !='-' && c[i] !='*' && c[i] !='/'){
                start++;
                continue;
            }
            object_name->len = start; 
        }
        
        data = object_name->data;
        isnum=1;
        for(j=0;j<object_name->len;j++){
            if(data[j]>='0' && data[j]<='9'){
                continue; 
            }
            else{
                isnum = 0;
            }
        }
        if(isnum == 1){
            start =0;
        }
        else{
            return ret;
        }
    }
    
    if(len == 0){
        ret = 0;
    }
    else{
        isnum=1;
        object_name->len = start; 
        data = object_name->data;
        for(j=0;j<object_name->len;j++){
            if(data[j]>='0' && data[j]<='9'){
                continue; 
            }
            else{
                isnum = 0;
            }
        }
        if(isnum == 1){
            ret = 0;
        }
    }
    
    return ret; 
}

char *
ngx_snmp_core_getKeepworld(ngx_str_t value, ngx_snmp_core_express_fun_handler_t *ret)
{
    ngx_int_t               i,num; 
    
    num = sizeof(keepworlds)/sizeof(ngx_snmp_core_express_fun_handler_t);
    for(i=0;i<num;i++){
        if(ngx_strncmp(value.data,keepworlds[i].key_world.data,keepworlds[i].key_world.len) == 0)
        {
            if(NULL == ret)
            {
                return NGX_CONF_OK;
            }
            else
            {
                ret->key_world = keepworlds[i].key_world;
                ret->ngx_snmp_fun_pt = keepworlds[i].ngx_snmp_fun_pt;
                ret->keyword_type = keepworlds[i].keyword_type;
                return NGX_CONF_OK; 
            }
        }
    }
    
    return NGX_CONF_ERROR; 
}

static char *
ngx_snmp_core_merge_group_conf(ngx_conf_t *cf, void *prev,void *conf)
{
    ngx_snmp_core_group_t       *prev_scgf,*scgf;
    
    prev_scgf = (ngx_snmp_core_group_t *)prev;
    scgf = (ngx_snmp_core_group_t *)conf;
    if(NGX_CONF_UNSET == scgf->interval)
    {
        if(NGX_CONF_UNSET != prev_scgf->interval)
        {
            scgf->interval = prev_scgf->interval;
        }
        else
        {
            scgf->interval = DEFAULT_INTERVAL;
        }
    }
    
    if(NGX_CONF_UNSET == scgf->fall)
    {
        if(NGX_CONF_UNSET != prev_scgf->fall)
        {
            scgf->fall = prev_scgf->fall;
        }
        else
        {
            scgf->fall = DEFAULTFALL;
        }
    }
    
    if(NGX_CONF_UNSET == scgf->port)
    {
        if(NGX_CONF_UNSET != prev_scgf->port)
        {
            scgf->port = prev_scgf->port;
        }
        else
        {
            scgf->port = DEFAULTPORT;
        }
    }
    
    if(NGX_CONF_UNSET == scgf->version)
    {
        if(NGX_CONF_UNSET != prev_scgf->version)
        {
            scgf->version = prev_scgf->version;
        }
        else
        {
            scgf->version = SNMP_VERSION_2C;
        }
    }
   
    return NGX_CONF_OK;
}

static char *
ngx_snmp_core_merge_item_conf(ngx_conf_t *cf, void *pre,void *conf)
{
    ngx_snmp_core_item_t        *prescicf,*scicf;
    
    prescicf = (ngx_snmp_core_item_t *)pre;
    scicf = (ngx_snmp_core_item_t *)conf; 
    
    if(scicf->name.len == 0 && prescicf->name.len > 0){
        scicf->name = prescicf->name;
    }
    
    if(scicf->direction == NGX_CONF_UNSET && prescicf->direction != NGX_CONF_UNSET){
        scicf->direction = prescicf->direction;
    }
    
    if(scicf->most == NGX_CONF_UNSET && prescicf->most != NGX_CONF_UNSET){
        scicf->most = prescicf->most;
    }
    
    if(scicf->weight == NGX_CONF_UNSET && prescicf->weight != NGX_CONF_UNSET){
        scicf->weight = prescicf->weight;
    }
        
    return NGX_CONF_OK; 
}


static ngx_int_t
ngx_snmp_getNameFromExpress(ngx_str_t value, ngx_str_t *name)
{
     ngx_int_t              start;
     ngx_uint_t              i;
     u_char                 *data; 
     
     if(value.len < 1)
     {
         return 0;
     }
     
    start = 0;
    data = value.data;
    for(i=0;i<value.len;i++)
    {
        if(start == 0)
        {
            if(data[i] == ' ')
            {
                continue;
            }
            else{
                name->data = &data[i];
                start++;
            }
        }
        else{
            if(data[i] == ' ' || data[i] == '='){
                name->len = start;
                break; 
            }
            else{
                start++;
                continue;
            }
        }
    } 
    
    return start;
}

 
static char *
ngx_snmp_core_merge_object_conf(ngx_conf_t *cf, void *pre,void *conf)
{
    ngx_snmp_core_object_t      *prescocf,*scocf;
   
    prescocf = (ngx_snmp_core_object_t *)pre;
    scocf = (ngx_snmp_core_object_t *)conf;
    
    if(scocf->name.len == 0 && prescocf->name.len >0){
        scocf->name = prescocf->name;
    }
    
    if(scocf->oid.len == 0 && prescocf->oid.len >0){
        scocf->oid =  prescocf->oid;
    }
    
    if(scocf->type == NGX_CONF_UNSET && prescocf->type != NGX_CONF_UNSET){
        scocf->type = prescocf->type;
    }
    
    return NGX_CONF_OK; 
}


static char *
ngx_snmp_core_initate_object_pdus(ngx_snmp_core_object_t **cocfp,ngx_conf_t *cf)
{   
    ngx_snmp_core_object_t                      *cocf;
    
    cocf = *cocfp;
    cocf->pool = ngx_create_pool(SNMP_POOL_SIZE,cf->log);
    if(cocf->pool == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_reqid = ngx_palloc(cocf->pool, sizeof(ngx_str_t));
    if(cocf->pdu_reqid == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_reqid->data = ngx_alloc(sizeof(u_char) * SNNP_BUFFER_LENGTH,cocf->pool->log);
    if(cocf->pdu_reqid->data == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_reqid->len = 0;
    
    cocf->pdu_head = ngx_palloc(cocf->pool, sizeof(ngx_str_t));
    if(cocf->pdu_head == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_head->data = ngx_alloc(sizeof(u_char) * SNNP_BUFFER_LENGTH,cocf->pool->log);
    if(cocf->pdu_head->data == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_head->len = 0;
    
    cocf->pdu_obj = ngx_palloc(cocf->pool, sizeof(ngx_str_t));
    if(cocf->pdu_obj == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_obj->data = ngx_alloc(sizeof(u_char) * SNNP_BUFFER_LENGTH,cocf->pool->log);
    if(cocf->pdu_obj->data == NULL)
    {
        return NGX_CONF_ERROR;
    }
    cocf->pdu_obj->len = 0;
    
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_snmp_core_init_share_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_snmp_core_main_conf_t           *oscmcf,*scmcf;
    ngx_snmp_timer_start_status_t       *start_status;
    ngx_slab_pool_t                     *shpool;
    
    
    oscmcf = (ngx_snmp_core_main_conf_t *)data;
    scmcf = (ngx_snmp_core_main_conf_t *) shm_zone->data;
    if(oscmcf){
        scmcf->start_status = oscmcf->start_status;
        return NGX_OK;
    }
    
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if(shm_zone->shm.exists) {
        scmcf->start_status = shpool->data;
        return NGX_OK;
    }
    
    scmcf->start_status = ngx_slab_alloc(shpool,sizeof(ngx_snmp_timer_start_status_t));
    if(scmcf->start_status == NULL){
        return NGX_ERROR;
    }
    
    start_status = scmcf->start_status;
    start_status->is_start = 0;
    start_status->running_process_num = 0;
    start_status->pid = 0;
    
    shpool->data =  scmcf->start_status;
    
    return NGX_OK;
}

static ngx_int_t 
ngx_snmp_core_post_conf(ngx_conf_t *cf){
    ngx_snmp_core_main_conf_t               *scmcf;
    ngx_snmp_core_group_t                   **cgcfp,*cgcf;
    ngx_uint_t                              i,j;
    ngx_snmp_core_item_t                    **scicfp,*scicf;
    ngx_snmp_core_object_t                  **scocfp,*scocf;
    ngx_str_t                               express,name;
    
    scmcf = (ngx_snmp_core_main_conf_t *)((ngx_snmp_conf_get_module_main_conf(cf,ngx_snmp_core_module)));
    if(scmcf == NULL){
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Can not get SNMP module main conf");
        return NGX_ERROR;
    }
    
    cgcfp = scmcf->groups.elts;
    if(scmcf->groups.nelts <1 ){
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "You define a snmp block but not define group block.");
        return NGX_ERROR;
    }
    
    for(i=0;i<scmcf->groups.nelts;i++){
        cgcf = cgcfp[i];
        if(cgcf->items.nelts <1 ){
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "No item block in a group block");
            return NGX_ERROR;
        }
        
        scicfp = cgcf->items.elts;
        for(j=0;j<cgcf->items.nelts;j++){
            scicf = scicfp[j];
            
            if( scicf->objects.nelts <1 ){
                ngx_log_error(NGX_LOG_ERR, cf->log, 0, "No object block in a item block");
                return NGX_ERROR;
            }
            if(scicf->objects.nelts < 2 || scicf->express.len == 0){
                scocfp = scicf->objects.elts;
                scocf = scocfp[0];
                scicf->name =  scocf->name;
            }
            else{
                express = scicf->express;
                if(ngx_snmp_getNameFromExpress(express,&name) <1 ){
                    return NGX_ERROR;
                }
                scicf->name = name;
            }
        }
    }
    
    return NGX_OK;
}

ngx_int_t ngx_snmp_fun_last(void *data){
    ngx_snmp_express_cal_parameters_t                      *fun_data;
    ngx_snmp_item_value_t                                  *siv;
    ngx_str_t                                              *obj_name;
    ngx_snmp_core_object_session_t                         *ossp,s;
    ngx_uint_t                                             i;
    float                                                  *value;
    ngx_snmp_core_server_data_t                            *server_data;
    
    fun_data = (ngx_snmp_express_cal_parameters_t *)data;
    siv = fun_data->siv;
    obj_name = fun_data->obj_name;
    value = fun_data->ret;
    server_data = siv->server_data;
    
    ossp = siv->object_session->elts;
    for(i=0;i<siv->object_session->nelts;i++){
        s = ossp[i];
        if((ngx_strcmp(&(s.core_object->name),obj_name)) == 0){
            if((s.last_stats == NGX_SNMP_VALUE_STATS_ERROR) || (s.received_sn) == 0){
                return NGX_ERROR;
            }
            if(s.value_type == SNMP_OBJECT_VALUETYPE_INT){
                *value = s.last_value;
            }
            else{
                *value = s.last_value*0.01;
            }
            return NGX_OK;
        }
    }
    
    ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Can not found object with object name \"%V\"",obj_name);
    return NGX_ERROR;
    
}

ngx_int_t
ngx_snmp_fun_change(void *data){
    ngx_snmp_express_cal_parameters_t                      *fun_data;
    ngx_snmp_item_value_t                                  *siv;
    ngx_str_t                                              *obj_name;
    ngx_snmp_core_object_session_t                         *ossp,s;
    ngx_uint_t                                             i;
    float                                                  *value;
    ngx_snmp_core_server_data_t                            *server_data;
    
    fun_data = (ngx_snmp_express_cal_parameters_t *)data;
    siv = fun_data->siv;
    obj_name = fun_data->obj_name;
    value = fun_data->ret;
    server_data = siv->server_data;
    
    ossp = siv->object_session->elts;
    for(i=0;i<siv->object_session->nelts;i++){
        s = ossp[i];
        if((ngx_strcmp(&(s.core_object->name),obj_name)) == 0){
            if((s.last_stats == NGX_SNMP_VALUE_STATS_ERROR) || (s.stats == NGX_SNMP_VALUE_STATS_ERROR)){
                return NGX_ERROR;
            }
            if(s.value_type == SNMP_OBJECT_VALUETYPE_INT){
                *value = (s.value - s.last_value);
            }
            else{
                *value = (s.value - s.last_value)*0.01;
            }
            return NGX_OK;
        }
    }
    
    ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Can not found object with object name \"%V\"",obj_name);
    return NGX_ERROR;
    
}

ngx_int_t
ngx_snmp_fun_rate(void *data){
    ngx_snmp_express_cal_parameters_t                      *fun_data;
    ngx_snmp_item_value_t                                  *siv;
    ngx_str_t                                              *obj_name;
    ngx_snmp_core_object_session_t                         *ossp,s;
    ngx_uint_t                                             i;
    float                                                  *value;
    ngx_snmp_core_server_data_t                            *server_data;
    ngx_int_t                                              interval;
    
    fun_data = (ngx_snmp_express_cal_parameters_t *)data;
    siv = fun_data->siv;
    obj_name = fun_data->obj_name;
    value = fun_data->ret;
    server_data = siv->server_data;
    
    ossp = siv->object_session->elts;
    for(i=0;i<siv->object_session->nelts;i++){
        s = ossp[i];
        if((ngx_strcmp(&(s.core_object->name),obj_name)) == 0){
            interval = siv->group->interval;
            if(s.value_type == SNMP_OBJECT_VALUETYPE_INT){
                *value = s.value/interval;
            }
            else{
                *value = (s.value*0.01)/interval;
            }
            return NGX_OK;
        }
    }
    
    ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Can not found object with object name \"%V\"",obj_name);
    return NGX_ERROR;
}

ngx_int_t
ngx_snmp_get_keyword_value(void *data){
    ngx_snmp_express_cal_parameters_t                      *fun_data;
    ngx_snmp_item_value_t                                  *siv;
    float                                                  *value;
    ngx_str_t                                              *obj_name,keyword;
    ngx_snmp_core_server_data_t                            *server_data;
    
    fun_data = (ngx_snmp_express_cal_parameters_t *)data;
    siv = fun_data->siv;
    obj_name = fun_data->obj_name;
    value = fun_data->ret;
    server_data = siv->server_data;
    ngx_str_set(&keyword,"interval");
    if((ngx_strcmp(obj_name,&keyword) == 0)){
        *value = siv->group->interval;
        return NGX_OK;
    }
    
    ngx_log_error(NGX_LOG_ERR, server_data->log, 0, "Can not found the value of keyword: \"%V\"",obj_name);
    return NGX_ERROR;
    
}