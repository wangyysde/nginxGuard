/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp_module.h"

ngx_uint_t  ngx_snmp_max_module;

static ngx_core_module_t ngx_snmp_module_ctx = {
    ngx_string("snmp"),
    NULL,
    NULL
};

static ngx_command_t  ngx_snmp_commands[] = {
    { 
        ngx_string("snmp"),
        NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,   
        ngx_snmp_snmp, 
        0,
        0,
        NULL 
    },
    { 
        ngx_string("group"),
        NGX_SNMP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,   
        ngx_snmp_group, 
        0,
        0,
        NULL 
    }
    
    ngx_null_command
};

static ngx_module_t  ngx_snmp_module = {
    NGX_MODULE_V1,
    &ngx_snmp_module_ctx,                                                       /* module context */
    ngx_snmp_commands,                                                   /* module directives  */
    NGX_CORE_MODULE,                                                            /* module type  */
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
ngx_snmp_snmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)   
{
    ngx_snmp_conf_ctx_t               *ctx;
    ngx_snmp_module_t                 *module;
    ngx_module_t                     **modules;
    ngx_uint_t                        i,m,mi;
    ngx_conf_t                        pcf;
    char                              *rv;
    ngx_snmp_core_main_conf_t         *cmcf;
    ngx_snmp_core_group_t            *cgcf, **cgcfp; 
    
    if (*(ngx_snmp_conf_ctx_t **) conf) {
        return "is duplicate";
    }
    
     /* the main snmp context */
    
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
    
    ctx->group_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_snmp_max_module);
    if (ctx->group_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->item_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_snmp_max_module);
    if (ctx->item_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->object_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_snmp_max_module);
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

        /* init snmp{} main_conf's */
        cf->ctx = ctx; 
        
        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf; 
                return rv; 
            }
        }
        
        for(i = 0; i<cmcf->groups.nelts;i++){
            
        }
       
    }    
    
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_SNMP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }
    
    *cf = pcf;
    
    return NGX_CONF_OK;
    


}

static char *
ngx_snmp_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    
}