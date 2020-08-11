/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp_module.h"

static ngx_core_module_t ngx_snmp_module_ctx = {
    ngx_string("snmp"),
    ngx_snmp_create_conf,
    ngx_snmp_init_conf
}

ngx_module_t  ngx_snmp_module = {
    NGX_MODULE_V1,
    &ngx_snmp_module_ctx,                                                       /* module context */
    ngx_snmp_module_commands,                                                   /* module directives */
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


static void *
ngx_snmp_create_conf(ngx_cycle_t *cycle)
{
    ngx_snmp_main_conf_t  *smcf;
    smcf = ngx_pcalloc(cycle->pool, sizeof(ngx_snmp_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }
    
    if((smcf->snmp_paras = ngx_array_create(cycle->pool,1,sizeof(ngx_snmp_paras_t)))
            ==NULL)
    {
        return NULL; 
    }
    if((smcf->server_data_settings = ngx_array_create(cycle->pool,1,sizeof(ngx_server_data_settings_t)))
            ==NULL)
    {
        return NULL; 
    }
 
    return smcf;
}

static void *
ngx_snmp_init_conf(ngx_cycle_t *cycle,void *conf)
{
   
}

static char *
ngx_snmp_parameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)   
{
    ngx_str_t                         name; 
    ngx_snmp_paras_t                  *sps,sp,*spp; 
    ngx_str_t                         *value;
    ngx_snmp_main_conf_t              *smcf;
    ngx_uint_t                        i; 
    
    
    value = cf->args->elts;
    name =  value[1];
    
    smcf = ngx_http_conf_get_module_main_conf(cf,ngx_snmp_module);
    sps = smcf->snmp_paras->elts;
    for (i = 0;  i < smcf->snmp_paras->nelts;i++) {
        sp = sps[i];
        if(ngx_strncmp(name.data,sp.name.data,name.len) == 0){
            return "is duplicate";
        }
    }
    spp = ngx_array_push(smcf->snmp_paras);
    if (spp == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(spp, sizeof(ngx_snmp_paras_t));
    spp->name = name; 
    spp->snmp_interval = 30;
    spp->snmp_ver = SNMP_VERSION_2C;
    spp->snmp_port = 161; 
    spp->snmp_socket_type = SNMP_SOCKET_UDP;
    ngx_str_set(spp->snmp_community,"public");
    ngx_str_set(spp->snmp_context_name,"context_name");
    spp->snmp_security_level = SNMP_SECURITY_LEVEL_NOAUTHNOPRIV;
    spp->snmp_auth_protocol = SNMP_AUTH_PROTOCOL_MD5;
    ngx_str_set(spp->snmp_auth_phrase,"auth_phrase");
    spp->snmp_privacy_protocol = SNMP_AUTH_PRIVACY_DES;
    ngx_str_set(spp->snmp_privacy_phrase,"privacy_phrase");
    ngx_str_set(spp->snmp_cpu_load_oid,SNMP_LOAD_OID);
    ngx_str_set(spp->snmp_swap_size_oid,SNMP_SWAP_SIZE_OID);
    ngx_str_set(spp->snmp_swap_available_oid,SNMP_SWAP_AVAILABLE_OID);
    ngx_str_set(spp->snmp_mem_size_oid,SNMP_MEM_SIZE_OID);
    ngx_str_set(spp->snmp_mem_free_oid,SNMP_MEM_FREE_OID);
    ngx_str_set(spp->snmp_mem_buffer_oid,SNMP_MEM_BUFFER_OID);
    ngx_str_set(spp->snmp_mem_cached_oid,SNMP_MEM_CACHED_OID);
    return NGX_CONF_OK;
}