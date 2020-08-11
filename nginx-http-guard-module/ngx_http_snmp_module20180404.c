/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_http_snmp_module.h"


static ngx_http_module_t  ngx_http_snmp_module_ctx = {     
    NULL,                                   /* preconfiguration */
    NULL,                                    /* postconfiguration */
    ngx_http_snmp_create_main_conf,         /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_snmp_module = {
    NGX_MODULE_V1,
    &ngx_http_snmp_module_ctx,             /* module context */
    ngx_http_snmp_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type  */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                /* init process ngx_http_guard_init_process*/
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_snmp_create_main_conf(ngx_conf_t *cf){
    ngx_snmp_main_conf_t            *smcf;
    
    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }
    smcf->snmp_paras = NULL; 
    smcf->server_data_settings = NULL; 
    return smcf; 
}

static char *
ngx_http_snmp_paras_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                         name; 
    ngx_snmp_paras_t                  *sps,sp,*spp; 
    ngx_str_t                         *value;
    ngx_snmp_main_conf_t              *smcf;
    ngx_uint_t                        i; 
    
    value = cf->args->elts;
    name =  value[1];
    
    smcf = (ngx_snmp_main_conf_t *)conf;
    if(smcf->snmp_paras == NULL){
        if((smcf->snmp_paras = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_paras_t)))
            ==NULL)
        {
                return NULL; 
        }
    }
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
    ngx_str_set(&spp->snmp_community,"context_name");
    ngx_str_set(&spp->snmp_context_name,"context_name");
    spp->snmp_security_level = SNMP_SECURITY_LEVEL_NOAUTHNOPRIV;
    spp->snmp_auth_protocol = SNMP_AUTH_PROTOCOL_MD5;
    ngx_str_set(&spp->snmp_auth_phrase,"auth_phrase");
    spp->snmp_privacy_protocol = SNMP_AUTH_PRIVACY_DES;
    ngx_str_set(&spp->snmp_privacy_phrase,"privacy_phrase");
    ngx_str_set(&spp->snmp_cpu_load_oid,SNMP_LOAD_OID);
    ngx_str_set(&spp->snmp_swap_size_oid,SNMP_SWAP_SIZE_OID);
    ngx_str_set(&spp->snmp_swap_available_oid,SNMP_SWAP_AVAILABLE_OID);
    ngx_str_set(&spp->snmp_mem_size_oid,SNMP_MEM_SIZE_OID);
    ngx_str_set(&spp->snmp_mem_free_oid,SNMP_MEM_FREE_OID);
    ngx_str_set(&spp->snmp_mem_buffer_oid,SNMP_MEM_BUFFER_OID);
    ngx_str_set(&spp->snmp_mem_cached_oid,SNMP_MEM_CACHED_OID);
    return NGX_CONF_OK;
}

static char *
ngx_snmp_parameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value;
    ngx_snmp_paras_t                  *spp;
    ngx_str_t                         var; 
    ngx_str_t                         varvalue;
    ngx_uint_t                        flag;
    
    
    value = cf->args->elts;
    spp = (ngx_snmp_paras_t *)conf;
    var = value[1]; 
    varvalue = value[2];
    
    flag = 0;
    if(ngx_strncmp(var.data,"interval",var.len) == 0){
        spp->snmp_interval = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(ngx_strncmp(var.data,"version",var.len) == 0){
        if(ngx_strncmp(varvalue.data,"1",varvalue.len) == 0){
            spp->snmp_ver = SNMP_VERSION_1;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"2c",varvalue.len) == 0){
            spp->snmp_ver = SNMP_VERSION_2C;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"2",varvalue.len) == 0){
            spp->snmp_ver = SNMP_VERSION_2;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"3",varvalue.len) == 0){
            spp->snmp_ver = SNMP_VERSION_3;
            flag = 1;
        }
    }
    if(ngx_strncmp(var.data,"port",var.len) == 0){
        spp->snmp_port = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1;
    }
    if(ngx_strncmp(var.data,"commnunity",var.len) == 0){
        spp->snmp_community = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"context_name",var.len) == 0){
        spp->snmp_context_name = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"security_name",var.len) == 0){
        spp->snmp_security_name = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"security_level",var.len) == 0){
        if(ngx_strncmp(varvalue.data,"noAuthNoPriv",varvalue.len) == 0){
            spp->snmp_security_level = SNMP_SECURITY_LEVEL_NOAUTHNOPRIV;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"uthNoPriv",varvalue.len) == 0){
            spp->snmp_security_level = SNMP_SECURITY_LEVEL_AUTHNOPRIV;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"AuthPriv",varvalue.len) == 0){
            spp->snmp_security_level = SNMP_SECURITY_LEVEL_AUTHPRIV;
            flag = 1;
        }
    }
    if(ngx_strncmp(var.data,"auth_protocol",var.len) == 0){
        if(ngx_strncmp(varvalue.data,"md5",varvalue.len) == 0){
            spp->snmp_auth_protocol = SNMP_AUTH_PROTOCOL_MD5;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"sha",varvalue.len) == 0){
            spp->snmp_auth_protocol = SNMP_AUTH_PROTOCOL_SHA;
            flag = 1;
        }
    }
    if(ngx_strncmp(var.data,"auth_phrase",var.len) == 0){
        spp->snmp_auth_phrase = varvalue;
        flag = 1;
    }
    if(ngx_strncmp(var.data,"privacy_protocol",var.len) == 0){
        if(ngx_strncmp(varvalue.data,"des",varvalue.len) == 0){
            spp->snmp_privacy_protocol = SNMP_AUTH_PRIVACY_DES;
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"aes",varvalue.len) == 0){
            spp->snmp_privacy_protocol = SNMP_AUTH_PRIVACY_AES;
            flag = 1;
        }
    }
    if(ngx_strncmp(var.data,"load_oid",var.len) == 0){
        spp->snmp_cpu_load_oid = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"swap_size_oid",var.len) == 0){
        spp->snmp_swap_size_oid = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"swap_free_size_oid",var.len) == 0){
        spp->snmp_swap_available_oid = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"mem_size_oid",var.len) == 0){
        spp->snmp_mem_size_oid = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"mem_free_oid",var.len) == 0){
        spp->snmp_mem_free_oid= varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"mem_buffer_oid",var.len) == 0){
        spp->snmp_mem_buffer_oid = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"cached_oid",var.len) == 0){
        spp->snmp_mem_cached_oid = varvalue; 
        flag = 1;
    }
    if(ngx_strncmp(var.data,"socket_type",var.len) == 0){
        if(ngx_strncmp(varvalue.data,"TCP",varvalue.len) == 0){
            spp->snmp_socket_type = SNMP_SOCKET_TCP; 
            flag = 1;
        }
        if(ngx_strncmp(varvalue.data,"UDP",varvalue.len) == 0){
            spp->snmp_socket_type = SNMP_SOCKET_UDP; 
            flag = 1;
        }
    }
    if(flag == 0){
        return "unavailable item";
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_snmp_server_performance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                                   name; 
    ngx_server_data_settings_t                  *sds,sd,*sdp; 
    ngx_str_t                                   *value;
    ngx_snmp_main_conf_t                        *smcf;
    ngx_uint_t                                   i; 
    
    value = cf->args->elts;
    name =  value[1];
    
    smcf = (ngx_snmp_main_conf_t *)conf;
    if(smcf->server_data_settings == NULL){
        if((smcf->server_data_settings = ngx_array_create(cf->pool,1,sizeof(ngx_server_data_settings_t)))
            ==NULL)
        {
                return NULL; 
        }
    }
    sds = smcf->server_data_settings->elts;
    for (i = 0;  i < smcf->server_data_settings->nelts;i++) {
        sd = sds[i];
        if(ngx_strncmp(name.data,sd.name.data,name.len) == 0){
            return "is duplicate";
        }
    }
    sdp = ngx_array_push(smcf->server_data_settings);
    ngx_memzero(sdp, sizeof(ngx_server_data_settings_t));
    sdp->name = name;
    sdp->cpu_load_max = CPU_LOAD_MAX;
    sdp->cpu_load_weight = CPU_LOAD_WEIGHT;
    sdp->swapratio_max = SWAPRATIO_MAX;
    sdp->swapratio_weight = SWAPRATIO_WEIGHT;
    sdp->freemem_min = FREEMEM_MIN;
    sdp->freemem_weight = FREEMEM_WEIGHT;
    return NGX_CONF_OK;
}

static char *
ngx_snmp_perf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                                   *value;
    ngx_server_data_settings_t                  *sdp;
    ngx_str_t                                   var; 
    ngx_str_t                                   varvalue;
    ngx_uint_t                                  flag;
    
    value = cf->args->elts;
    sdp = (ngx_server_data_settings_t *)conf;
    var = value[1]; 
    varvalue = value[2];
    
    flag = 0;
    
    if(ngx_strncmp(var.data,"load_max",var.len) == 0){
        sdp->cpu_load_max = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(ngx_strncmp(var.data,"load_weight",var.len) == 0){
        sdp->cpu_load_weight = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(ngx_strncmp(var.data,"swapratio_max",var.len) == 0){
        sdp->swapratio_max = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(ngx_strncmp(var.data,"swapratio_weight",var.len) == 0){
        sdp->swapratio_weight = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(ngx_strncmp(var.data,"freemem_min",var.len) == 0){
        sdp->freemem_min = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(ngx_strncmp(var.data,"freemem_weight",var.len) == 0){
        sdp->freemem_weight = ngx_atoi(varvalue.data,varvalue.len);
        flag = 1; 
    }
    if(flag == 0){
        return "unavailable item";
    }
    return NGX_CONF_OK;
}