/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_http_snmp_module.h"


static ngx_http_module_t  ngx_http_snmp_module_ctx = {     
    NULL,                                   /* preconfiguration */
    ngx_http_snmp_post_conf,                /* postconfiguration */
    ngx_http_snmp_create_main_conf,         /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};

ngx_module_t  ngx_http_snmp_module = {
    NGX_MODULE_V1,
    &ngx_http_snmp_module_ctx,             /* module context */
    ngx_http_snmp_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type  */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_snmp_init_process,            /* init process ngx_http_guard_init_process*/
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
    smcf->guard_upstream = NULL; 
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

static char *
ngx_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                            *value;
    ngx_str_t                             upstream_name, para_name,server_setting_name,redirect_uri;
    ngx_snmp_main_conf_t                 *smcf;
    ngx_guard_upstream_t                 gu,*gus,*gup;
    ngx_uint_t                           i; 
    value =  cf->args->elts;
    upstream_name = value[1];
    para_name = value[2];
    server_setting_name = value[3];
    redirect_uri = value[4];
    smcf = (ngx_snmp_main_conf_t *)cf->ctx;
    if(smcf->guard_upstream == NULL){
        if((smcf->guard_upstream=ngx_array_create(cf->pool,1,sizeof(ngx_guard_upstream_t))) == NULL){
            return NULL; 
        }
    }
    gus = smcf->guard_upstream->elts;
    for(i=0;i<smcf->guard_upstream->nelts;i++){
        gu =  gus[i];
        if(ngx_strncmp(upstream_name.data,gu.upstream_name.data,upstream_name.len) == 0){
            return "is duplicate";
        }
    }
    gup = ngx_array_push(smcf->guard_upstream);
    gup->upstream_name = upstream_name;
    gup->para_name = para_name;
    gup->server_setting_name = server_setting_name;
    gup->redirect_uri = redirect_uri;
    gup->uscf = NULL; 
    gup->server_data_settings = NULL; 
    gup->snmp_paras = NULL; 
    gup->snmp_session = NULL; 
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_snmp_post_conf(ngx_conf_t *cf){
    ngx_snmp_main_conf_t                 *smcf;
    ngx_guard_upstream_t                 *gus,gu;
    ngx_http_upstream_main_conf_t        *upmfs;
    ngx_http_upstream_srv_conf_t         *upsvrs,upsvr;
    ngx_snmp_paras_t                     *sps,sp;
    ngx_server_data_settings_t           *sds,sd;
    ngx_str_t                            upstream_name, para_name,server_setting_name;
    ngx_uint_t                           i,j,k,l,found;
    
    
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_snmp_module);
    gus = smcf->guard_upstream->elts;
    upmfs = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    upsvrs = upmfs->upstreams.elts;
    sps = smcf->snmp_paras->elts;
    sds = smcf->server_data_settings->elts;
    for(i=0;i<smcf->guard_upstream->nelts;i++){
        found = 0; 
        gu = gus[i];
        upstream_name = gu.upstream_name;
        para_name = gu.para_name;
        server_setting_name = gu.server_setting_name;
        for(j=0;j<upmfs->upstreams.nelts;j++){
            upsvr = upsvrs[i];
            if(ngx_strncmp(upstream_name.data,upsvr.host.data,upstream_name.len) == 0){
                for(k=0;k<smcf->snmp_paras->nelts;k++){
                    sp = sps[k];
                    if(ngx_strncmp(para_name.data,sp.name.data,para_name.len) == 0){
                        for(l=0;l<smcf->server_data_settings->nelts;l++){
                            sd = sds[l];
                            if(ngx_strncmp(server_setting_name.data,sd.name.data,server_setting_name.len)){
                                found = 1; 
                            }
                        }
                    }
                }
            }
        }
        if(found == 0){
            ngx_array_remove(smcf->guard_upstream,i);
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "No upstream:\"%V\" or SNMP parametes:\"%V\" or Server Data setting:\"%V\"",
                                    upstream_name,para_name,server_setting_name);
            
        }
    }
    if(ngx_http_snmp_initate_session(cf) != NGX_OK){
        return NGX_ERROR; 
    }
    return NGX_OK;
}

static ngx_uint_t 
ngx_array_remove(ngx_array_t *a,ngx_uint_t no){
    ngx_uint_t      i;
    void            *dst,*src;
    
    if(no >= a->nelts){
        return NGX_ERROR; 
    }
    for(i=no;i<(a->nelts -1);i++){
        dst = (u_char *) a->elts + a->size * i;
        src = (u_char *) a->elts + a->size * (i+1);
        ngx_memcpy(dst,src,a->size);
    }
    a->nelts--;
    return NGX_OK;
}

static ngx_int_t
ngx_http_snmp_initate_session(ngx_conf_t *cf){
    ngx_snmp_main_conf_t                 *smcf;
    ngx_guard_upstream_t                 *gus,gu;
    ngx_http_upstream_main_conf_t        *upmfs;
    ngx_http_upstream_srv_conf_t         *upsvrs,upsvr;
    ngx_http_upstream_server_t           *sers,ser; 
    ngx_snmp_paras_t                     *sps,sp;
    ngx_server_data_settings_t           *sds,sd;
    ngx_snmp_session_t                   *snmp_session,*ssps,ss;
    ngx_uint_t                           i,j,k,l;
    ngx_str_t                            upstream_name, para_name,server_setting_name,*server_ip;
    
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_snmp_module);
    gus = smcf->guard_upstream->elts;
    upmfs = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    upsvrs = upmfs->upstreams.elts;
    sps = smcf->snmp_paras->elts;
    sds = smcf->server_data_settings->elts;
    for(i=0;i<smcf->guard_upstream->nelts;i++){
        gu = gus[i];
        upstream_name = gu.upstream_name;
        para_name = gu.para_name;
        server_setting_name = gu.server_setting_name;
        for(j=0;j<upmfs->upstreams.nelts;j++){
            upsvr = upsvrs[i];
            if(ngx_strncmp(upstream_name.data,upsvr.host.data,upstream_name.len) == 0){
                if(gu.snmp_session == NULL){
                    if((gu.snmp_session = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_session_t))) == NULL){
                        return NGX_ERROR;
                    }
                }
                gu.uscf = &upsvr;
                sers = upsvr.servers->elts;
                for(k=0;k<upsvr.servers->nelts;k++){
                    ser = sers[k];
                    snmp_session = ngx_array_push(gu.snmp_session);
                    server_ip = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
                    if(server_ip == NULL){
                        return NGX_ERROR;
                    }
                    snmp_session->server_ip = (ngx_str_t)server_ip;
                    snmp_session->uscf = &upsvr;
                    if(ngx_http_snmp_get_server_ip(&ser,&server_ip) != NGX_OK){
                        return NGX_ERROR;
                    }
                    ngx_http_snmp_init_server_data(&snmp_session->server_data);
                    if(ngx_http_snmp_init_server_pdu(cf,snmp_session) == NGX_ERROR){
                        return NGX_ERROR;
                    }
                }
            }
        }
        for(j=0;j<smcf->snmp_paras->nelts;j++){
            sp = sps[j];
            if(ngx_strncmp(para_name.data,sp.name.data,sp.name.len) == 0){
                gu.snmp_paras = &sp;
                ssps = gu.snmp_session->elts;
                for(k=0;k<gu.snmp_session->nelts;k++){
                    ss = ssps[k];
                    ss.snmp_paras = &sp;
                    if(ngx_http_snmp_build_pdu(&ss,&sp) == NGX_ERROR){
                        return NGX_ERROR;
                    }
                } 
            }
        }
        for(j=0;j<smcf->server_data_settings->nelts;j++){
            sd = sds[j];
            if(ngx_strncmp(server_setting_name.data,sd.name.data,sd.name.len) == 0){
                gu.server_data_settings = &sd;
                ssps = gu.snmp_session->elts;
                for(k=0;k<gu.snmp_session->nelts;k++){
                    ss = ssps[k];
                    ss.server_data_settings = &sd;
                }
            }
        }
    }
    return NGX_OK;
}
    
static ngx_int_t 
ngx_http_snmp_init_process (ngx_cycle_t *cycle){
    ngx_http_guard_main_conf_t           *gmcf;
    ngx_guard_upstream_t                  gu,*gus;
    ngx_snmp_paras_t                      *sp;
    static ngx_event_t                    ev;
    ngx_int_t                             i;
    
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "SNMP collection event has been set.");
    ev.handler=ngx_http_snmp_event_handler;
    ev.log=cycle->log; 
    gmcf = (ngx_snmp_main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle,ngx_http_snmp_module);
    gus = gmcf->guard_upstream->elts;
    for(i=0;i<gmcf->guard_upstream->nelts;i++){
        gu = gus[i];
        ev.data = &gu;
        sp = gu.snmp_paras;
        ngx_add_timer(&ev, (sp->snmp_interval*1000));
    }
    return NGX_OK;
    
}

static ngx_int_t
ngx_http_snmp_get_server_ip(ngx_http_upstream_server_t *us,ngx_str_t **server_ip){
    u_char                       *p,*host,*last;
    size_t                       len;
 
    p = us.addrs->name.data;
    len = us.addrs->name.len;
    if (len >= 5 && ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        ngx_str_set(*server_ip, "127.0.0.1");        
    }
    else if(len && p[0] == '[') {
        host = us.addrs->name.data + 1;
        last = us.addrs->name.data + us.addrs->name.len;
        p = ngx_strlchr(host, last, ']');
        if (p == NULL) {
            return NGX_ERROR;
        }
        len = p - host;
        if (len == 0) {
            return NGX_ERROR;
        }
        host = host -1;
        *server_ip->data = host;
        *server_ip->len = len + 2;
    }
    else{
        host = us.addrs->name.data;
        last = us.addrs->name.data + us.addrs->name.len;
        p = ngx_strlchr(host, last, ':');
        if (p == NULL) {
            *server_ip->len = us.addrs->name.len;
        }
        else {
            *server_ip->len = p - host;
        }
        *server_ip->data = host;
    }
    return NGX_OK; 
}

static ngx_int_t
ngx_http_snmp_init_server_data(ngx_server_data_t *sd){
    sd->load_update_time = 0;  
    sd->swap_update_time = 0;  
    sd->cpu_load_value = 0;   
    sd->swap_used_value = 0;   
    sd->swapration_value = 0;  
    sd->freemem_value = 0;     
    sd->freemem_update_time = 0;
    sd->buffered_value = 0;    
    sd->buffered_update_time = 0;
    sd->cached_value = 0;      
    sd->cached_update_time = 0;
    sd->freemem_size = 0;      
    sd->freemem_update_time =0;
    return NGX_OK; 
}

static ngx_int_t
ngx_http_snmp_init_server_pdu(ngx_conf_t *cf,ngx_snmp_session_t *ss){
    
    if((ss->pdu_reqid = ngx_pcalloc(cf->pool,sizeof(ngx_str_t))) == NULL){
        return NGX_ERROR; 
    }
    if((ss->pdu_reqid->data = ngx_pcalloc(cf->pool,(sizeof(u_char)*len))) == NULL){
        return NGX_ERROR;
    }
    ss->pdu_reqid->len = 0;
    if((ss->pdu_head = ngx_pcalloc(cf->pool,sizeof(ngx_snmp_request_pdu_t))) == NULL){
        return NGX_ERROR;
    }
    if(ngx_http_snmp_init_str_for_pdu(cf,ss->pdu_head,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
        return NGX_ERROR;
    }
   
    if((ss->pdu_obj = ngx_pcalloc(cf->pool,sizeof(ngx_snmp_request_pdu_t))) == NULL){
        return NGX_ERROR;
    }
    if(ngx_http_snmp_init_str_for_pdu(cf,ss->pdu_obj,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
        return NGX_ERROR;
    }
    if(ngx_http_snmp_init_str_for_pdu(cf,ss->pdu,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
        return NGX_ERROR;
    }
    return NGX_OK; 
}

static ngx_int_t 
ngx_http_snmp_init_str_for_pdu(ngx_conf_t *cf,ngx_snmp_request_pdu_t *srp,ngx_int_t len){
    ngx_int_t          i;
    ngx_str_t          **p;
            
    for(i=0;i<SNMP_OBJ_NUM; i++){
        switch(i){
            case 0:
                p = &srp->cpu_load;
                break;
            case 1:
                p = &srp->mem_buffer;
                break;
            case 2:
                p = &srp->mem_cached;
                break;
            case 3:
                p = &srp->mem_free;
                break;
            case 4:
                p = &srp->mem_size;
                break;
            case 5:
                p = &srp->swap_free;
                break;
            case 6:
                p = &srp->swap_size;
                break;
            default:
                return NGX_ERROR;
                break;
        }
    }
    
    if((*p = ngx_pcalloc(cf->pool,sizeof(ngx_str_t))) == NULL){
        return NGX_ERROR; 
    }
    if((*p->data = ngx_pcalloc(cf->pool,(sizeof(u_char)*len))) == NULL){
        return NGX_ERROR;
    }
    *p->len = 0;
    return NGX_OK;
}
static ngx_int_t 
ngx_http_snmp_build_pdu(ngx_snmp_session_t *ss,ngx_snmp_paras_t *sp){
    ngx_str_t                   obj_oid,*srp; 
    ngx_int_t                   i;
    
    switch(sp->snmp_ver){
        case SNMP_VERSION_1:
            return NGX_ERROR;
            break; 
        case SNMP_VERSION_2C:
            ngx_http_snmp_build_request_id(ss);
            ngx_http_snmp_build_2c_pdu_head(ss,sp);
            for(i=0;i<SNMP_OBJ_NUM;i++){
                switch(i){
                    case 0:
                        obj_oid = sp->snmp_cpu_load_oid;
                        srp = ss->pdu_obj->cpu_load;
                        break;
                    case 1:
                        obj_oid = sp->snmp_mem_buffer_oid;
                        srp = ss->pdu_obj->mem_buffer;
                        break;
                    case 2:
                        obj_oid = sp->snmp_mem_cached_oid;
                        srp = ss->pdu_obj->mem_cached;
                        break;
                    case 3:
                        obj_oid = sp->snmp_mem_free_oid;
                        srp = ss->pdu_obj->mem_free;
                        break;
                    case 4:
                        obj_oid = sp->snmp_mem_size_oid;
                        srp = ss->pdu_obj->mem_size;
                        break;
                    case 5:
                        obj_oid = sp->snmp_swap_available_oid;
                        srp = ss->pdu_obj->swap_free;
                        break;
                    case 6:
                        obj_oid = sp->snmp_swap_size_oid;
                        srp = ss->pdu_obj->swap_size;
                        break;
                    default:
                        return NGX_ERROR;
                        break;
                }
                if(ngx_http_snmp_build_2c_oct(obj_oid,srp) == NGX_ERROR){
                    return NGX_ERROR;
                }
            }
        default:
            return NGX_ERROR;
            break;
    }
}

static ngx_int_t 
ngx_http_snmp_build_2c_oct(ngx_str_t *oid,ngx_str_t *pdup){
    u_char              *tmpoid,*suboid,*tmpber;
    ngx_uint_t           firstobj,secobj,nodeoid,suboid_len,suboid_pos,objlen;
    
    
    if(oid->len <2){
        return NGX_ERROR;
    }
    
    suboid = oid->data;
    objlen = suboid_pos = 0;
    for(;(tmpoid=ngx_strstr((const char *)oid->data,"."));){
        suboid_len = tmpoid - suboid;
        if(suboid_pos == 0){
            firstobj = ngx_atoi((const char *)suboid,suboid_len);
        }
        else if(suboid_pos == 1){
            secobj = ngx_atoi((const char *)suboid,suboid_len);
            nodeoid = 40 * firstobj + secobj; 
        }
        else{
            nodeoid = ngx_atoi((const char *)suboid,suboid_len);
        }
        if( suboid_pos !=0 ){
            objlen = ngx_http_snmp_build_ber(nodeoid,pdup,objlen);
        }
        suboid = ++tmpoid;
        suboid_pos++;
    }
    if(suboid != tmpoid){
        if(suboid_pos == 1){
            secobj = ngx_atoi((const char *)suboid,objlen);
            nodeoid = 40 * firstobj + secobj; 
        }
        else{
            nodeoid = ngx_atoi((const char *)suboid,objlen);
        }
        objlen = ngx_http_snmp_build_ber(nodeoid,pdup,objlen);
    }
    pdup->len = objlen;
    tmpber = pdup->data;
    tmpber[objlen++] = 0x05;
    tmpber[objlen++] = 0x00;
    tmpber[objlen] = '\0';
    return NGX_OK;
}

static ngx_int_t 
ngx_http_snmp_build_ber(ngx_uint_t nodeoid, ngx_str_t *pdup,ngx_uint_t objlen){
    u_char   *buf;
    
    buf = pdup->data;
    if(objlen < 0){
        objlen = 0;
    }
    if(nodeoid < 0x80){
        buf[objlen] = nodeoid;
    }
    else if(nodeoid < 0x4000){
        buf[objlen++] = ((nodeoid >> 7) | 0x80);
        buf[objlen] = (nodeoid & 0x07f);
    }
    else if (nodeoid < 0x200000) {
        buf[objlen++] = ((nodeoid >> 14) | 0x80);
        buf[objlen++] = ((nodeoid >> 7 & 0x7f) | 0x80);
        buf[objlen] = (nodeoid & 0x07f);
    }
    else if (nodeoid < 0x10000000 ) {
        buf[objlen++] = ((nodeoid >> 21) | 0x80);
        buf[objlen++] = ((nodeoid >> 14 & 0x7f) | 0x80);
        buf[objlen++] = ((nodeoid >> 7 & 0x7f) | 0x80);
        buf[objlen] = (nodeoid & 0x07f);
    }
    else{
        buf[objlen++] = ((nodeoid >> 28) | 0x80);
        buf[objlen++] = ((nodeoid >> 21 & 0x7f) | 0x80);
        buf[objlen++] = ((nodeoid >> 14 & 0x7f) | 0x80);
        buf[objlen++] = ((nodeoid >> 7 & 0x7f) | 0x80);
        buf[objlen] = (nodeoid & 0x07f);
    }
    return(++objlen);
}

static ngx_int_t 
ngx_http_snmp_build_request_id(ngx_snmp_session_t *ss){
    ngx_int_t               now,i,j,k;
    u_char                  *reqid; 
    now =  ngx_time();
    k = 0;
    reqid = ss->pdu_reqid->data;
    for(;now>0;){
	j = now & 0xFF;
        reqid[k] = j;
        k++;
	now >>=8;
    }
    ss->pdu_reqid->len = k;
    return NGX_OK; 
}

static ngx_int_t 
ngx_http_snmp_build_2c_pdu_head(ngx_snmp_session_t *ss,ngx_snmp_paras_t *sp){
    ngx_int_t           i,j,k;
    ngx_str_t           *obj;
    u_char              *head;
    
    for(i=0;i<SNMP_OBJ_NUM; i++){
        switch(i){
            case 0:
                obj = ss->pdu_head->cpu_load;
                break;
            case 1:
                obj = ss->pdu_head->mem_buffer;
                break;
            case 2:
                obj = ss->pdu_head->mem_cached;
                break;
            case 3:
                obj = ss->pdu_head->mem_free;
                break;
            case 4:
                obj = ss->pdu_head->mem_size;
                break;
            case 5:
                obj = ss->pdu_head->swap_free;
                break;
            case 6:
                obj = ss->pdu_head->swap_size;
                break;
            default:
                return NGX_ERROR;
                break;
        }
    }
    head = obj->data;
    j = 0;
    head[j++] = DATA_ZERO;
    head[j++] = DATA_ZERO;
    head[j++] = SNMP_DATA_TYPE_SEQ;
    head[j++] = 20 + sp->snmp_community.len + ss->pdu_reqid->len + obj_len;
    head[j++] = SNMP_DATA_TYPE_INT;
    head[j++] = 0x01;
    head[j++] = sp->snmp_ver;
    head[j++] = SNMP_DATA_TYPE_OCTSTR;
    head[j++] = sp->snmp_community.len;
    for(k = 0; k<sp->snmp_community.len; k++){
        head[j++] = sp->snmp_community.data[k];
    }
    head[i] = SNMP_GET_REQUEST;
    obj->len = i + 1; 
    return NGX_OK;
}

static void ngx_http_snmp_event_handler(ngx_event_t *ev){ 
    ngx_guard_upstream_t            *gu;
    ngx_snmp_paras_t                *sp;
    ngx_snmp_session_t              *sss,ss;
    ngx_int_t                       i;
    
    gu = (ngx_guard_upstream_t *)ev->data;
    sp = gu->snmp_paras;
    ngx_add_timer(ev,sp->snmp_interval*1000);
    sss = gu->snmp_session->elts;
    for(i = 0;i<gu->snmp_session->nelts;i++){
        ss = sss[i];
        if(ngx_http_snmp_send_pdu(&ss) != NGX_OK){
            ngx_log_error(NGX_LOG_EMERG, rev->log, 0, 
                "Sending SNMP Request PDU Error.");
            return NGX_ERROR;
        }
    }
}

static ngx_int_t
ngx_http_snmp_send_pdu(ngx_snmp_session_t *ss){
    ngx_str_t                   i,j; 
    
    if(ngx_http_snmp_complete_pdu(ss) != NGX_OK){
        return NGX_ERROR;
    }
    

}

static ngx_int_t
ngx_http_snmp_complete_pdu(ngx_snmp_session_t *ss){
    ngx_str_t               *pdu;
    ngx_str_t               *pdu_head,*pdu_obj,*pdu;
    u_char                  *src_char,*dst_char;
    ngx_int_t               i,j,k;
    
    ngx_http_snmp_build_request_id(ss);
    for(i=0;i<SNMP_OBJ_NUM;i++){
        switch(i){
            case 0:
                pdu_head = ss->pdu_head->cpu_load;
                pdu_obj = ss->pdu_obj->cpu_load;
                pdu =  ss->pdu->cpu_load;
                pdu->len = 0;
                break;
            case 1:
                pdu_head = ss->pdu_head->mem_buffer;
                pdu_obj = ss->pdu_obj->mem_buffer;
                pdu =  ss->pdu->mem_buffer;
                pdu->len = 0;
                break;
            case 2:
                pdu_head = ss->pdu_head->mem_cached;
                pdu_obj = ss->pdu_obj->mem_cached;
                pdu =  ss->pdu->mem_cached;
                pdu->len = 0;
                break;
            case 3:
                pdu_head = ss->pdu_head->mem_free;
                pdu_obj = ss->pdu_obj->mem_free;
                pdu =  ss->pdu->mem_free;
                pdu->len = 0;
                break;
            case 4:
                pdu_head = ss->pdu_head->mem_size;
                pdu_obj = ss->pdu_obj->mem_size;
                pdu =  ss->pdu->mem_size;
                pdu->len = 0;
                break;
            case 5:
                pdu_head = ss->pdu_head->swap_free;
                pdu_obj = ss->pdu_obj->swap_free;
                pdu =  ss->pdu->swap_free;
                pdu->len = 0;
                break;
            case 5:
                pdu_head = ss->pdu_head->swap_size;
                pdu_obj = ss->pdu_obj->swap_size;
                pdu =  ss->pdu->swap_size;
                pdu->len = 0;
                break;
            default:
                return NGX_ERROR;
                break;
        }
        j = 0;
        src_char = pdu_head->data;
        dst_char = pdu->data;
        for(k=0;i<pdu_head->len;k++){
            dst_char[j++] = src_char[k]; 
        }
        dst_char[j++] = 13 + ss->pdu_reqid->len + pdu_obj->len;
        dst_char[j++] = SNMP_DATA_TYPE_INT;
        dst_char[j++] = ss->pdu_reqid->len;
        src_char =  ss->pdu_reqid->data;
        for(k=0;k<ss->pdu_reqid->len;k++){
            dst_char[j++] = src_char[k];
        }
        dst_char[j++] = SNMP_DATA_TYPE_INT;
        dst_char[j++] = 0x01;
        dst_char[j++] = 0x00;
        dst_char[j++] = SNMP_DATA_TYPE_INT;
        dst_char[j++] = 0x01;
        dst_char[j++] = 0x00;
        dst_char[j++] = SNMP_DATA_TYPE_SEQ;
        dst_char[j++] = 3 + pdu_obj->len;
        dst_char[j++] = SNMP_DATA_TYPE_SEQ;
        dst_char[j++] = 1 + pdu_obj->len;
        dst_char[j++] = SNMP_DATA_TYPE_OBJID;
        dst_char[j++] = pdu_obj->len - 1;
        src_char = pdu_obj->data;
        for(k=0;k<pdu_obj->len;k++){
            dst_char[j++] = src_char[k];
        }
    }
    return NGX_OK;
}