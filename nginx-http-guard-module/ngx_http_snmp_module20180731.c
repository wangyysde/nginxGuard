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
    smcf->guard_upstream = NULL;
    smcf->snmp_perfs = NULL;
    return smcf; 
}

static char *
ngx_http_snmp_paras_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                         name; 
    ngx_snmp_paras_t                  *sps,sp,*spp; 
    ngx_str_t                         *value;
    ngx_snmp_main_conf_t              *smcf;
    ngx_snmp_oid_t                    *snmp_oid;
    ngx_uint_t                        i,num; 
    
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
    spp->snmp_interval = SNMP_DEFAULT_INTERVAL;
    spp->snmp_ver = SNMP_VERSION_2C;
    spp->snmp_port = SNMP_DEFAULT_PORT; 
    spp->snmp_socket_type = SNMP_SOCKET_UDP;
    ngx_str_set(&spp->snmp_community,SNMP_DEFAULT_COMMUNITY);
    ngx_str_set(&spp->snmp_context_name,SNMP_DEFAULT_CONTEXTNAME);
    spp->snmp_security_level = SNMP_SECURITY_LEVEL_NOAUTHNOPRIV;
    spp->snmp_auth_protocol = SNMP_AUTH_PROTOCOL_MD5;
    ngx_str_set(&spp->snmp_auth_phrase,SNMP_DEFAULT_AUTHPHRASE);
    spp->snmp_privacy_protocol = SNMP_AUTH_PRIVACY_DES;
    ngx_str_set(&spp->snmp_privacy_phrase,SNMP_DEFAULT_PRIVACYPHRASE);
    if((spp->snmp_oids = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_oid_t)))
            ==NULL)
    {
           return NULL;
    }
    num =  sizeof(snmp_oids)/sizeof(ngx_snmp_oid_t);
    for(i=0;i<num;i++){
        snmp_oid = ngx_array_push(spp->snmp_oids);
        if (snmp_oid == NULL) {
            return NGX_CONF_ERROR;
        }
        snmp_oid->id = snmp_oids[i].id;
        snmp_oid->obj_name = snmp_oids[i].obj_name;
        snmp_oid->default_oid = snmp_oids[i].default_oid;
        snmp_oid->conf_oid = snmp_oids[i].conf_oid;
     }
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
    ngx_int_t                         i,num;
    ngx_snmp_oid_t                    *oids,oid; 
    
    
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
    num =  sizeof(snmp_oids)/sizeof(ngx_snmp_oid_t);
    oids = spp->snmp_oids->elts;
    for(i=0;i<num;i++){
        if(ngx_strncmp(var.data,snmp_oids[i].obj_name.data,var.len) == 0){
            oid = oids[i];
            oid.conf_oid = varvalue;
            flag = 1;
        }
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
    ngx_snmp_perf_group_t                       *sps,sp,*spp; 
    ngx_str_t                                   *value;
    ngx_snmp_main_conf_t                        *smcf;
    ngx_snmp_perf_t                             *sperf;
    ngx_uint_t                                   i,num; 
    
    value = cf->args->elts;
    name =  value[1];
    
    smcf = (ngx_snmp_main_conf_t *)conf;
    if(smcf->snmp_perfs == NULL){
        if((smcf->snmp_perfs = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_perf_group_t)))
            ==NULL)
        {
                return NULL; 
        }
    }
    sps = smcf->snmp_perfs->elts;
    for (i = 0;  i < smcf->snmp_perfs->nelts;i++) {
        sp = sps[i];
        if(ngx_strncmp(name.data,sp.perf_group.data,name.len) == 0){
            return "is duplicate";
        }
    }
    spp = ngx_array_push(smcf->snmp_perfs);
    ngx_memzero(spp, sizeof(ngx_snmp_perf_group_t));
    spp->perf_group = name;
    if((spp->snmp_perfs = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_perf_t)))
            ==NULL){
        return NULL;
    }
    num = sizeof(snmp_perfs)/sizeof(ngx_snmp_perf_t);
    for(i=0;i<num;i++){
        sperf = ngx_array_push(spp->snmp_perfs);
        ngx_memzero(sperf, sizeof(ngx_snmp_perf_t));
        sperf->id = snmp_perfs[i].id;
        sperf->obj_name = snmp_perfs[i].obj_name;
        sperf->default_max = snmp_perfs[i].default_max;
        sperf->default_weight = snmp_perfs[i].default_weight;
        sperf->conf_max = snmp_perfs[i].conf_max;
        sperf->conf_weight = snmp_perfs[i].conf_weight;
    }
    return NGX_CONF_OK;
}

static char *
ngx_snmp_perf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                                   *value;
    ngx_snmp_perf_t                             *sp;
    ngx_str_t                                   var; 
    ngx_str_t                                   max,weight;
    ngx_uint_t                                  flag,i,num;
    
    value = cf->args->elts;
    sp = (ngx_snmp_perf_t *)conf;
    var = value[1]; 
    max = value[2];
    weight = value[3];
    
    flag = 0;
    num = sizeof(snmp_perfs)/sizeof(ngx_snmp_perf_t);
    for(i=0;i<num;i++){
        if(ngx_strncmp(var.data,snmp_perfs[i].obj_name.data,var.len) == 0){
            sp->conf_max = ngx_atoi(max.data,max.len);
            sp->conf_weight = ngx_atoi(weight.data,weight.len);
            flag = 1; 
        }
    }
    if(flag == 0){
        return "unavailable item";
    }
    return NGX_CONF_OK;
}

static char *
ngx_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t                            *value;
    ngx_str_t                             upstream_name, para_name,perf_group_name,redirect_uri;
    ngx_snmp_main_conf_t                 *smcf;
    ngx_guard_upstream_t                 gu,*gus,*gup;
    ngx_uint_t                           i; 
    value =  cf->args->elts;
    upstream_name = value[1];
    para_name = value[2];
    perf_group_name = value[3];
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
    gup->perf_group_name = perf_group_name;
    gup->redirect_uri = redirect_uri;
    gup->uscf = NULL; 
    gup->snmp_perf_group = NULL; 
    gup->snmp_paras = NULL; 
    gup->snmp_server_data = NULL; 
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_snmp_post_conf(ngx_conf_t *cf){
    ngx_snmp_main_conf_t                 *smcf;
    ngx_guard_upstream_t                 *gus,gu;
    ngx_http_upstream_main_conf_t        *upmfs;
    ngx_http_upstream_srv_conf_t         *upsvrs,upsvr;
    ngx_snmp_paras_t                     *sps,sp;
    ngx_snmp_perf_group_t                *perfs,perf;
    ngx_str_t                            upstream_name, para_name,perf_group_name;
    ngx_uint_t                           i,j,k,l,found;
    
    
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_snmp_module);
    gus = smcf->guard_upstream->elts;
    upmfs = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    upsvrs = upmfs->upstreams.elts;
    sps = smcf->snmp_paras->elts;
    perfs = smcf->snmp_perfs->elts;
    for(i=0;i<smcf->guard_upstream->nelts;i++){
        found = 0; 
        gu = gus[i];
        upstream_name = gu.upstream_name;
        para_name = gu.para_name;
        perf_group_name = gu.perf_group_name;
        for(j=0;j<upmfs->upstreams.nelts;j++){
            upsvr = upsvrs[i];
            if(ngx_strncmp(upstream_name.data,upsvr.host.data,upstream_name.len) == 0){
                for(k=0;k<smcf->snmp_paras->nelts;k++){
                    sp = sps[k];
                    if(ngx_strncmp(para_name.data,sp.name.data,para_name.len) == 0){
                        for(l=0;l<smcf->snmp_perfs->nelts;l++){
                            perf = perfs[l];
                            if(ngx_strncmp(perf_group_name.data,perf.perf_group.data,perf_group_name.len)){
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
                                   "No upstream:\"%V\" or SNMP parametes:\"%V\" or perf group name:\"%V\"",
                                    upstream_name,para_name,perf_group_name);
            
        }
    }
    if(ngx_http_snmp_initate_server_data(cf) != NGX_OK){
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
ngx_http_snmp_initate_server_data(ngx_conf_t *cf){
    ngx_snmp_main_conf_t                 *smcf;
    ngx_guard_upstream_t                 *gus,gu;
    ngx_http_upstream_main_conf_t        *upmfs;
    ngx_http_upstream_srv_conf_t         *upsvrs,upsvr;
    ngx_http_upstream_server_t           *sers,ser; 
    ngx_snmp_paras_t                     *sps,sp;
    ngx_snmp_obj_data_t                  *obj_datas,obj_data;
    ngx_snmp_perf_group_t                *perfs,perf;
    ngx_snmp_perf_t                      *ps,p;
    ngx_snmp_server_data_t               *server_datas,server_data;
    ngx_uint_t                           i,j,k,l,m,n;
    ngx_int_t                            obj_id,found;
    ngx_str_t                            upstream_name, para_name,perf_group_name,*server_ip,obj_name,perf_name;
    
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_snmp_module);
    gus = smcf->guard_upstream->elts;
    upmfs = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    upsvrs = upmfs->upstreams.elts;
    sps = smcf->snmp_paras->elts;
    perfs = smcf->snmp_perfs->elts;

    for(i=0;i<smcf->guard_upstream->nelts;i++){
        gu = gus[i];
        upstream_name = gu.upstream_name;
        para_name = gu.para_name;
        perf_group_name = gu.perf_group_name;
        for(j=0;j<upmfs->upstreams.nelts;j++){
            upsvr = upsvrs[i];
            if(ngx_strncmp(upstream_name.data,upsvr.host.data,upstream_name.len) == 0){
                if(gu.snmp_server_data == NULL){
                    if((gu.snmp_server_data = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_server_data_t))) == NULL){
                        return NGX_ERROR;
                    }
                }
                gu.uscf = &upsvr;
                sers = upsvr.servers->elts;
                for(k=0;k<upsvr.servers->nelts;k++){
                    ser = sers[k];
                    server_datas = ngx_array_push(gu.snmp_server_data);
                    server_ip = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
                    if(server_ip == NULL){
                        return NGX_ERROR;
                    }
                    server_datas->server_ip = *server_ip;
                    server_datas->name = ser.name;
                    server_datas->pool = cf->pool;
                    server_datas->uscf = &upsvr;
                    if(ngx_http_snmp_get_server_ip(&ser,&server_ip) != NGX_OK){
                        return NGX_ERROR;
                    }
                    if((server_datas->obj_data = ngx_array_create(cf->pool,1,sizeof(ngx_snmp_obj_data_t))) == NULL){
                        return NGX_ERROR;
                    }
                    ngx_http_snmp_init_obj_data(cf,server_datas);
                }
            }
        }
        for(j=0;j<smcf->snmp_paras->nelts;j++){
            sp = sps[j];
            if(ngx_strncmp(para_name.data,sp.name.data,sp.name.len) == 0){
                gu.snmp_paras = &sp;
                server_datas = gu.snmp_server_data->elts;
                for(k=0;k<gu.snmp_server_data->nelts;k++){
                    server_data = server_datas[k];
                    server_data.snmp_paras = &sp;
                    if(ngx_http_snmp_build_pdu(&server_data,&sp) == NGX_ERROR){
                        return NGX_ERROR;
                    }
                } 
            }
        }
        for(j=0;j<smcf->snmp_perfs->nelts;j++){
            perf = perfs[j];
            if(ngx_strncmp(perf_group_name.data,perf.perf_group.data,perf.perf_group.len) == 0){
                gu.snmp_perf_group = &perf;
                server_datas = gu.snmp_server_data->elts;
                for(k=0;k<gu.snmp_server_data->nelts;k++){
                    server_data = server_datas[k];
                    obj_datas = server_data.obj_data->elts;
                    for(l=0;l<server_data.obj_data->nelts;l++){
                        obj_data = obj_datas[l];
                        obj_id = obj_data.obj_id;
                        obj_name = snmp_oids[obj_id].obj_name;
                        n = sizeof(obj_perf_relation)/sizeof(obj_perf_t);
                        for(m=0;m<n;m++){
                            if(ngx_strncmp(obj_perf_relation[m].obj_name.data,obj_name.data,obj_name.len) == 0){
                                perf_name = obj_perf_relation[m].perf_name;
                            }
                        }
                        ps = perf.snmp_perfs->elts;
                        found = 0;
                        for(m=0;m<perf.snmp_perfs->nelts;m++){
                            p = ps[m];
                            if(ngx_strncmp(p.obj_name.data,perf_name.data,perf_name.len) == 0){
                                obj_data.snmp_perf = &p;
                                found = 1;
                            }
                        }
                        if(!found){
                            obj_data.snmp_perf = NULL;
                        }
                    }
                }
            }
        }
    }
    return NGX_OK;
}
    
static ngx_int_t 
ngx_http_snmp_init_process(ngx_cycle_t *cycle){
    ngx_snmp_main_conf_t                *gmcf;
    ngx_guard_upstream_t                  gu,*gus;
    ngx_snmp_paras_t                      *sp;
    static ngx_event_t                    ev;
    ngx_uint_t                             i;
    
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
    ngx_str_t                    *srv_ip;
    
    srv_ip = *server_ip; 
    p = us->addrs->name.data;
    len = us->addrs->name.len;
    if (len >= 5 && ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        ngx_str_set(srv_ip, "127.0.0.1");        
    }
    else if(len && p[0] == '[') {
        host = us->addrs->name.data + 1;
        last = us->addrs->name.data + us->addrs->name.len;
        p = ngx_strlchr(host, last, ']');
        if (p == NULL) {
            return NGX_ERROR;
        }
        len = p - host;
        if (len == 0) {
            return NGX_ERROR;
        }
        host = host -1;
        srv_ip->data = host; 
        srv_ip->len = len + 2;
    }
    else{
        host = us->addrs->name.data;
        last = us->addrs->name.data + us->addrs->name.len;
        p = ngx_strlchr(host, last, ':');
        if (p == NULL) {
            srv_ip->len = us->addrs->name.len;
        }
        else {
            srv_ip->len = p - host;
        }
        srv_ip->data = host;
    }
    return NGX_OK; 
}

static ngx_int_t
ngx_http_snmp_init_obj_data(ngx_conf_t *cf,ngx_snmp_server_data_t *server_data){
    ngx_snmp_obj_data_t                *obj_data; 
    ngx_int_t                           i,num;
    
    num = sizeof(snmp_oids)/sizeof(ngx_snmp_oid_t);
    for(i=0;i<num;i++){
        obj_data = ngx_array_push(server_data->obj_data);
        obj_data->obj_id = i;
        obj_data->snmp_obj = NULL;
        obj_data->snmp_perf = NULL; 
        obj_data->last_update_time = 0;
        obj_data->last_value = 0;
        obj_data->update_time = 0;
        obj_data->value = 0;
        obj_data->request_id = 0;
        obj_data->receive_id = 0;
        obj_data->log = NULL; 
        obj_data->server_data = NULL; 
        obj_data->peer = NULL; 
        if((obj_data->pc=ngx_pcalloc(cf->pool,sizeof(ngx_peer_connection_t)))==NULL){
            return NGX_ERROR;
            obj_data->pc->sockaddr = NULL;
        }
        if(ngx_http_snmp_initate_str(cf,&obj_data->receive_buf,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
            return NGX_ERROR;
        }
        if(ngx_http_snmp_initate_str(cf,&obj_data->pdu_reqid,SNMP_REQUEST_ID_LEN) == NGX_ERROR){
            return NGX_ERROR;
        }
        if(ngx_http_snmp_initate_str(cf,&obj_data->pdu_head,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
            return NGX_ERROR;
        }
        if(ngx_http_snmp_initate_str(cf,&obj_data->pdu_obj,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
            return NGX_ERROR;
        }
        if(ngx_http_snmp_initate_str(cf,&obj_data->pdu,SNMP_MAX_PDU_LENGTH) == NGX_ERROR){
            return NGX_ERROR;
        }
        obj_data->c = NULL; 
    }
    return NGX_OK; 
}

static ngx_int_t
ngx_http_snmp_initate_str(ngx_conf_t *cf,ngx_str_t **str,ngx_int_t len){
    ngx_str_t           *string; 
    string = *str; 
    
    if((string = ngx_pcalloc(cf->pool,sizeof(ngx_str_t))) == NULL){
        return NGX_ERROR;
    }
    if((string->data = ngx_pcalloc(cf->pool,sizeof(u_char)*len)) == NULL){
        return NGX_ERROR;
    }
    string->len = 0;
    return NGX_OK;
}

static ngx_int_t 
ngx_http_snmp_build_pdu(ngx_snmp_server_data_t *server_data,ngx_snmp_paras_t *sp){
    
    switch(sp->snmp_ver){
        case SNMP_VERSION_1:
            return NGX_ERROR;
            break; 
        case SNMP_VERSION_2C:
            ngx_http_snmp_build_request_id(server_data);
            ngx_http_snmp_build_2c_oct(server_data);
            ngx_http_snmp_build_2c_pdu_head(server_data,sp);
        default:
            return NGX_ERROR;
            break;
    }
}

static ngx_int_t 
ngx_http_snmp_build_2c_oct(ngx_snmp_server_data_t *server_data){
    u_char              *tmpoid,*suboid,*tmpber;
    ngx_uint_t           firstobj,secobj,nodeoid,suboid_len,suboid_pos,objlen;
    ngx_snmp_obj_data_t  *obj_datas,obj_data;
    ngx_snmp_paras_t      *paras;
    ngx_snmp_oid_t        *paras_oids,para_oid; 
    ngx_str_t             *oid,*pdup;
    ngx_uint_t            i;
    
    paras = server_data->snmp_paras;
    paras_oids = paras->snmp_oids->elts;
    obj_datas = server_data->obj_data->elts;
    
    for(i=0;i<server_data->obj_data->nelts;i++){
        obj_data = obj_datas[i];
        para_oid = paras_oids[i];
        obj_data.snmp_obj = &para_oid;
        oid =  &para_oid.conf_oid;
        pdup = obj_data.pdu_obj;
        suboid = oid->data;
        objlen = suboid_pos = 0;
        tmpoid=(u_char *)ngx_strstr(oid->data,".");
        for(;(tmpoid != NULL);){
            suboid_len = tmpoid - suboid;
            if(suboid_pos == 0){
                firstobj = ngx_atoi(suboid,suboid_len);
            }
            else if(suboid_pos == 1){
                secobj = ngx_atoi(suboid,suboid_len);
                nodeoid = 40 * firstobj + secobj; 
            }
            else{
                nodeoid = ngx_atoi(suboid,suboid_len);
            }
            if( suboid_pos !=0 ){
                objlen = ngx_http_snmp_build_ber(nodeoid,pdup,objlen);
            }
            suboid = ++tmpoid;
            suboid_pos++;
            tmpoid=(u_char *)ngx_strstr(oid->data,".");
        }
        if(suboid != tmpoid){
            if(suboid_pos == 1){
                secobj = ngx_atoi(suboid,objlen);
                nodeoid = 40 * firstobj + secobj; 
            }
            else{
                nodeoid = ngx_atoi(suboid,objlen);
            }
            objlen = ngx_http_snmp_build_ber(nodeoid,pdup,objlen);
        }
        pdup->len = objlen;
        tmpber = pdup->data;
        tmpber[objlen++] = 0x05;
        tmpber[objlen++] = 0x00;
        tmpber[objlen] = '\0';
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_http_snmp_build_ber(ngx_uint_t nodeoid, ngx_str_t *pdup,ngx_int_t objlen){
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
ngx_http_snmp_build_request_id(ngx_snmp_server_data_t *server_data){
    ngx_uint_t               now,i,j,k,l;
    u_char                  *reqid,*id; 
    ngx_snmp_obj_data_t     *obj_datas,obj_data;
    
    obj_datas = server_data->obj_data->elts;
     k = 0;
    for(i=0;i<server_data->obj_data->nelts;i++){
        obj_data=obj_datas[i];
        if(i == 0){
           now =  ngx_time();
           reqid=obj_data.pdu_reqid->data;
           for(;now>0;){
                j = now & 0xFF;
                reqid[k] = j;
                k++;
                now >>=8;
            }
        }
        else{
            id = obj_data.pdu_reqid->data;
            for(l=0;l<k;l++){
                id[l] = reqid[l];
            }
        }
         obj_data.pdu_reqid->len = k;
         obj_data.request_id = now;
    }
    return NGX_OK; 
}

static ngx_int_t 
ngx_http_snmp_build_2c_pdu_head(ngx_snmp_server_data_t *server_data,ngx_snmp_paras_t *sp){
    ngx_uint_t           i,j,k;
    u_char              *head;
    ngx_snmp_obj_data_t     *obj_datas, obj_data;
    
    obj_datas = server_data->obj_data->elts;
    for(i=0;i<server_data->obj_data->nelts;i++){
        obj_data = obj_datas[i];
        obj_data.server_data = server_data;
        obj_data.peer->name = server_data->name;
        obj_data.peer->sockaddr = (struct sockaddr *)server_data->server_ip.data;
        head = obj_data.pdu_head->data;
        j = 0;
        head[j++] = DATA_ZERO;
        head[j++] = DATA_ZERO;
        head[j++] = SNMP_DATA_TYPE_SEQ;
        head[j++] = 20 + sp->snmp_community.len + obj_data.pdu_reqid->len + obj_data.pdu_obj->len;
        head[j++] = SNMP_DATA_TYPE_INT;
        head[j++] = 0x01;
        head[j++] = sp->snmp_ver;
        head[j++] = SNMP_DATA_TYPE_OCTSTR;
        head[j++] = sp->snmp_community.len;
        for(k = 0; k<sp->snmp_community.len; k++){
            head[j++] = sp->snmp_community.data[k];
        }
        head[i] = SNMP_GET_REQUEST;
        obj_data.pdu_head->len = i + 1; 
    }
    return NGX_OK;
}

static void ngx_http_snmp_event_handler(ngx_event_t *ev){ 
    ngx_guard_upstream_t            *gu;
    ngx_snmp_paras_t                *sp;
    ngx_snmp_server_data_t          *server_datas,server_data; 
    ngx_snmp_obj_data_t             *obj_datas,obj_data;              
    ngx_uint_t                       i,j;
    
    gu = (ngx_guard_upstream_t *)ev->data;
    sp = gu->snmp_paras;
    ngx_add_timer(ev,sp->snmp_interval*1000);
    server_datas = gu->snmp_server_data->elts;
    for(i=0;i<gu->snmp_server_data->nelts;i++){
        server_data = server_datas[i];
        obj_datas = server_data.obj_data->elts;
        for(j=0;j<server_data.obj_data->nelts;j++){
            obj_data = obj_datas[j];
            if(obj_data.log == NULL){
                obj_data.log =  ev->log;
            }
            if(ngx_http_snmp_send_pdu(&obj_data) != NGX_OK){
                ngx_log_error(NGX_LOG_WARN, obj_data.log, 0, 
                "Sending SNMP Request PDU to Server:%V for Object:%V Error.",server_data.server_ip,snmp_oids[j].obj_name);
            }
            else{
                ngx_log_error(NGX_LOG_WARN, obj_data.log, 0, 
                "Sending SNMP Request PDU to Server:%V for Object:%V Successful.",server_data.server_ip,snmp_oids[j].obj_name);
            }
        }
    }
}

static ngx_int_t
ngx_http_snmp_send_pdu(ngx_snmp_obj_data_t *obj_data){
    ngx_int_t                                  rc; 
    ngx_peer_connection_t                      *pc;
    struct sockaddr_in                         *sin;
    
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    
    if(ngx_http_snmp_complete_pdu(obj_data) != NGX_OK){
        return NGX_ERROR;
    }
    if(obj_data->c == NULL || obj_data->c->destroyed || obj_data->c->close){
        pc =  obj_data->pc;
        if(pc->sockaddr == NULL){
            rc = ngx_parse_addr(obj_data->server_data->pool,obj_data->peer,
                obj_data->server_data->server_ip.data,obj_data->server_data->server_ip.len);
            switch (rc){
                case NGX_OK:
                    break;
                case NGX_DECLINED:
                    ngx_log_error(NGX_LOG_ERR,obj_data->log, 0,
                        "upstream invalid server address:\"%V\"",obj_data->server_data->server_ip);
                default:
                    return NGX_ERROR;
                    
            }
            switch (obj_data->peer->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
                case AF_INET6:
                    sin6 = (struct sockaddr_in6 *) obj_data->peer->sockaddr;
                    sin6->sin6_port = htons((in_port_t)obj_data->server_data->snmp_para.snmp_port);
                    break;
#endif
                default: /* AF_INET */
                    sin = (struct sockaddr_in *) obj_data->peer->sockaddr;
                    sin->sin_port = htons((in_port_t) obj_data->server_data->snmp_paras->snmp_port);
                    break;
            }
        }
        pc->local = NULL; 
        pc->log = obj_data->log;
        pc->get = ngx_http_snmp_get_peer;
        pc->free = ngx_http_snmp_free_peer;
        pc->data = obj_data;
        pc->type = obj_data->server_data->snmp_paras->snmp_socket_type;
        pc->socklen = obj_data->peer->socklen;
        pc->sockaddr = obj_data->peer->sockaddr;
        pc->name = &obj_data->server_data->name;
        rc = ngx_event_connect_peer(pc);
        if (rc != NGX_OK && rc != NGX_AGAIN ) {
            ngx_log_error(NGX_LOG_EMERG,obj_data->log, 0,"Create snmp connection failed");
            return NGX_ERROR;
        }
        obj_data->c = pc->connection;
    }
    obj_data->c->data = obj_data;
    obj_data->c->pool = obj_data->server_data->pool;
    obj_data->c->read->handler = ngx_http_snmp_recv;
    obj_data->c->write->handler = ngx_http_snmp_dummy_send;
    ngx_http_snmp_send(obj_data);
    if(obj_data->c->write->timer_set){
        ngx_del_timer(obj_data->c->write);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_snmp_complete_pdu(ngx_snmp_obj_data_t *obj_data){
    u_char                  *src_char,*dst_char;
    ngx_uint_t               i,j;
    
    ngx_http_snmp_rebuild_request_id(obj_data);
    j = 0;
    src_char = obj_data->pdu_head->data;
    dst_char = obj_data->pdu->data;
    for(i=0;i<obj_data->pdu_head->len; i++){
        dst_char[j++] = src_char[i]; 
    }
    dst_char[j++] = 13 + obj_data->pdu_reqid->len + obj_data->pdu_obj->len;
    dst_char[j++] = SNMP_DATA_TYPE_INT;
    dst_char[j++] = obj_data->pdu_reqid->len;
    src_char = obj_data->pdu_reqid->data;
    for(i=0;i<obj_data->pdu_reqid->len;i++){
        dst_char[j++] = src_char[i];
    }
    dst_char[j++] = SNMP_DATA_TYPE_INT;
    dst_char[j++] = 0x01;
    dst_char[j++] = 0x00;
    dst_char[j++] = SNMP_DATA_TYPE_INT;
    dst_char[j++] = 0x01;
    dst_char[j++] = 0x00;
    dst_char[j++] = SNMP_DATA_TYPE_SEQ;
    dst_char[j++] = 3 + obj_data->pdu_obj->len; 
    dst_char[j++] = SNMP_DATA_TYPE_SEQ;
    dst_char[j++] = 1 + obj_data->pdu_obj->len; 
    dst_char[j++] = SNMP_DATA_TYPE_OBJID;
    dst_char[j++] = obj_data->pdu_obj->len - 1;
    src_char = obj_data->pdu_obj->data;
    for(i=0;i<obj_data->pdu_obj->len;i++){
        dst_char[j++] = src_char[i];
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_http_snmp_rebuild_request_id(ngx_snmp_obj_data_t *obj_data){
    ngx_int_t           i,j,now;
    u_char              *reqid;
    now =  ngx_time();
    reqid=obj_data->pdu_reqid->data;
    j = 0;
    for(;now>0;){
        i = now & 0xFF;
        reqid[j] = j;
        j++;
        now >>=8;
    }
    obj_data->pdu_reqid->len = j;
    obj_data->request_id = now;
    return NGX_OK;
}

static ngx_int_t
ngx_http_snmp_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}

static void
ngx_http_snmp_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}
static void
ngx_http_snmp_dummy_send(ngx_event_t *wev){
    return;
}

static void
ngx_http_snmp_send(ngx_snmp_obj_data_t *obj_data){
    ngx_connection_t                          *c;
    ngx_uint_t                                sendlen;
    
    c = obj_data->c;
    if(c->destroyed){
        if(c->read->timer_set){
            ngx_log_error(NGX_LOG_ERR,obj_data->log, NGX_ETIMEDOUT, 
                "Read SNMP data ERROR");
            ngx_del_timer(c->read);
        }
    } 
    sendlen = c->send(c,obj_data->pdu->data,obj_data->pdu->len);
    if(sendlen<obj_data->pdu->len){
        ngx_log_error(NGX_LOG_ERR, obj_data->log, 0, "Send  SNMP Date  error");
        if(c->read->timer_set){
            ngx_del_timer(c->read);
        }
    }
    if(!c->read->timer_set){
        ngx_add_timer(c->read,5000);
        c->read->timer_set = 1;
    }
    return; 
}

static void
ngx_http_snmp_recv(ngx_event_t *rev){
    return;
}