/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <ngx_core.h>
#include <ngx_http.h>
#include "snmpget/snmpget.h"





typedef struct {
    float                     cpu_load;
    int                       mem_used;
    int                       mem_total;
    int                       mem_sscontext;
    int                       interface_last_byes;
    int                       interface_current_byes;
    float                     disk_io_rate;
} ngx_http_guard_snmp_data_t;

typedef struct {
    ngx_str_t                   server_addr;
    ngx_http_guard_snmp_data_t  snmp_data;
} ngx_http_guard_server_snmp_data_t;

typedef struct {
    ngx_str_t                   upstream_name;
    ngx_array_t                 *servers_snmp_data;
} ngx_http_guard_servers_t;

typedef struct {
    ngx_int_t                   snmp_port;
    ngx_int_t                   snmp_ver;
    ngx_int_t                   snmpget_timeout;
    ngx_str_t                   snmp_community; 
    ngx_int_t                   get_interval;
    ngx_str_t                   cpu_oid;
    ngx_str_t                   memused_oid;
    ngx_str_t                   memtotal_oid;
    ngx_str_t                   memssc_oid; 
    ngx_str_t                   nicthroughput_oid; 
    ngx_str_t                   iorate_oid;
} ngx_http_guard_snmp_para_t;

typedef struct {
    ngx_array_t                   *guard_upstream;
    ngx_http_guard_snmp_para_t    snmp_paras;
} ngx_http_guard_main_conf_t;


static void *
ngx_http_guard_core_create_conf(ngx_cycle_t *cycle);
static char *
ngx_http_upstream_guard_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_guard_parse_snmp_paras(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_guard_core_init_process(ngx_cycle_t *cycle);
//static void ngx_http_guard_timer(ngx_event_t *wev);



static ngx_command_t  ngx_guard_core_commands[] = {

      { ngx_string("guard_upstream"),
      NGX_MAIN_CONF| NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_guard_conn,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmpport"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmpver"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmptimeout"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmpcommunity"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_getinterval"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_cpuoid"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_memused"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_memtotal"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_memssc"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_nic"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_iorate"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      ngx_null_command
};


static ngx_core_module_t  ngx_http_guard_core_ctx = {
    ngx_string("guard_core"),
    ngx_http_guard_core_create_conf,             /* create conf */
    NULL,                                        /*init conf */
};

ngx_module_t ngx_guard_core_module ={
    NGX_MODULE_V1,
    &ngx_http_guard_core_ctx,
    ngx_guard_core_commands,
    NGX_CORE_MODULE,
    NULL,
    NULL,
    ngx_guard_core_init_process,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_guard_core_create_conf(ngx_cycle_t *cycle)
{
    ngx_http_guard_main_conf_t  *gmcf;
    
    gmcf = ngx_pcalloc(cycle->pool, sizeof(ngx_http_guard_main_conf_t));
    if (gmcf == NULL) {
        return NULL;
    }
    
    if ((gmcf->guard_upstream = ngx_array_create(cycle->pool, 4,
                       sizeof(ngx_http_guard_servers_t)))
        == NULL)
    {
        return NULL;
    }
    return gmcf;
}

static char *
ngx_http_upstream_guard_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
   // ngx_shm_zone_t               *shm_zone;
    ngx_http_guard_main_conf_t   *gmcf;
    ngx_http_guard_servers_t     *gusvrs,*gusvrp,gusvr;
    u_char            *p;
    ngx_str_t  *value;
    ngx_uint_t  i;
    
    value = cf->args->elts;  
   // gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_guard_core_module);
    gmcf = ngx_get_conf((ngx_http_guard_main_conf_t *)cf->cycle->conf_ctx,ngx_guard_core_module);
    gusvrs = gmcf->guard_upstream->elts;
    for (i = 0;  i < gmcf->guard_upstream->nelts;i++) {
        gusvr = gusvrs[i];
        if(ngx_strncmp(value[1].data,gusvr.upstream_name.data,gusvr.upstream_name.len) == 0){
            return "is duplicate";
        }
    }
    gusvrp = ngx_array_push(gmcf->guard_upstream);
    if (gusvrp == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(gusvrp, sizeof(ngx_http_guard_servers_t));
    gusvrp->upstream_name.len = value[1].len;
    gusvrp->upstream_name.data = ngx_alloc(sizeof(NGINX_VAR) * value[1].len,cf->log);
    if (gusvrp->upstream_name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    p = ngx_cpymem(gusvrp->upstream_name.data, value[1].data, sizeof(NGINX_VAR) * value[1].len);
    if ((gusvrp->servers_snmp_data=ngx_array_create(cf->pool, 1,sizeof(ngx_http_guard_server_snmp_data_t))) == NULL){
        return NULL;
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_guard_parse_snmp_paras(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_guard_main_conf_t           *gmcf;
    ngx_str_t                            *strp;
    
   // gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_guard_core_module);
    gmcf =ngx_get_conf((ngx_http_guard_main_conf_t *)cf->cycle->conf_ctx,ngx_guard_core_module);
    ngx_str_t        *value;
    
    value = cf->args->elts;
    if(ngx_strncmp(cmd->name.data,"guard_snmpport",ngx_strlen("guard_snmpport")) == 0){
        gmcf->snmp_paras.snmp_port = ngx_atoi(value[1].data, value[1].len);
        if (gmcf->snmp_paras.snmp_port == NGX_ERROR) {
            return "invalid number";
        }
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_snmpver",ngx_strlen("guard_snmpver")) == 0){
        if(ngx_strncmp(value[1].data,"v1",ngx_strlen("v1")) == 0){
            return "We can suport only v2c";
        }
        else if(ngx_strncmp(value[1].data,"v2c",ngx_strlen("v1")) == 0){
            gmcf->snmp_paras.snmp_ver = SNMP_VERSION_2C;
            return NGX_CONF_OK;
        }
        else if(ngx_strncmp(value[1].data,"v1",ngx_strlen("v3")) == 0){
            return "We can suport only v2c";
        }
        else{
            return "Invalid parameters";
        }
    }
    else if(ngx_strncmp(cmd->name.data,"guard_snmptimeout",ngx_strlen("guard_snmptimeout")) == 0){
        gmcf->snmp_paras.snmpget_timeout = ngx_atoi(value[1].data, value[1].len);
        if (gmcf->snmp_paras.snmpget_timeout == NGX_ERROR) {
            return "invalid number";
        }
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_snmpcommunity",ngx_strlen("guard_snmpcommunity")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.snmp_community.data = strp->data;
        gmcf->snmp_paras.snmp_community.len = strp->len;
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_getinterval",ngx_strlen("guard_getinterval")) == 0){
        gmcf->snmp_paras.get_interval = ngx_atoi(value[1].data, value[1].len);
        if (gmcf->snmp_paras.get_interval == NGX_ERROR) {
            return "invalid number";
        }
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_cpuoid",ngx_strlen("guard_cpuoid")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.cpu_oid.data = strp->data;
        gmcf->snmp_paras.cpu_oid.len = strp->len;      
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_memused",ngx_strlen("guard_memused")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.memused_oid.data = strp->data;
        gmcf->snmp_paras.memused_oid.len = strp->len;      
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_memtotal",ngx_strlen("guard_memtotal")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.memtotal_oid.data = strp->data;
        gmcf->snmp_paras.memtotal_oid.len = strp->len;      
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_memssc",ngx_strlen("guard_memssc")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.memssc_oid.data = strp->data;
        gmcf->snmp_paras.memssc_oid.len = strp->len;      
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_nic",ngx_strlen("guard_nic")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.nicthroughput_oid.data = strp->data;
        gmcf->snmp_paras.nicthroughput_oid.len = strp->len;      
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_iorate",ngx_strlen("guard_iorate")) == 0){
        strp = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(strp == NULL){
            return NGX_CONF_ERROR;
        }
        strp->data = ngx_pcalloc(cf->pool, sizeof(u_char)*value[1].len);
        if(strp->data == NULL){
            return NGX_CONF_ERROR;
        }
        ngx_cpystrn(strp->data,value[1].data,value[1].len);
        strp->len = value[1].len;
        gmcf->snmp_paras.iorate_oid.data = strp->data;
        gmcf->snmp_paras.iorate_oid.len = strp->len;      
        return NGX_CONF_OK;
    }
    else{
        return "Invalid director";
    }
    
}

static void test_timer(ngx_event_t *wev){
     ngx_add_timer(wev, 5000);
     ngx_log_error(NGX_LOG_DEBUG, wev->log, 0, "AAAAAThis is runnig");
}

static ngx_int_t
ngx_guard_core_init_process(ngx_cycle_t *cycle)
{
    ngx_http_guard_main_conf_t           *gmcf;
    static ngx_event_t gdrive_timer_wev; 
    static ngx_connection_t   dumb_con;
    
    
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "set guard timer");
    
    //dumb_con = malloc(sizeof(ngx_connection_t *));
    gdrive_timer_wev.handler=test_timer;                   
    gdrive_timer_wev.log=cycle->log; 
    gmcf = (ngx_http_guard_main_conf_t *) ngx_get_conf(cycle->conf_ctx,ngx_guard_core_module);
    gdrive_timer_wev.data=&dumb_con;
    dumb_con.data = gmcf;
    dumb_con.fd = (ngx_socket_t)-1;
    //gdrive_timer_wev.data = gmcf;
    ngx_add_timer(&gdrive_timer_wev, 5000);
    //ngx_add_timer(&gdrive_timer_wev, (gmcf->snmp_paras.get_interval*1000));
    return NGX_OK;
}

/*
static void ngx_http_guard_timer(ngx_event_t *wev){ 
    ngx_http_guard_main_conf_t           *gmcf;
    ngx_http_guard_servers_t             *gusvrs,gusvr;
    ngx_http_guard_server_snmp_data_t    *gsvrs, gsvr;
    snmp_msg_t                           *snmp_msg;
    snmp_para_t                          *snmp_para;
    ngx_uint_t                            i,j; 
    int                                  snmp_errno;
    ngx_connection_t                     *dumb_con;
    
    ngx_log_error(NGX_LOG_DEBUG, wev->log, 0, "This is runnig");
   // gmcf = (ngx_http_guard_main_conf_t *) wev->data;
    dumb_con = (ngx_connection_t *)wev->data;
    gmcf = (ngx_http_guard_main_conf_t *)dumb_con->data;
    //ngx_add_timer(wev, gmcf->snmp_paras.get_interval);
    ngx_add_timer(wev, 5000);
    if(!(snmp_msg = (snmp_msg_t *)malloc(sizeof(snmp_msg_t)))){
        ngx_log_error(NGX_LOG_EMERG, wev->log, 0, "Alloc memory error"); 
        return;
        //  return NGX_ERROR;
    }
    if(!(snmp_para = (snmp_para_t *)malloc(sizeof(snmp_para_t)))){
        ngx_log_error(NGX_LOG_EMERG, wev->log, 0, "Alloc memory error"); 
        goto free_snmp_msg;
    }
    gusvrs = gmcf->guard_upstream->elts;
    snmp_para->port = gmcf->snmp_paras.snmp_port;
    snmp_para->snmp_version = gmcf->snmp_paras.snmp_ver;
    snmp_para->community = gmcf->snmp_paras.snmp_community.data;
    for(i=0;i<gmcf->guard_upstream->nelts;i++){
        gusvr = gusvrs[i];
        gsvrs = gusvr.servers_snmp_data->elts;
        for(j=0;j<gusvr.servers_snmp_data->nelts;j++){
            gsvr = gsvrs[j];
            snmp_para->remote_add = gsvr.server_addr.data;
            snmp_para->oid = gmcf->snmp_paras.cpu_oid.data;
            if((snmp_errno = snmp_get_msg(snmp_para,snmp_msg)) != 0){
                ngx_log_error(NGX_LOG_EMERG, wev->log, 0, "Get SNMP data ERROR:%s",snmp_strerror(snmp_errno)); 
                goto free_snmp_para;
            }
            gsvr.snmp_data.cpu_load = strtof((const char *)snmp_msg->valuemsg,NULL);
            ngx_log_error(NGX_LOG_NOTICE, wev->log, 0, "Get server:%s CPU load is:%(number)f",snmp_para->remote_add,gsvr.snmp_data.cpu_load); 
        }
    }
    return; 
   // return NGX_OK; 
    
free_snmp_para:
   free(snmp_para);    
 free_snmp_msg:
    free(snmp_msg);
 return ;
} 
*/