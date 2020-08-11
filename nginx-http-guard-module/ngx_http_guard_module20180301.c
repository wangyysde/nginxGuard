/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * 
 * 
 */


#include <ngx_core.h>
#include <ngx_http.h>
#include "snmpget/snmpget.h"

#define CONNECT_NUM_PER_SERVER     10
#define TRANSACTION_TIME           60
#define RESPONSE_MSG               "Servers are very busy ,please waiting for a short time"



typedef struct {
    u_char                     color;
    u_char                     len;
    u_short                    conn;
    u_char                     data[1];
    time_t                     refreshtime;
    u_short                     accepted;
} ngx_http_guard_conn_node_t;


typedef struct {
    ngx_shm_zone_t            *shm_zone;
    ngx_rbtree_node_t         *node;
} ngx_http_guard_conn_cleanup_t;

typedef struct {
    ngx_rbtree_t              *rbtree;
    ngx_http_complex_value_t   key;
    ngx_uint_t                 conn; 
} ngx_http_guard_conn_ctx_t;


typedef struct {
    ngx_shm_zone_t            *shm_zone;
    ngx_uint_t                 conn;
} ngx_http_guard_conn_guard_t;


typedef struct {
    ngx_array_t                guards;
    ngx_array_t                snmp_data; 
    ngx_uint_t                 log_level;
    ngx_uint_t                 status_code;
    ngx_int_t                  reset_time;
    ngx_str_t                  resp_msg;
    ngx_str_t                  redi_url;
} ngx_http_guard_conn_conf_t;

typedef struct {
    float                     cpu_load;
    int                       mem_used;
    int                       mem_total;
    int                       mem_sscontext;
    int                       nic_read_last_byes;
    int                       nic_read_current_byes;
    int                       nic_write_last_byes;
    int                       nic_write_current_byes;
    int                       disk_read_last_byes;
    int                       disk_read_current_byes;
    int                       disk_write_last_byes;
    int                       disk_write_current_byes;
} ngx_http_guard_snmp_data_t;

typedef struct {
    ngx_connection_t                   *connection;
    ngx_peer_connection_t              *pc;
    ngx_int_t                          obj; 
    snmp_para_t                        *snmp_paras;
    u_char                             *recv_buf;
    receive_msg_t                      *parseed_msg;
    snmp_msg_t                         *result_msg;
    ngx_int_t                          status;
    ngx_http_guard_snmp_data_t         *snmp_data;
    snmp_oct_t                         *snmp_pdu;
}ngx_http_guard_snmp_session_t;

typedef struct {
    ngx_msec_t                         timeout;
    size_t                             bufsize;
    ngx_str_t                          upstream_name;
    ngx_str_t                          server_addr;
    ngx_pool_t                         *pool;
    ngx_log_t                          *log; 
    ngx_addr_t                         *peer;
    ngx_http_guard_snmp_data_t         *snmp_data;
    ngx_array_t                        *snmp_sess;    
} ngx_http_guard_connect_session_t;


typedef struct {
    ngx_str_t                           server_addr;
    ngx_http_guard_connect_session_t    *snmp_cs;
    ngx_http_guard_snmp_data_t           snmp_data;
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
    ngx_str_t                   nic_read_oid;
    ngx_str_t                   nic_write_oid;
    ngx_str_t                   disk_read_oid;
    ngx_str_t                   disk_write_oid;
} ngx_http_guard_snmp_para_t;

typedef struct {
    ngx_array_t                   *guard_upstream;
    ngx_http_guard_snmp_para_t    snmp_paras;
} ngx_http_guard_main_conf_t;

/*
static uint32_t ngx_crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};

 */



static ngx_rbtree_node_t *ngx_http_guard_conn_lookup(ngx_rbtree_t *rbtree,
    uint32_t hash);
static void ngx_http_guard_conn_cleanup(void *data);
static void ngx_http_guard_conn_cleanup_all(ngx_pool_t *pool);

static void *ngx_http_guard_conn_create_conf(ngx_conf_t *cf);
static char *ngx_http_guard_conn_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_guard_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_guard_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_guard_post_conf(ngx_conf_t *cf);
static uint32_t ngx_http_generate_hash(ngx_http_request_t *r);
static int ngx_http_guard_delete_overtime_node(ngx_http_request_t *r, ngx_uint_t i);
static ngx_rbtree_node_t *
ngx_http_guard_lookup_by_refreshtime(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, ngx_int_t reset_time);
static ngx_int_t ngx_http_guard_handler_request(ngx_http_request_t *r);
static char *
ngx_http_upstream_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_guard_parse_snmp_paras(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_guard_create_main_conf(ngx_conf_t *cf);
static void ngx_http_guard_timer(ngx_event_t *ev);
static ngx_int_t 
ngx_http_guard_get_snmp_data(ngx_event_t *ev,ngx_http_guard_server_snmp_data_t gsvr,ngx_str_t upstream_name,ngx_int_t obj);
ngx_int_t ngx_http_guard_init_process (ngx_cycle_t *cycle);
static ngx_int_t 
ngx_http_guard_add_server(ngx_conf_t *cf,ngx_str_t upstream_name, ngx_http_upstream_server_t us);
static int
ngx_http_guard_find_server(ngx_conf_t *cf,ngx_str_t *server_addr,ngx_str_t upstream_name);

static void
ngx_http_guard_dummy_send(ngx_event_t *wev);
static char *
ngx_http_guard_parse_snmp_paras(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t 
ngx_http_guard_create_connection(ngx_http_guard_connect_session_t *snmp_cs,ngx_event_t *ev,ngx_int_t obj);
static ngx_int_t
ngx_http_guard_get_peer(ngx_peer_connection_t *pc, void *data);
static void
ngx_http_guard_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state);
static void
ngx_http_guard_send(ngx_event_t *wev,ngx_int_t obj);
static void
ngx_http_guard_recv(ngx_event_t *rev);
static ngx_int_t
ngx_http_guard_build_snmp_send_pdu(ngx_http_guard_connect_session_t *snmp_cs,ngx_int_t obj);
//ngx_int_t 
//ngx_http_guard_destroy_snmp_cs(ngx_http_guard_connect_session_t  *snmp_cs);
//static void
//ngx_http_guard_close(ngx_connection_t *c);
static ngx_int_t
ngx_http_guard_handler_snmp_data(ngx_http_guard_connect_session_t *snmp_cs,ngx_int_t obj);
static ngx_int_t 
ngx_http_guard_initate_snmp_cs(ngx_http_guard_server_snmp_data_t *gsvr, ngx_conf_t *cf);

static ngx_conf_enum_t  ngx_http_guard_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_guard_conn_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_guard_conn_commands[] = {

    { ngx_string("guard_conn_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_guard_conn_zone,
      0,
      0,
      NULL },

    { ngx_string("guard_conn"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_guard_conn,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("guard_conn_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conn_conf_t, log_level),
      &ngx_http_guard_conn_log_levels },

    { ngx_string("guard_conn_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conn_conf_t, status_code),
      &ngx_http_guard_conn_status_bounds },
      
    {  ngx_string("reset_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conn_conf_t, reset_time),
      NULL },

     {  ngx_string("response_msg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conn_conf_t, resp_msg),
      NULL },

      {  ngx_string("redirect_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_guard_conn_conf_t, redi_url),
      NULL },
      { ngx_string("guard_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_guard_upstream,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmpport"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmpver"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmptimeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_snmpcommunity"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_getinterval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_cpuoid"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_memused"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_memtotal"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_memssc"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_nic_read"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_nic_write"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_disk_read"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_disk_write"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      ngx_null_command
};

static ngx_http_module_t  ngx_http_guard_conn_module_ctx = {     // 
    NULL,                                  /* preconfiguration */
    ngx_http_guard_post_conf,              /* postconfiguration */

    ngx_http_guard_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_guard_conn_create_conf,       /* create location configuration */
    ngx_http_guard_conn_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_guard_module = {
    NGX_MODULE_V1,
    &ngx_http_guard_conn_module_ctx,       /* module context */
    ngx_http_guard_conn_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type  */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_guard_init_process,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void ngx_http_guard_timer(ngx_event_t *ev){ 
    ngx_http_guard_main_conf_t           *gmcf;
    ngx_http_guard_servers_t             *gusvrs,gusvr;
    ngx_http_guard_server_snmp_data_t    *gsvrs, gsvr;
    snmp_para_t                          *snmp_para;
    ngx_uint_t                            i,j; 
    ngx_http_guard_snmp_session_t         *snmp_ss,*snmp_s;
   
    gmcf = (ngx_http_guard_main_conf_t *) ev->data;
    ngx_add_timer(ev,gmcf->snmp_paras.get_interval*1000);
    ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Now starting get SNMP data"); 
    gusvrs = gmcf->guard_upstream->elts;
    for(i=0;i<gmcf->guard_upstream->nelts;i++){
        gusvr = gusvrs[i];
        gsvrs = gusvr.servers_snmp_data->elts;
        for(j=0;j<gusvr.servers_snmp_data->nelts;j++){
            gsvr = gsvrs[j];
            snmp_ss = gsvr.snmp_cs->snmp_sess->elts;
            snmp_s = &snmp_ss[0];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid =gmcf->snmp_paras.cpu_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,0) != NGX_OK ){
                continue;
            }
            snmp_s = &snmp_ss[1];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid = gmcf->snmp_paras.memused_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,1) != NGX_OK){
                continue;
            }
            snmp_s = &snmp_ss[2];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid =  gmcf->snmp_paras.memtotal_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,2) != NGX_OK){
                continue;
            }
            snmp_s = &snmp_ss[3];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid = gmcf->snmp_paras.memssc_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,3) != NGX_OK){
                continue;
            }
            snmp_s = &snmp_ss[4];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid = gmcf->snmp_paras.nic_read_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,4) != NGX_OK){
                continue;
            }
            snmp_s = &snmp_ss[5];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid = gmcf->snmp_paras.nic_write_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,5) != NGX_OK){
                continue;
            }
            snmp_s = &snmp_ss[6];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid = gmcf->snmp_paras.disk_read_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,6) != NGX_OK){
                continue;
            }
            snmp_s = &snmp_ss[7];
            snmp_para = snmp_s->snmp_paras;
            snmp_para->oid = gmcf->snmp_paras.disk_write_oid.data;
            if(ngx_http_guard_get_snmp_data(ev,gsvr,gusvr.upstream_name,7) != NGX_OK){
                continue;
            }
        }
    }
    return;    
} 

ngx_int_t ngx_http_guard_init_process (ngx_cycle_t *cycle){
    ngx_http_guard_main_conf_t           *gmcf;
    
    static ngx_event_t ev; 
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "set guard snmp get data timer");
    ev.handler=ngx_http_guard_timer;
    ev.log=cycle->log; 
    gmcf = (ngx_http_guard_main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle,ngx_http_guard_module);
    ev.data = gmcf;
    ngx_add_timer(&ev, (gmcf->snmp_paras.get_interval*1000));
    return NGX_OK;
} 
        
        
static uint32_t crc32_short(u_char *p, size_t len)
{
  u_char    c;
  uint32_t  crc;
   crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = ngx_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = ngx_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static ngx_int_t
ngx_http_guard_conn_handler(ngx_http_request_t *r)
{
    size_t                          n;
    uint32_t                        hash;
    ngx_str_t                       key;
    ngx_uint_t                      i;
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_node_t              *node;
  //  ngx_pool_cleanup_t             *cln;
    ngx_http_guard_conn_ctx_t      *ctx;
    ngx_http_guard_conn_node_t     *lc;
    ngx_http_guard_conn_conf_t     *lccf;
    ngx_http_guard_conn_guard_t    *guards;
 //   ngx_http_guard_conn_cleanup_t  *lccln;   
    //ngx_str_t                       uri;
 //    ngx_int_t                        rc;
  //   ngx_buf_t                        *b;
  //   ngx_chain_t                     out;

  //  static ngx_str_t  lkey = ngx_string("Location");
    
    hash = ngx_http_generate_hash(r);
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_guard_module);
    guards = lccf->guards.elts;                            //entities list tables?
 //   return NGX_DECLINED;
    for (i = 0; i < lccf->guards.nelts; i++) {
        ctx = guards[i].shm_zone->data;
        
        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "No i is:%ui The data of the key is : \"%V\" the key len is:%ui ",
                          i,&key, key.len);
        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }
        /* The following has been commented by Wayne Wang on May 04 2017
        r->main->limit_conn_set = 1;                              

        hash = ngx_crc32_short(key.data, key.len);
        */
        shpool = (ngx_slab_pool_t *) guards[i].shm_zone->shm.addr;
        
        ngx_shmtx_lock(&shpool->mutex);
        ngx_http_guard_delete_overtime_node(r,i);
        ngx_shmtx_unlock(&shpool->mutex);
      //  node = ngx_http_guard_conn_lookup(ctx->rbtree, &key, hash);   //按hash查找node 并判断key值，如果key值小于找到的node返回左孩子，否则返回右孩�?
        node = ngx_http_guard_conn_lookup(ctx->rbtree,  hash);
        if (node == NULL) {                         //找到对应的结点？
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Node has NOT found!");
            n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(ngx_http_guard_conn_node_t, data)
                + key.len;
            node = ngx_slab_alloc_locked(shpool, n);
            if (node == NULL) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Alloc share memory for node error!");
              //  ngx_shmtx_unlock(&shpool->mutex);
             //   ngx_http_guard_conn_cleanup_all(r->pool);
                return lccf->status_code;
            }

            lc = (ngx_http_guard_conn_node_t *) &node->color;
            node->key = hash;
            lc->len = (u_char) key.len;
            lc->conn = 1;
            lc->accepted = 0; 
            lc->refreshtime = ngx_time();
            
            //ngx_memcpy(lc->data, key.data, key.len);
            ngx_rbtree_insert(ctx->rbtree, node);
           // ngx_slab_free_locked(shpool, node);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"CTX CONN is: %ui!",ctx->conn);
            if ( ctx->conn >= guards[i].conn) {
                
                ngx_log_error(lccf->log_level, r->connection->log, 0,
                              "Becuase our server is too busy to accept your connection request \"%V\"",
                               &guards[i].shm_zone->shm.name);
                return ngx_http_guard_handler_request(r);
            }
            lc->accepted = 1; 
            ctx->conn++;
        } 
        else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Node has found!");
            lc = (ngx_http_guard_conn_node_t *) &node->color;
            lc->refreshtime = ngx_time();
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"LC ACCEPTED  is: %ui!",lc->accepted);
            if(lc->accepted != 1){
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"CTX CONN is: %ui!",ctx->conn);
                if ( ctx->conn >= guards[i].conn) {                   
                    ngx_log_error(lccf->log_level, r->connection->log, 0,
                              "Becuase our server is too busy to accept your connection request \"%V\"",
                               &guards[i].shm_zone->shm.name);
                    return ngx_http_guard_handler_request(r);
                }
                else{
                    lc->accepted = 1;
                    ctx->conn++;
                }
            }
        }
  
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "guard conn: %08Xi %d", node->key, lc->conn);

        //ngx_shmtx_unlock(&shpool->mutex);
/*
        cln = ngx_pool_cleanup_add(r->pool,
                                   sizeof(ngx_http_guard_conn_cleanup_t));
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_guard_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = guards[i].shm_zone;
        lccln->node = node;
 */
    }

    return NGX_DECLINED;
}


static void
ngx_http_guard_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_guard_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_http_guard_conn_node_t *) &node->color;
            lcnt = (ngx_http_guard_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

/*
static ngx_rbtree_node_t *
ngx_http_guard_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
 */
static ngx_rbtree_node_t *
ngx_http_guard_conn_lookup(ngx_rbtree_t *rbtree, uint32_t hash)
{
     // ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    // ngx_http_guard_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        return node;
        /*The following has been commented by Wayne Wang on 04 May 2017
        lcn = (ngx_http_guard_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
        */
    }

    return NULL;
}


static void
ngx_http_guard_conn_cleanup(void *data)
{
    ngx_http_guard_conn_cleanup_t  *lccln = data;

    ngx_slab_pool_t             *shpool;
    ngx_rbtree_node_t           *node;
    ngx_http_guard_conn_ctx_t   *ctx;
    ngx_http_guard_conn_node_t  *lc;
            
    ctx = lccln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lccln->shm_zone->shm.addr;
    node = lccln->node;
    lc = (ngx_http_guard_conn_node_t *) &node->color;
   
/*
    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
 */
}


static ngx_inline void
ngx_http_guard_conn_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == ngx_http_guard_conn_cleanup) {
        ngx_http_guard_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static ngx_int_t
ngx_http_guard_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_guard_conn_ctx_t  *octx = data;

    size_t                      len;
    ngx_slab_pool_t            *shpool;
    ngx_rbtree_node_t          *sentinel;
    ngx_http_guard_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->rbtree = octx->rbtree;
        ctx->conn =  0;    //Initated conn is zero on May 31 2017 by Wayne Wang 
          
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;
        ctx->conn  = 0;      //Initated conn is zero on Jun 13 2017 by Wayne Wang 
        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_guard_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in guard_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_http_guard_conn_create_conf(ngx_conf_t *cf)
{
    ngx_http_guard_conn_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_guard_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->guards.elts = NULL;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;
    conf->reset_time = NGX_CONF_UNSET;
    
    return conf;
}


static char *
ngx_http_guard_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_guard_conn_conf_t *prev = parent;
    ngx_http_guard_conn_conf_t *conf = child;

    if (conf->guards.elts == NULL) {
        conf->guards = prev->guards;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);
    ngx_conf_merge_value(conf->reset_time,prev->reset_time,TRANSACTION_TIME);
    ngx_conf_merge_str_value(conf->resp_msg,prev->resp_msg,RESPONSE_MSG);
    ngx_conf_merge_str_value(conf->redi_url,prev->redi_url,"off");
    
    return NGX_CONF_OK;
}


static char *
ngx_http_guard_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)   
{
    /*
     
     */
    u_char                            *p;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;   
    ngx_http_guard_conn_ctx_t         *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;           //value是一个数组， value[0]:guard_conn_zone value[1]:$binary_remote_addr value[2]:zone=addr:10m

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_guard_conn_ctx_t));  
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];           
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {     
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    //解析zone=addr:10m内容，并将设置name.data=addr name.len 为addr字符串长度；同时设置s.data �? 10m ，s.len = 区域大小数�?�的长度，如10m的长度为3个字�?
    for (i = 2; i < cf->args->nelts; i++) {       

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;   //获取�?取得的区域的大小�? 
            s.len = value[i].data + value[i].len - s.data;   //区域大小数�?�的长度，如10m的长度为3个字�?

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_guard_module);  //如果系统之前已经分配过name的区域，则返加该区域的地�?，否则新分配�?个name区域并返回地�?
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_guard_conn_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_guard_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_shm_zone_t               *shm_zone;
    ngx_http_guard_conn_conf_t   *lccf = conf;
    ngx_http_guard_conn_guard_t  *guard, *guards;

    ngx_str_t  *value;
    ngx_int_t   n;
    ngx_uint_t  i;

    value = cf->args->elts;

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_guard_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    guards = lccf->guards.elts;

    if (guards == NULL) {
        if (ngx_array_init(&lccf->guards, cf->pool, 1,
                           sizeof(ngx_http_guard_conn_guard_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->guards.nelts; i++) {
        if (shm_zone == guards[i].shm_zone) {
            return "is duplicate";
        }
    }

    n = ngx_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (n > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NGX_CONF_ERROR;
    }

    guard = ngx_array_push(&lccf->guards);
    if (guard == NULL) {
        return NGX_CONF_ERROR;
    }

    guard->conn = n;
    guard->shm_zone = shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_guard_post_conf(ngx_conf_t *cf)   
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_guard_main_conf_t   *gmcf;
    ngx_http_guard_servers_t     *gusvrs,gusvr;
    ngx_str_t                   upstream_name;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_srv_conf_t   **uscfp,uscf;
    ngx_http_upstream_server_t     *uss,us;
    ngx_uint_t  i,j,k,l;
    
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;
  //  uscf = *uscfp;
    gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_guard_module);
    gusvrs = gmcf->guard_upstream->elts;
    for (i = 0;  i < gmcf->guard_upstream->nelts;i++) {
        gusvr = gusvrs[i];
        upstream_name = gusvr.upstream_name;
        k = 0;
        for (j = 0; j < umcf->upstreams.nelts; j++) {
            uscf = *uscfp[j];
            if (uscf.host.len == upstream_name.len 
                    && ngx_strncmp(uscf.host.data,upstream_name.data, upstream_name.len) == 0){
                uss = uscf.servers->elts;
                for(l=0;l<uscf.servers->nelts;l++){
                    us = uss[l];
                    ngx_http_guard_add_server(cf,upstream_name,us);
                }
                k++;
            }
        }
        if(k == 0){
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,"Found unknow upstream:\"%V\"",upstream_name);
            return NGX_ERROR;
        }
    }
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_guard_conn_handler;
   
    return NGX_OK;
}

static uint32_t ngx_http_generate_hash(ngx_http_request_t *r)
{
    struct sockaddr_in          *sin;
    u_char                      *useragent; 
    uint32_t                    hash;
#if (NGX_HAVE_INET6) 
   struct sockaddr_in6         *sin6; 
   in_addr_t                    addr;
#endif
 //  u_char                      *p;
   ngx_http_guard_conn_conf_t     *lccf;
   
   
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_guard_module);
    sin = (struct sockaddr_in *) r->connection->sockaddr; 
    useragent = r->headers_in.user_agent->value.data;
    
    hash  =  ((uint32_t) sin->sin_addr.s_addr) & crc32_short(useragent, (size_t) r->headers_in.user_agent->value.len );
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Guard hash is :%uD", hash);
    return hash; 
   //hash = crc32_short(str, 8);
   
   
 /* 先解决IPv4情形下的问题，故注释掉以下的�? 20170413
   switch (r->connection->sockaddr->sa_family) {
        case AF_INET:
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "The Client IPv4 is: %ul ",
                          sin->sin_addr.s_addr);
        
            break;
#if (NGX_HAVE_INET6)
        
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
            p = sin6->sin6_addr.s6_addr;
            if(IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)){
                addr = p[12] << 24;
                addr += p[13] << 16;
                addr += p[14] << 8;
                addr += p[15];
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "The Client IPv6 is: %ul ",
                          htonl(addr));
            }else{
                size_t  cl;
                u_char  ct[NGX_INET6_ADDRSTRLEN];
                cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
               
                * The following statemnets has erros 
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "The Client IPv6(P) is: %s ",
                          p);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "cl is: %*s ",
                          cl);
                
            }  
            break;
#endif 
    }
    */
}

//static int ngx_http_guard_delete_overtime_node(ngx_rbtree_t *rbtree, ngx_int_t reset_time){
static int ngx_http_guard_delete_overtime_node(ngx_http_request_t *r, ngx_uint_t i){
    ngx_http_guard_conn_ctx_t      *ctx;
    ngx_slab_pool_t                *shpool;
    ngx_http_guard_conn_conf_t     *lccf;
    ngx_http_guard_conn_guard_t    *guards;
    
    ngx_rbtree_t *rbtree;
   // ngx_http_guard_conn_node_t     *lc;
    ngx_rbtree_node_t *node, *sentinel, *root; 
    
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_guard_module);
    guards = lccf->guards.elts;
    ctx = guards[i].shm_zone->data;
    rbtree = ctx->rbtree;
    root = rbtree->root;
    sentinel = rbtree->sentinel;
    shpool = (ngx_slab_pool_t *) guards[i].shm_zone->shm.addr;
    while( (node= ngx_http_guard_lookup_by_refreshtime(root,sentinel,lccf->reset_time)) != sentinel){
        ngx_rbtree_delete(rbtree, node);
        ngx_slab_free_locked(shpool, node);
        root = rbtree->root;
        if(ctx->conn > 0){
            ctx->conn--;
        }
        else{
            ctx->conn = 0; 
        }
    }
    return NGX_OK; 
}

static ngx_rbtree_node_t *
ngx_http_guard_lookup_by_refreshtime(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, ngx_int_t reset_time){
   ngx_http_guard_conn_node_t     *lc;
   ngx_rbtree_node_t              *retnode = sentinel;
   ngx_rbtree_node_t              *nodeleft;
   
   /**/
   if(node != sentinel ){
       lc = (ngx_http_guard_conn_node_t *) &node->color;
       if( (ngx_int_t)(ngx_time() - lc->refreshtime) >= reset_time ){
           return node;
       }
    //   else{
           nodeleft = node->left;
       if((retnode = ngx_http_guard_lookup_by_refreshtime(nodeleft,sentinel,reset_time )) != sentinel ){
               return retnode;
           }
    //   }
       node = node->right;
       if((retnode = ngx_http_guard_lookup_by_refreshtime(node,sentinel,reset_time )) != sentinel ){
            return retnode;
       }   
   }
   return sentinel;
}

static ngx_int_t
ngx_http_guard_handler_request(ngx_http_request_t *r)
{
    ngx_http_guard_conn_conf_t     *lccf;
    ngx_int_t                        rc;
    ngx_buf_t                        *b;
    ngx_chain_t                     out;
    
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_guard_module);
    if(ngx_strcmp(lccf->redi_url.data,"off") == 0){
        ngx_log_error(lccf->log_level, r->connection->log, 0,
            "This is runing");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = lccf->resp_msg.len;
        ngx_str_set(&r->headers_out.content_type, "text/html; charset=UTF-8");
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
        b->last_buf = (r == r->main) ? 1: 0;
        b->last_in_chain = 1;
        b->memory = 1;
        b->pos = lccf->resp_msg.data;
        b->last = b->pos + lccf->resp_msg.len;
        out.buf = b;
        out.next = NULL;
        return ngx_http_output_filter(r, &out);
    }
    else{
        if (ngx_strncmp(lccf->redi_url.data, "http://", sizeof("http://") - 1) == 0
            || ngx_strncmp(lccf->redi_url.data, "https://", sizeof("https://") - 1) == 0
            || ngx_strncmp(lccf->redi_url.data, "$scheme", sizeof("$scheme") - 1) == 0)
        {
            r->headers_out.location = ngx_list_push(&r->headers_out.headers);
            if (r->headers_out.location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_str_set(&r->headers_out.location->key, "Location");
            ngx_str_set(&r->headers_out.content_type, "text/html; charset=UTF-8");
            r->headers_out.location->hash = 1;
            r->headers_out.location->value = lccf->redi_url;
            r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
            return NGX_HTTP_MOVED_TEMPORARILY;
        }
        else{
            return ngx_http_internal_redirect(r, &lccf->redi_url, &r->args);
        }
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

static char *
ngx_http_upstream_guard_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_guard_main_conf_t   *gmcf;
    ngx_http_guard_servers_t     *gusvrs,*gusvrp,gusvr;
    u_char            *p;
    ngx_str_t  *value;
    ngx_uint_t  i;
    
    value = cf->args->elts;
    gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_guard_module);
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

static void *
ngx_http_guard_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_guard_main_conf_t  *gmcf;
    gmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_guard_main_conf_t));
    if (gmcf == NULL) {
        return NULL;
    }

    if ((gmcf->guard_upstream = ngx_array_create(cf->pool, 4,
                       sizeof(ngx_http_guard_servers_t)))
        == NULL)
    {
        return NULL;
    }

    return gmcf;
}

static ngx_int_t
ngx_http_guard_add_server(ngx_conf_t *cf,ngx_str_t upstream_name, ngx_http_upstream_server_t us){
    ngx_http_guard_main_conf_t          *gmcf;
    ngx_http_guard_servers_t            *gusvrs,gusvr;
    ngx_http_guard_server_snmp_data_t   *gsvr;
    size_t                       len;
  //  ngx_url_t                    u;
    u_char                       *p,*host,*last;
    ngx_str_t                    *server_addr;
    ngx_uint_t                        i,j;
    ngx_http_guard_snmp_session_t     *snmp_ss,*snmp_s;
    
    p = us.addrs->name.data;
    len = us.addrs->name.len;
    if (len >= 5 && ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        server_addr = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(server_addr ==  NULL){
             return NGX_ERROR;
        }
        ngx_str_set(server_addr, "127.0.0.1");        
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
        server_addr = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(server_addr == NULL){
             return NGX_ERROR;
        }
        host = host -1;
        server_addr->len = len + 2;
        server_addr->data = host;
    }
    else{
        host = us.addrs->name.data;
        last = us.addrs->name.data + us.addrs->name.len;
        server_addr = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if(server_addr == NULL){
             return NGX_ERROR;
        }
        p = ngx_strlchr(host, last, ':');
        if (p == NULL) {
            server_addr->len = us.addrs->name.len;
        }
        else {
            server_addr->len = p - host;
        }
        server_addr->data = host;
    }
    if(ngx_http_guard_find_server(cf,server_addr,upstream_name) == 0){
        gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_guard_module);
        gusvrs = gmcf->guard_upstream->elts;
        for (i = 0; i < gmcf->guard_upstream->nelts;i++) {
            gusvr = gusvrs[i];
            if(ngx_strncmp(upstream_name.data,gusvr.upstream_name.data,gusvr.upstream_name.len) == 0){
                gsvr = ngx_array_push(gusvr.servers_snmp_data);
                if(gsvr == NULL){
                    return NGX_ERROR;
                }
                if(ngx_http_guard_initate_snmp_cs(gsvr,cf) != NGX_OK){
                    return NGX_ERROR; 
                }
                gsvr->snmp_data.cpu_load = 0;
                gsvr->snmp_data.mem_used = 0;
                gsvr->snmp_data.nic_read_last_byes = 0;
                gsvr->snmp_data.nic_read_current_byes = 0;
                gsvr->snmp_data.nic_write_last_byes = 0;
                gsvr->snmp_data.nic_write_current_byes = 0;
                gsvr->snmp_data.disk_read_last_byes = 0;
                gsvr->snmp_data.disk_read_current_byes = 0;
                gsvr->snmp_data.disk_write_last_byes = 0;
                gsvr->snmp_data.disk_write_current_byes = 0;
                gsvr->snmp_data.mem_sscontext = 0; 
                gsvr->snmp_data.mem_total = 0;
                gsvr->server_addr.data = server_addr->data;
                gsvr->server_addr.len = server_addr->len;
                gsvr->snmp_cs->upstream_name = upstream_name;
                gsvr->snmp_cs->server_addr.data = server_addr->data;
                gsvr->snmp_cs->server_addr.len = server_addr->len;
                gsvr->snmp_cs->snmp_data = &gsvr->snmp_data;
                snmp_ss = gsvr->snmp_cs->snmp_sess->elts;
                for(j=0;j<8;j++){
                    snmp_s = &snmp_ss[j];
                    snmp_s->snmp_paras->port = gmcf->snmp_paras.snmp_port;
                    snmp_s->snmp_paras->snmp_version = gmcf->snmp_paras.snmp_ver;
                    snmp_s->snmp_paras->community = gmcf->snmp_paras.snmp_community.data;
                    snmp_s->snmp_paras->remote_add = server_addr->data;
                }
                gsvr->snmp_cs->pool = cf->pool;
                gsvr->snmp_cs->peer->name = upstream_name;
                gsvr->snmp_cs->peer->sockaddr = (struct sockaddr *)server_addr->data;
            }
        }
        
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_http_guard_initate_snmp_cs(ngx_http_guard_server_snmp_data_t *gsvr, ngx_conf_t *cf)
{
    ngx_int_t                         i; 
    ngx_http_guard_snmp_session_t     *snmp_ss,*snmp_s;
    
    if((gsvr->snmp_cs = ngx_pcalloc(cf->pool, sizeof(ngx_http_guard_connect_session_t))) == NULL){
        return NGX_ERROR;
    }
    gsvr->snmp_cs->timeout = NGX_ETIMEDOUT;
    gsvr->snmp_cs->bufsize = sizeof(char)*MAX_BUF_LENGTH;
    ngx_str_set(&gsvr->snmp_cs->upstream_name,"");
    ngx_str_set(&gsvr->snmp_cs->server_addr,"");
    gsvr->snmp_cs->pool = NULL; 
    gsvr->snmp_cs->log = NULL;
    if((gsvr->snmp_cs->peer = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t))) == NULL){
        return NGX_ERROR;
    }
    gsvr->snmp_cs->snmp_data = NULL; 
    if((gsvr->snmp_cs->snmp_sess = ngx_array_create(cf->pool,8,sizeof(ngx_http_guard_snmp_session_t))) == NULL){
        return NGX_ERROR;
    }
    snmp_ss = gsvr->snmp_cs->snmp_sess->elts;
    for(i=0;i<8;i++){
        snmp_s = &snmp_ss[i];
        snmp_s->connection = NULL;
        if((snmp_s->pc = ngx_pcalloc(cf->pool, sizeof(ngx_peer_connection_t))) == NULL){
            return NGX_ERROR;
        }
        snmp_s->obj = -1;
        if((snmp_s->snmp_paras = ngx_pcalloc(cf->pool, sizeof(snmp_para_t))) == NULL){
            return NGX_ERROR;
        }
        if((snmp_s->recv_buf = ngx_pcalloc(cf->pool,sizeof(u_char)*MAX_BUF_LENGTH)) == NULL){
            return NGX_ERROR;
        }
        if((snmp_s->parseed_msg = ngx_pcalloc(cf->pool,sizeof(receive_msg_t))) == NULL){
            return NGX_ERROR;
        }
        if((snmp_s->result_msg = ngx_pcalloc(cf->pool,sizeof(snmp_msg_t))) == NULL){
            return NGX_ERROR;
        }
        snmp_s->status = NGX_OK;
        if((snmp_s->snmp_pdu = ngx_pcalloc(cf->pool,sizeof(snmp_oct_t))) == NULL){
            return NGX_ERROR;
        }
    }
    return NGX_OK; 
    
}

static int
ngx_http_guard_find_server(ngx_conf_t *cf,ngx_str_t *server_addr,ngx_str_t upstream_name){
    ngx_http_guard_main_conf_t           *gmcf;
    ngx_http_guard_servers_t             *gusvrs,gusvr;
    ngx_http_guard_server_snmp_data_t    *gsvrs, gsvr;
    ngx_uint_t                            i,j;
   
    gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_guard_module);
    gusvrs = gmcf->guard_upstream->elts;
    for (i = 0;  i < gmcf->guard_upstream->nelts;i++) {
        gusvr = gusvrs[i];
        if(ngx_strncmp(upstream_name.data,gusvr.upstream_name.data,gusvr.upstream_name.len) == 0){
            gsvrs = gusvr.servers_snmp_data->elts;
            for(j=0;j<gusvr.servers_snmp_data->nelts;j++){
               gsvr = gsvrs[j];
               if(ngx_strncmp(gsvr.server_addr.data,server_addr->data,server_addr->len)  == 0){
                   return(1);
               }
            }
        }
    }
    return(0);
}

static char *
ngx_http_guard_parse_snmp_paras(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_guard_main_conf_t           *gmcf;
    //ngx_str_t                            *strp;
    
    gmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_guard_module);
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
        gmcf->snmp_paras.snmp_community = value[1];
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
        gmcf->snmp_paras.cpu_oid = value[1];
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_memused",ngx_strlen("guard_memused")) == 0){
        gmcf->snmp_paras.memused_oid = value[1];
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_memtotal",ngx_strlen("guard_memtotal")) == 0){
        gmcf->snmp_paras.memtotal_oid = value[1];
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_memssc",ngx_strlen("guard_memssc")) == 0){
        gmcf->snmp_paras.memssc_oid = value[1];
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_nic_read",ngx_strlen("guard_nic_read")) == 0){
        gmcf->snmp_paras.nic_read_oid = value[1]; 
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_nic_write",ngx_strlen("guard_nic_write")) == 0){
        gmcf->snmp_paras.nic_write_oid = value[1]; 
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_disk_read",ngx_strlen("guard_disk_read")) == 0){
        gmcf->snmp_paras.disk_read_oid = value[1]; 
        return NGX_CONF_OK;
    }
    else if(ngx_strncmp(cmd->name.data,"guard_disk_write",ngx_strlen("guard_disk_write")) == 0){
        gmcf->snmp_paras.disk_write_oid = value[1]; 
        return NGX_CONF_OK;
    }
    else{
        return "Invalid director";
    }
    
}

static ngx_int_t 
ngx_http_guard_create_connection(ngx_http_guard_connect_session_t *snmp_cs,ngx_event_t *ev,ngx_int_t obj)
{
    ngx_peer_connection_t                     *pc;
    ngx_int_t                                  rc;
    ngx_connection_t                          *c;
    ngx_http_guard_snmp_session_t     *snmp_ss,*snmp_s;
    
    snmp_ss = snmp_cs->snmp_sess->elts;
    snmp_s = &snmp_ss[obj];
    pc =  snmp_s->pc; 
    pc->local = NULL; 
    pc->log = ev->log;
    pc->get = ngx_http_guard_get_peer;
    pc->free = ngx_http_guard_free_peer;
    pc->data = snmp_cs;
    pc->type = SOCK_DGRAM;
    pc->socklen =snmp_cs->peer->socklen;
    pc->sockaddr = snmp_cs->peer->sockaddr;
    pc->name = &snmp_cs->peer->name;
    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_error(NGX_LOG_EMERG,ev->log, 0,"Create snmp connection failed");
        return NGX_ERROR;
    }
    c = pc->connection;
    c->data = snmp_cs;
    c->pool = snmp_cs->pool;
    ev = c->write;
    c->read->handler = ngx_http_guard_recv;
    c->write->handler = ngx_http_guard_dummy_send;
    snmp_s->connection = c;
    ngx_http_guard_send(c->write,obj);
    if(c->write->timer_set){
        ngx_del_timer(c->write);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_guard_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}
static void
ngx_http_guard_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}

static void
ngx_http_guard_send(ngx_event_t *wev,ngx_int_t obj)
{
   // ngx_peer_connection_t                     *pc;
    ngx_connection_t                          *c;
    ngx_http_guard_connect_session_t          *snmp_cs;
    ngx_event_t                               *rev;
    ngx_http_guard_snmp_session_t             *snmp_ss,*snmp_s;
    snmp_oct_t                                *snmp_pdu;
    
    c = wev->data;
    snmp_cs = c->data;
    snmp_ss = snmp_cs->snmp_sess->elts;
    snmp_s = &snmp_ss[obj];
    snmp_pdu = snmp_s->snmp_pdu;
    if (c->destroyed) 
    {
        free(snmp_pdu->ber_oct);
        snmp_pdu->length = 0;
        ngx_del_timer(c->read);
        ngx_close_connection(c);
        return;
    }
   
    if (wev->timedout) 
    {
        ngx_log_error(NGX_LOG_INFO, wev->log, NGX_ETIMEDOUT, 
                "guard: client send timed out");
        c->timedout = 1;
        free(snmp_pdu->ber_oct);
        snmp_pdu->length = 0;
        ngx_del_timer(c->read);
        ngx_close_connection(c);
        return;
    }
    
    rev = c->read;
    if (c->send(c, snmp_pdu->ber_oct,snmp_pdu->length) < (ssize_t) snmp_pdu->length) {
        ngx_log_error(NGX_LOG_EMERG, wev->log, 0, 
                "guard: Send PDU error");
        if(rev->timer_set){
            ngx_del_timer(rev);
        }
    }
    free(snmp_pdu->ber_oct);
    snmp_pdu->length = 0;
    return;
}

static void
ngx_http_guard_recv(ngx_event_t *rev)
{
    ngx_connection_t                          *c;
    ngx_http_guard_connect_session_t          *snmp_cs;
    ngx_int_t                                 n;
    int                                       snmp_err_code;
   // u_char                                    *s;
    u_char                                    *recv_buf;
    receive_msg_t                             *parseed_msg; 
    snmp_msg_t                                *result_msg; 
    ngx_http_guard_snmp_session_t             *snmp_s,*snmp_ss;
    ngx_int_t                                 i,obj;
    
    c = rev->data;
    snmp_cs = c->data;
    snmp_ss = snmp_cs->snmp_sess->elts;
    for(i=0;i<8;i++){
        snmp_s = &snmp_ss[i];
        if(c == snmp_s->connection){
            obj = i;
        }
    }
    snmp_s =  &snmp_ss[obj];
    if(rev->timedout){
        ngx_log_error(NGX_LOG_EMERG, rev->log, NGX_ETIMEDOUT, 
                "guard: receive snmp data timed out");
     //   ngx_del_timer(c->read);
        ngx_close_connection(c);
        return;
    }
    recv_buf = snmp_s->recv_buf;
    ngx_memzero(recv_buf, snmp_cs->bufsize);
    while(rev->ready){
        n = c->recv(c,recv_buf,snmp_cs->bufsize);
        if(n == NGX_AGAIN){
            break;
        }
        if(n == NGX_ERROR){
            ngx_log_error(NGX_LOG_EMERG, rev->log, NGX_ETIMEDOUT, 
                "guard: receive snmp data error");
          //  ngx_del_timer(c->read);
            ngx_close_connection(c);
            return;
        }
    }
    parseed_msg = snmp_s->parseed_msg;
    if(!initate_snmp_receive_msg(parseed_msg)){
        ngx_log_error(NGX_LOG_EMERG, rev->log, NGX_ETIMEDOUT, 
                "guard: initate snmp receive msg error");
        return;
    }
    if((snmp_err_code=snmp_parase_response(recv_buf,parseed_msg)) != 0){
        ngx_log_error(NGX_LOG_EMERG, rev->log, NGX_ETIMEDOUT, 
                "guard: get a unavailable SNMP message:%s",snmp_strerror(snmp_err_code));
     //   ngx_del_timer(c->read);
        ngx_close_connection(c);
        return; 
    }
    result_msg = snmp_s->result_msg;
    if((snmp_err_code=snmp_get_response_msg(parseed_msg,result_msg))!=0){
        ngx_log_error(NGX_LOG_EMERG, rev->log, 0, 
                "guard: get the SNMP message error:%s",snmp_strerror(snmp_err_code));
        free(parseed_msg->msg);
        free(parseed_msg->objoid->ber_oct);
        free(parseed_msg->objoid);
        free(parseed_msg->reqid->ber_oct);
        free(parseed_msg->reqid);
      //  ngx_del_timer(c->read);
        ngx_close_connection(c);
        return;
    }
    if(result_msg->type == 2){
        ngx_log_error(NGX_LOG_EMERG, rev->log, 0, 
                "We get a strig SNMP message:%s of %d",result_msg->valuemsg,obj);
    }
    else{
        ngx_log_error(NGX_LOG_EMERG, rev->log, 0, 
                
                "We get a numberic SNMP message:%d of %d",result_msg->value, obj);
    }
    snmp_s->status = NGX_OK;
  //  ngx_close_connection(rev->data);
    ngx_http_guard_handler_snmp_data(snmp_cs,obj);
    if(result_msg->type == 2){
        free(result_msg->valuemsg);
    }
    free(parseed_msg->msg);
    free(parseed_msg->objoid->ber_oct);
    free(parseed_msg->objoid);
    free(parseed_msg->reqid->ber_oct);
    free(parseed_msg->reqid);
 //   ngx_del_timer(c->read);
    ngx_close_connection(c);
    return;
}

static ngx_int_t
ngx_http_guard_build_snmp_send_pdu(ngx_http_guard_connect_session_t *snmp_cs,ngx_int_t obj)
{
    snmp_session_t                    *snmp_session;
    snmp_para_t                       *snmp_para;
    snmp_oct_t                        *snmp_pdu;
    ngx_http_guard_snmp_session_t     *snmp_ss,*snmp_s;
   // ngx_int_t                  i;
    
    snmp_ss = snmp_cs->snmp_sess->elts;
    snmp_s = &snmp_ss[obj];
    snmp_pdu = snmp_s->snmp_pdu;
    if(!(snmp_session = (snmp_session_t *)malloc(sizeof(snmp_session_t)))){
        ngx_log_error(NGX_LOG_ERR,snmp_cs->log, 0,"Alloc memory for snmp session error.");
        return NGX_ERROR;
    }
    initate_snmp_session(snmp_session);
    snmp_para = snmp_s->snmp_paras; 
    snmp_session->objoid_str = (u_char *)snmp_para->oid;
    snmp_session->version = (long)snmp_para->snmp_version;
    snmp_session->community = (u_char *)snmp_para->community;
    snmp_session->community_length = strlen((const char *)snmp_para->community);
    initate_snmp_oct(snmp_pdu);
    if(!snmp_build_getRequestPDU(snmp_pdu,snmp_session)){
        ngx_log_error(NGX_LOG_ERR,snmp_cs->log, 0,"Building SNMP send PDU Error.");
        free(snmp_session);
        snmp_session = NULL;
        return NGX_ERROR;
    }
    free(snmp_session);
    snmp_session = NULL;
    return NGX_OK;
}

/*
ngx_int_t 
ngx_http_guard_destroy_snmp_cs(ngx_http_guard_connect_session_t  *snmp_cs){
    //ngx_http_guard_close(snmp_cs->connection);
    free(snmp_cs->snmp_pdu);
    snmp_cs->snmp_pdu = NULL;
    free(snmp_cs->recv_buf);
    snmp_cs->recv_buf = NULL;
    ngx_pfree(snmp_cs->pool,snmp_cs->pc);
    ngx_pfree(snmp_cs->pool,snmp_cs->peer);
    ngx_destroy_pool(snmp_cs->pool);
    free(snmp_cs->result_msg);
    free(snmp_cs->parseed_msg);
    free(snmp_cs);
    snmp_cs = NULL;
    return NGX_OK;
}
*/
/*
static void
ngx_http_guard_close(ngx_connection_t *c)
{
    ngx_close_connection(c);
    return; 
}
*/

static void
ngx_http_guard_dummy_send(ngx_event_t *wev){
    return;
}

static ngx_int_t 
ngx_http_guard_get_snmp_data(ngx_event_t *ev,ngx_http_guard_server_snmp_data_t gsvr,ngx_str_t upstream_name, ngx_int_t obj){
    ngx_http_guard_connect_session_t     *snmp_cs;
    ngx_uint_t                            rc;
    snmp_para_t                          *snmp_para;
    struct sockaddr_in                   *sin;
    ngx_http_guard_snmp_session_t     *snmp_ss,*snmp_s;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    snmp_cs = gsvr.snmp_cs;
    snmp_cs->log = ev->log;
    snmp_ss = snmp_cs->snmp_sess->elts;
    snmp_s = &snmp_ss[obj];
    snmp_s->obj = obj;
    snmp_para = snmp_s->snmp_paras;
    rc = ngx_parse_addr(snmp_cs->pool, snmp_cs->peer,
            gsvr.server_addr.data, gsvr.server_addr.len);
    switch (rc){
        case NGX_OK:
            break;
        case NGX_DECLINED:
            ngx_log_error(NGX_LOG_ERR, ev->log, 0,
               "upstream invalid server address:\"%V\"",gsvr.server_addr);
        default:
       //     ngx_http_guard_destroy_snmp_cs(snmp_cs);
            return NGX_ERROR;     
    }
    switch (snmp_cs->peer->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) snmp_cs->peer->sockaddr;
            sin6->sin6_port = htons((in_port_t) gmcf->snmp_paras.snmp_port);
            break;
#endif
        default: /* AF_INET */
            sin = (struct sockaddr_in *) snmp_cs->peer->sockaddr;
            sin->sin_port = htons((in_port_t) snmp_para->port);
            break;
    }
    if(ngx_http_guard_build_snmp_send_pdu(snmp_cs,obj) != NGX_OK ){
            return NGX_ERROR;
        }
    if(ngx_http_guard_create_connection(snmp_cs,ev,obj) != NGX_OK){
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_guard_handler_snmp_data(ngx_http_guard_connect_session_t *snmp_cs,ngx_int_t obj)
{
    snmp_msg_t                         *result_msg;
    ngx_http_guard_snmp_data_t         *snmp_data;
    ngx_http_guard_snmp_session_t     *snmp_ss,*snmp_s;
    
    snmp_ss = snmp_cs->snmp_sess->elts;
    snmp_s = &snmp_ss[obj];
    if(snmp_s->status != NGX_OK){
        ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                "guard: get a unavailable SNMP message");
        return NGX_ERROR;
    }
    result_msg = snmp_s->result_msg;
    snmp_data = snmp_cs->snmp_data;
    switch(obj){
        case 0:
            if(result_msg->type != 2){
            ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                "guard: get a unavailable cpu load value");
            }
            snmp_data->cpu_load = atof((char *)result_msg->valuemsg);
            break;
        case 1:
           if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable memory used value");
            }
            snmp_data->mem_used = result_msg->value;
            break;
        case 2:
            if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable memory total value");
            }
            snmp_data->mem_total = result_msg->value;
            break;
        case 3:
            if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable memory sscontext value");
            }
            snmp_data->mem_sscontext = result_msg->value;
            break;
        case 4:
            if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable interface current byes value");
            }
            snmp_data->nic_read_last_byes = snmp_data->nic_read_current_byes;
            snmp_data->nic_read_current_byes = result_msg->value;
            break;
        case 5:
            if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable interface current byes value");
            }
            snmp_data->nic_write_last_byes = snmp_data->nic_write_current_byes;
            snmp_data->nic_write_current_byes = result_msg->value;
            break;
        case 6:
            if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable disk io read value");
            }
            snmp_data->disk_read_last_byes = snmp_data->disk_read_current_byes;
            snmp_data->disk_read_current_byes = result_msg->value;
            break;
        case 7:
            if(result_msg->type != 1){
                ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                    "guard: get a unavailable disk io write value");
            }
            snmp_data->disk_write_last_byes = snmp_data->disk_write_current_byes;
            snmp_data->disk_write_current_byes = result_msg->value;
            break;
        default:
            ngx_log_error(NGX_LOG_EMERG,snmp_cs->log, 0, 
                "guard: get a unknown object  value");
    }
    //ngx_http_guard_destroy_snmp_cs(snmp_cs);
    return NGX_OK;
}