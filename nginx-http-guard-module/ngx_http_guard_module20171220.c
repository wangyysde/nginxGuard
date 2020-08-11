/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * 
 * 20171213   ngx_http_guard_conn_init
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
    ngx_uint_t                 cpu_load;
    ngx_uint_t                 mem_used;
    ngx_uint_t                 mem_total;
    ngx_uint_t                 mem_sscontext;
    ngx_uint_t                 interface_last_byes;
    ngx_uint_t                 interface_current_byes;
    ngx_uint_t                 disk_io_rate;
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
static ngx_int_t ngx_http_guard_conn_init(ngx_conf_t *cf);
static uint32_t ngx_http_generate_hash(ngx_http_request_t *r);
static int ngx_http_guard_delete_overtime_node(ngx_http_request_t *r, ngx_uint_t i);
static ngx_rbtree_node_t *
ngx_http_guard_lookup_by_refreshtime(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, ngx_int_t reset_time);
static ngx_int_t ngx_http_guard_handler_request(ngx_http_request_t *r);
static char *
ngx_http_upstream_guard_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_guard_parse_snmp_paras(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_guard_create_main_conf(ngx_conf_t *cf);
/*
static ngx_int_t
ngx_http_upstream_init_guard_conn(ngx_conf_t *cf,ngx_http_upstream_srv_conf_t *us);
static ngx_int_t
ngx_http_upstream_init_guard_conn_peer(ngx_http_request_t *r,ngx_http_upstream_srv_conf_t *us);
static ngx_int_t
ngx_http_upstream_get_guard_conn_peer(ngx_peer_connection_t *pc, void *data);
*/
ngx_int_t ngx_http_guard_init_process (ngx_cycle_t *cycle);
static ngx_int_t ngx_http_guard_add_server(ngx_conf_t *cf,ngx_str_t upstream_name, ngx_http_upstream_server_t us);
static int
ngx_http_guard_find_server(ngx_conf_t *cf,ngx_str_t *server_addr,ngx_str_t upstream_name);

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
      ngx_http_upstream_guard_conn,
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
      
      { ngx_string("guard_nic"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      { ngx_string("guard_iorate"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_guard_parse_snmp_paras,
      0,
      0,
      NULL },
      
      ngx_null_command
};

/*
static ngx_int_t
ngx_http_upstream_init_guard_conn(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init guard conn");

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {    // Should be make sure????????
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_guard_conn_peer;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_init_guard_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init guard conn peer");

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_guard_conn_peer;

    return NGX_OK;
}
*/
/*
static ngx_int_t
ngx_http_upstream_get_guard_conn_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc, total;
    ngx_uint_t                     i, n, p, many;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = rrp->peers;

    ngx_http_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        

        if (best == NULL
            || peer->conns * best->weight < best->conns * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (peer->conns * best->weight == best->conns * peer->weight) {
            many = 1;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            if (peer->down) {
                continue;
            }

            if (peer->conns * best->weight != best->conns * peer->weight) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        rc = ngx_http_upstream_get_guard_conn_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_http_upstream_rr_peers_wlock(peers);
    }

   

    for (peer = peers->peer; peer; peer = peer->next) {
        peer->fails = 0;
    }

    ngx_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}
*/


static ngx_http_module_t  ngx_http_guard_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_guard_conn_init,              /* postconfiguration */

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
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_guard_init_process,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

//static void add_timer(ngx_event_t *ev){
 //   static ngx_connection_t dumb;
    
//}

static  void test_timer(ngx_event_t *wev){ 
    ngx_log_error(NGX_LOG_DEBUG, wev->log, 0, "gdrive timer out"); 
     ngx_add_timer(wev, 5000);
} 

ngx_int_t ngx_http_guard_init_process (ngx_cycle_t *cycle){
    static ngx_event_t gdrive_timer_wev; 
    static ngx_connection_t dumb;
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "set guard timer");
    gdrive_timer_wev.handler=test_timer;
    gdrive_timer_wev.log=cycle->log; 
    gdrive_timer_wev.data=&dumb; 
    dumb.fd=(ngx_socket_t)-1; 
    ngx_add_timer(&gdrive_timer_wev, 5000);
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

int start_get_data(){
    
    for(;;){
        printf("aaaaaa\n");
        sleep(5);
    }
}

static ngx_int_t
ngx_http_guard_conn_init(ngx_conf_t *cf)   
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
  //  gusvrs = gusvrp;
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
                   // us = uscfp[j]->servers->elts[l];
                    us = uss[l];
                    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    //           "Upstream: \"%V\",Server Name:\"%V\",Add Name\"%V\" Addr:\"%s\" ",upstream_name,us.name,us.addrs->name,us.addrs->sockaddr->sa_data);
                    ngx_http_guard_add_server(cf,upstream_name,us);
                    //ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,"Upstream: \"%s \"",upstream_name.data); 
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,"Upstream: \"%s \"",upstream_name.data);
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
ngx_http_upstream_guard_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
   // ngx_shm_zone_t               *shm_zone;
    ngx_http_guard_main_conf_t   *gmcf;
    ngx_http_guard_servers_t     *gusvrs,*gusvrp,gusvr;
    u_char            *p;
    //ngx_http_guard_upstream_snmp_data_t  *snmp_data, *snmp_datas;
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
    //shm_zone = ngx_shared_memory_add(cf, &value[1], sizeof(ngx_http_guard_servers_t),
   //                                  &ngx_http_guard_module);
   // if (shm_zone == NULL) {
  //      return NGX_CONF_ERROR;
  //  }
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
   // gusvrp->upstream_name.data = value[1].data;
  //  gusvrp->upstream_name = value[1];
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
    //ngx_url_t                    u;
    u_char                       *p,*host,*last;
    ngx_str_t                    *server_addr;
    ngx_uint_t                    i;

    
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
        // ngx_cpystrn(server_addr->data,host,(len+2));
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
        //ngx_cpystrn(server_addr->data,host,server_addr->len);
    }
    
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "Server: \"%V\"", server_addr);
    //ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,"Server: \"%V\"", server_addr); 
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
                gsvr->snmp_data.cpu_load = 0;
                gsvr->snmp_data.mem_used = 0;
                gsvr->snmp_data.disk_io_rate = 0; 
                gsvr->snmp_data.interface_current_byes = 0;
                gsvr->snmp_data.interface_last_byes = 0; 
                gsvr->snmp_data.mem_sscontext = 0; 
                gsvr->snmp_data.mem_total = 0;
                gsvr->server_addr.data = server_addr->data;
                gsvr->server_addr.len = server_addr->len;
            }
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
    ngx_str_t                            *strp;
    
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
