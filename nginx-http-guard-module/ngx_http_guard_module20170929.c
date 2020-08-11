/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_core.h>
#include <ngx_http.h>

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
    ngx_uint_t                 log_level;
    ngx_uint_t                 status_code;
    ngx_int_t                  reset_time;
    ngx_str_t                  resp_msg;
    ngx_str_t                  redi_url;
} ngx_http_guard_conn_conf_t;

static uint32_t ngx_crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};




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

      ngx_null_command
};


static ngx_http_module_t  ngx_http_guard_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_guard_conn_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
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
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

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
    ngx_pool_cleanup_t             *cln;
    ngx_http_guard_conn_ctx_t      *ctx;
    ngx_http_guard_conn_node_t     *lc;
    ngx_http_guard_conn_conf_t     *lccf;
    ngx_http_guard_conn_guard_t    *guards;
    ngx_http_guard_conn_cleanup_t  *lccln;   
    //ngx_str_t                       uri;
    ngx_int_t                        rc;
    ngx_buf_t                        *b;
    ngx_chain_t                     out;

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
ngx_http_guard_conn_init(ngx_conf_t *cf)   
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    
    
    
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
               /* 
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
    ngx_http_guard_conn_node_t     *lc;
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



