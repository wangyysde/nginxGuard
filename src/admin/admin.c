/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <ngx_http.h>
#include "admin.h"

typedef struct {
    ngx_array_t                   get_variables;                                /*bzhy_admin_http_variable_t */
    ngx_array_t                   post_variables;                               /*bzhy_admin_http_variable_t */
    ngx_array_t                   cookie_variables;                             /*bzhy_admin_http_variable_t */
    ngx_array_t                   session_variables;                            /*bzhy_admin_http_variable_t */
    u_char                        *pos;
    u_char                        *last;
    ngx_uint_t                     type;
    size_t                         length;
    size_t                         padding;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    unsigned                       fastcgi_stdout:1;
    unsigned                       large_stderr:1;
    unsigned                       header_sent:1;

    ngx_array_t                   *split_parts;

    ngx_str_t                      script_name;
    ngx_str_t                      path_info;
} ngx_http_bzhy_admin_ctx_t;


static void  *admin_core_create_svr_conf(ngx_conf_t *cf);
static void *
admin_core_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t admin_core_post_conf(ngx_conf_t *cf);
//static ngx_int_t admin_core_init_handler(ngx_http_request_t *r);
static void *
admin_core_create_main_conf(ngx_conf_t *cf);
static char *
admin_core_command_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_bzhy_admin_handler(ngx_http_request_t *r);

void
ngx_http_bzhy_admin_init(ngx_http_request_t *r);
static ngx_int_t 
ngx_http_bzhy_admin_init_http_variable_array(ngx_http_request_t *r);
static ngx_int_t 
ngx_http_bzhy_admin_get_variables(ngx_http_request_t *r);

static ngx_http_module_t  admin_core_module_ctx = {        
    NULL,                                                                      /* preconfiguration */
    admin_core_post_conf,                                                      /* postconfiguration */

    admin_core_create_main_conf,                                               /* create main configuration */
    NULL,                                                                      /* init main configuration */
    admin_core_create_svr_conf,                                                /* create server configuration */
    NULL,                                                                      /* merge server configuration */

    admin_core_create_loc_conf,                                                /* create location configuration */
    NULL                                                                        /* merge location configuration */
};

static ngx_command_t admin_core_commands[] = {
 
    { ngx_string("admin"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      admin_core_command_admin,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(admin_core_loc_conf_t, admin_flag),
      NULL },
      
    { ngx_string("admin_page_dir"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(admin_core_svr_conf_t, admin_page_dir),
      NULL },
    
    { ngx_string("upstream_conf_dir"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(admin_core_svr_conf_t, upstream_conf_dir),
      NULL },
      
      { ngx_string("session_dir"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(admin_core_svr_conf_t, session_file_dir),
      NULL },
      
      { ngx_string("session_expire"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(admin_core_svr_conf_t, session_max_expire),
      NULL },
      
      ngx_null_command
};

ngx_module_t  admin_core_module = {
    NGX_MODULE_V1,
    &admin_core_module_ctx,                        /* module context */
    admin_core_commands,                           /* module directives */
    NGX_HTTP_MODULE,                               /* module type  */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
admin_core_create_svr_conf(ngx_conf_t *cf){
    admin_core_svr_conf_t               *acscf;
       
    acscf = ngx_pcalloc(cf->pool, sizeof(admin_core_svr_conf_t));
    if (acscf == NULL) {
        return "Alloc memory for Admin sever conf error";
    }
    
    ngx_str_null(&acscf->admin_page_dir);
    ngx_str_null(&acscf->ngx_main_conf);
    ngx_str_null(&acscf->upstream_conf_dir);
    ngx_str_null(&acscf->session_file_dir);
    acscf->session_max_expire = NGX_CONF_UNSET;
    
    return acscf;
    
} 

static void *
admin_core_create_loc_conf(ngx_conf_t *cf){
    admin_core_loc_conf_t               *aclcf;
       
    aclcf = ngx_pcalloc(cf->pool, sizeof(admin_core_loc_conf_t));
    if (aclcf == NULL) {
        return "Alloc memory for Admin loc conf error";
    }
    
    aclcf->admin_flag = NGX_CONF_UNSET;
        
    return aclcf;
    
} 

static void *
admin_core_create_main_conf(ngx_conf_t *cf){
    admin_core_main_conf_t               *acmcf;
    
    acmcf = ngx_pcalloc(cf->pool, sizeof(admin_core_main_conf_t));
    if (acmcf == NULL) {
        return "Alloc memory for Admin main conf error";
    }
    
    if (ngx_array_init(&acmcf->admin_core_srv,cf->pool,1,sizeof(admin_core_svr_conf_t *))
        != NGX_OK)
    {
        return "Initate admin core server conf error";
    }
    
    return acmcf;
}

static ngx_int_t
admin_core_post_conf(ngx_conf_t *cf){
  //  ngx_http_core_main_conf_t                       *hcmcf;
  //  ngx_http_handler_pt                             *h;
    admin_core_svr_conf_t                           *acscf,**acscfp;
    admin_core_main_conf_t                          *acmcf;
    ngx_uint_t                                      i,j;
    u_char                                          *tmp_file,*p;
    ngx_str_t                                       test_file;
    ngx_file_info_t                                 fi;
    
    
    acmcf = ngx_http_conf_get_module_main_conf(cf,admin_core_module);
    if(acmcf == NULL){
        return NGX_ERROR;
    }
    
    tmp_file = ngx_alloc(sizeof(u_char)*MAX_PATH_LEN,cf->log);
    if(tmp_file == NULL){
        return NGX_ERROR;
    }
    
    ngx_str_set(&test_file,"test.tmp");
    
    acscfp = acmcf->admin_core_srv.elts;
    for(i=0;i<acmcf->admin_core_srv.nelts;i++){
        acscf = acscfp[i];
        if(acscf->admin_page_dir.len == 0){
            ngx_str_set(&acscf->admin_page_dir, ADMIN_PAGE_DIR);
        }
        
        if (ngx_conf_full_name(cf->cycle,&acscf->admin_page_dir, 0) != NGX_OK) {
            goto end; 
        }
        
        ngx_file_info(acscf->admin_page_dir.data,&fi);
        if(!ngx_is_dir(&fi)){
             ngx_log_error(NGX_LOG_ERR,cf->log, 0, 
                     "Admin page dir:\"%V\"  is not available.",&acscf->admin_page_dir);
             goto end;
        }
        
        p = ngx_cpymem(tmp_file, acscf->admin_page_dir.data, (acscf->admin_page_dir.len + 1));
        j = acscf->admin_page_dir.len;
        if(tmp_file[j-1] != '/'){
            tmp_file[j] = '/';
        }
        
        ngx_cpystrn(p, test_file.data, test_file.len + 1);       
        if(ngx_open_tempfile(tmp_file,0,0) == -1){
            ngx_log_error(NGX_LOG_ERR,cf->log, 0, "Open the admin page dir:\"%V\"  error.Please check path primission.",&acscf->admin_page_dir);
            goto end;
        }
        
        if(acscf->upstream_conf_dir.len == 0){
            ngx_str_set(&acscf->upstream_conf_dir, UPSTREAM_CONF_DIR);
        }
    
        if (ngx_conf_full_name(cf->cycle,&acscf->upstream_conf_dir, 0) != NGX_OK) {
            goto end;
        }
        
        ngx_memzero(&fi,sizeof(ngx_file_info_t));
        ngx_file_info(acscf->upstream_conf_dir.data,&fi);
        if(!ngx_is_dir(&fi)){
             ngx_log_error(NGX_LOG_WARN,cf->log, 0, 
                     "Upstream conf  dir:\"%V\"  is not available.",&acscf->upstream_conf_dir);
             ngx_create_dir(acscf->upstream_conf_dir.data,DEFAULT_ACCESS_MODE);
        }
        
        p = ngx_cpymem(tmp_file, acscf->upstream_conf_dir.data, (acscf->upstream_conf_dir.len + 1));
        j = acscf->upstream_conf_dir.len;
        if(tmp_file[j-1] != '/'){
            tmp_file[j] = '/';
        }
        
        ngx_cpystrn(p, test_file.data, test_file.len + 1);
        
        if(ngx_open_tempfile(tmp_file,0,0) == -1){
            ngx_log_error(NGX_LOG_ERR,cf->log, 0, "Open the upstream conf dir:\"%V\"  error.Please check path primission.",&acscf->upstream_conf_dir);
            goto end;
        }
        
        if(acscf->session_file_dir.len == 0){
            ngx_str_set(&acscf->session_file_dir, SESSION_DIR);
        }
        
        if (ngx_conf_full_name(cf->cycle,&acscf->session_file_dir, 0) != NGX_OK) {
            goto end;
        }
        
        ngx_memzero(&fi,sizeof(ngx_file_info_t));
        ngx_file_info(acscf->session_file_dir.data,&fi);
        if(!ngx_is_dir(&fi)){
             ngx_log_error(NGX_LOG_WARN,cf->log, 0, 
                     "Session file dir:\"%V\"  is not available.",&acscf->session_file_dir);
             ngx_create_dir(acscf->session_file_dir.data,DEFAULT_ACCESS_MODE);
        }
        
        p = ngx_cpymem(tmp_file, acscf->session_file_dir.data, (acscf->session_file_dir.len + 1));
        j = acscf->session_file_dir.len;
        if(tmp_file[j-1] != '/'){
            tmp_file[j] = '/';
        }
        
        ngx_cpystrn(p, test_file.data, test_file.len + 1);
        
        if(ngx_open_tempfile(tmp_file,0,0) == -1){
            ngx_log_error(NGX_LOG_ERR,cf->log, 0, "Open the session dir:\"%V\"  error.Please check path primission.",&acscf->session_file_dir);
            goto end;
        }
        
        
        acscf->ngx_main_conf = cf->cycle->conf_file;
        if (ngx_conf_full_name(cf->cycle,&acscf->ngx_main_conf, 0) != NGX_OK) {
            goto end;
        }
        
        if(acscf->authfile.len == 0){
            ngx_str_set(&acscf->authfile, ADMIN_CORE_AUTH_FILE);
        }
        if (ngx_conf_full_name(cf->cycle,&acscf->authfile, 0) != NGX_OK) {
            goto end;
        }
        if(ngx_open_file(acscf->authfile.data,O_RDWR,0,0660) == -1){
            ngx_log_error(NGX_LOG_ERR,cf->log, 0, "Open the auth file :\"%V\"  error.Please check path primission.",&acscf->authfile);
            goto end;
        }
        
        if(acscf->session_max_expire == NGX_CONF_UNSET){
            acscf->session_max_expire = SESSION_MAX_EXPIRE;
        }
    }
        
    return NGX_OK;
    
    
end:
    ngx_free(tmp_file);
    return NGX_ERROR;

}

/*
static ngx_int_t
admin_core_init_handler(ngx_http_request_t *r){
     admin_core_svr_conf_t                               *acscf;

    acscf = ngx_http_get_module_srv_conf(r,admin_core_module);
    if(acscf == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if(acscf->admin_flag == NGX_CONF_UNSET){
        return NGX_OK;
    }
    return NGX_OK;
}
*/

static char *
admin_core_command_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    admin_core_svr_conf_t                      *acscf,**acscfp,*tmpacscf;
    admin_core_main_conf_t                     *acmcf;
    ngx_str_t                                  *values;
    admin_core_loc_conf_t                      *aclcf;
    ngx_int_t                                  found;
    ngx_uint_t                                 i;
    ngx_http_core_loc_conf_t                   *clcf;
    
    values =  cf->args->elts;
    
    aclcf = (admin_core_loc_conf_t *)conf;
    
    if( aclcf->admin_flag != NGX_CONF_UNSET){
        return "is duplicate";
    }
    
    if (ngx_strcasecmp(values[1].data, (u_char *) "on") == 0) {
        aclcf->admin_flag = 1;

    } else if (ngx_strcasecmp(values[1].data, (u_char *) "off") == 0) {
        aclcf->admin_flag = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     values[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }
    
    acscf = ngx_http_conf_get_module_srv_conf(cf,admin_core_module);
    if(acscf == NULL){
        return NGX_CONF_ERROR;
    }
    
    acmcf = ngx_http_conf_get_module_main_conf(cf,admin_core_module);
    if(acmcf == NULL){
        return NGX_CONF_ERROR;
    }
    
    acscfp = acmcf->admin_core_srv.elts;
    found = 0;
    for(i=0;i<acmcf->admin_core_srv.nelts;i++){
        tmpacscf = acscfp[i];
        if(acscf == tmpacscf){
            found = 1;
            break;
        }
    }
    
    if(found == 0){
        acscfp = ngx_array_push(&acmcf->admin_core_srv);
        *acscfp = acscf;
    }
     
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_bzhy_admin_handler;
    
    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }
     
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_bzhy_admin_handler(ngx_http_request_t *r){
    ngx_http_bzhy_admin_ctx_t            *bzhy_admin_ctx;
    ngx_int_t                             rc;
    
    
    bzhy_admin_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_bzhy_admin_ctx_t));
    if (bzhy_admin_ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    
    ngx_http_set_ctx(r, bzhy_admin_ctx, admin_core_module);
    
    rc = ngx_http_read_client_request_body(r, ngx_http_bzhy_admin_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    
    return NGX_DONE;
}

void
ngx_http_bzhy_admin_init(ngx_http_request_t *r)
{
    ngx_connection_t                     *c;
    ngx_int_t                            rc;
    
    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http bzhy admin init, client timer: %d", c->read->timer_set);
    
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }
    
    rc = ngx_http_bzhy_admin_init_http_variable_array(r);
    if(rc != NGX_OK){
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    
    rc = ngx_http_bzhy_admin_get_variables(r);
    if(rc != NGX_OK){
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    
    
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}

static ngx_int_t 
ngx_http_bzhy_admin_get_variables(ngx_http_request_t *r){
    ngx_http_bzhy_admin_ctx_t            *bzhy_admin_ctx;
    ngx_int_t                            len,namelen,valuelen;
    ngx_str_t                            args;
    u_char                               *var,*name,*value,*pos,*buf,*p,*last;
    bzhy_admin_http_variable_t           *variable;
    ngx_buf_t                            *b;
    ngx_chain_t                          *cl;
    
    if(r != r->main){
        return NGX_OK;
    }
    
    bzhy_admin_ctx = ngx_http_get_module_ctx(r, admin_core_module);
    if(bzhy_admin_ctx == NULL){
        return NGX_ERROR;
    }
    
    if(r->method == NGX_HTTP_GET){
        args =r->args;
        if(args.len>0){
            var = args.data;
            while(1 == 1){
                name = var;
                pos = (u_char *)ngx_strchr(var,'=');
                if(pos == NULL){
                    break;
                }
                namelen = pos - name;
                
                var = value = ++pos;
                pos = (u_char *)ngx_strchr(var,'&');
                if(pos == NULL){
                    valuelen = r->args.data + r->args.len - value;
                    variable = ngx_array_push( &bzhy_admin_ctx->get_variables);
                    if(variable == NULL){
                        return NGX_ERROR;
                    }
                    variable->name.data = name;
                    variable->name.len = namelen;
                    variable->value.data = value;
                    variable->value.len = valuelen;
                    break;
                }
                valuelen = pos - value;
                variable = ngx_array_push( &bzhy_admin_ctx->get_variables);
                if(variable == NULL){
                    return NGX_ERROR;
                }
                variable->name.data = name;
                variable->name.len = namelen;
                variable->value.data = value;
                variable->value.len = valuelen;
                var = ++pos;
            }
        }
    }
    
    if(r->method == NGX_HTTP_POST){
        if(r->request_body != NULL && r->request_body->bufs != NULL){
            len = 0;
            if (r->request_body->bufs->next != NULL) {
                for (cl = r->request_body->bufs; cl; cl = cl->next) {
                    b = cl->buf;
                    if (b->in_file) {
                        continue;
                    }
                    len += b->last - b->pos;
                }
                if(len != 0){
                    buf = ngx_palloc(r->pool, len);
                    if (buf == NULL) {
                        return NGX_ERROR;
                    }
                    p = buf;
                    last = p + len;
                    for (cl = r->request_body->bufs; cl; cl = cl->next) {
                        b = cl->buf;
                        if (b->in_file) {
                            continue;
                        }
                        p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
                    }
                }
            }
            else{
                b = r->request_body->bufs->buf;
                if (ngx_buf_size(b) != 0) {
                    buf = b->pos;
                    last = b->last;
                    len = last - buf;
                }
            }
            
            if(len >0 ){
                args.data = buf;
                args.len = len ;
                var = args.data;
                while(1 == 1){
                    name = var;
                    pos = (u_char *)ngx_strchr(var,'=');
                    if(pos == NULL){
                        break;
                    }
                    namelen = pos - name;
                    var = value = ++pos;
                    pos = (u_char *)ngx_strchr(var,'&');
                    if(pos == NULL){
                        valuelen = buf + len - value;
                        variable = ngx_array_push( &bzhy_admin_ctx->post_variables);
                        if(variable == NULL){
                            return NGX_ERROR;
                        }
                        variable->name.data = name;
                        variable->name.len = namelen;
                        variable->value.data = value;
                        variable->value.len = valuelen;
                        break;
                    }
                    valuelen = pos - value;
                    variable = ngx_array_push( &bzhy_admin_ctx->get_variables);
                    if(variable == NULL){
                        return NGX_ERROR;
                    }
                    variable->name.data = name;
                    variable->name.len = namelen;
                    variable->value.data = value;
                    variable->value.len = valuelen;
                    var = ++pos;
                }
            }
        }
    }
    
    return NGX_OK;
}

static ngx_int_t 
ngx_http_bzhy_admin_init_http_variable_array(ngx_http_request_t *r){
    ngx_http_bzhy_admin_ctx_t            *bzhy_admin_ctx;
    
    if(r == r->main){
        bzhy_admin_ctx = ngx_http_get_module_ctx(r, admin_core_module);
        if(bzhy_admin_ctx == NULL){
            return NGX_ERROR;
        }
        
        if (ngx_array_init(&bzhy_admin_ctx->get_variables,r->pool,1,sizeof(bzhy_admin_http_variable_t))
        != NGX_OK)
        {
            return NGX_ERROR;
        }
        
        if (ngx_array_init(&bzhy_admin_ctx->post_variables,r->pool,1,sizeof(bzhy_admin_http_variable_t))
        != NGX_OK)
        {
            return NGX_ERROR;
        }
        
        if (ngx_array_init(&bzhy_admin_ctx->cookie_variables,r->pool,1,sizeof(bzhy_admin_http_variable_t))
        != NGX_OK)
        {
            return NGX_ERROR;
        }
        
        if (ngx_array_init(&bzhy_admin_ctx->session_variables,r->pool,1,sizeof(bzhy_admin_http_variable_t))
        != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    
    return NGX_OK;
}