/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <ngx_http.h>

#include "admin.h"


static void  *admin_core_create_svr_conf(ngx_conf_t *cf);
static ngx_int_t admin_core_post_conf(ngx_conf_t *cf);
static ngx_int_t admin_core_init_handler(ngx_http_request_t *r);
static void *
admin_core_create_main_conf(ngx_conf_t *cf);
static char *
admin_core_command_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
admin_core_get_cookie_key_and_value(ngx_str_t *linedata,ngx_str_t *key,ngx_str_t *value);
static ngx_int_t
admin_core_clean_sess_files(ngx_http_request_t *r);
static u_char *
admin_core_get_line_data_from_buf(u_char *buf,ngx_str_t *line_data);
static ngx_int_t
admin_core_get_sess_info(ngx_http_request_t *r,ngx_file_t *file);
static ngx_int_t admin_core_session_handler(ngx_http_request_t *r);
static void 
admin_core_form_data_handler(ngx_http_request_t *r);
static admin_core_msg_t * 
admin_core_get_error_msg(ngx_int_t errorno);


admin_core_msg_t      *admin_core_msg = NULL;

admin_core_form_action_route_t form_routes[] = {
    {ngx_string("login"),admin_core_do_login_post}
};


static ngx_http_module_t  admin_core_module_ctx = {        
    NULL,                                                                      /* preconfiguration */
    admin_core_post_conf,                                                      /* postconfiguration */

    admin_core_create_main_conf,                                               /* create main configuration */
    NULL,                                                                      /* init main configuration */
    admin_core_create_svr_conf,                                                /* create server configuration */
    NULL,                                                                      /* merge server configuration */

    NULL,                                                                       /* create location configuration */
    NULL                                                                        /* merge location configuration */
};

static ngx_command_t admin_core_commands[] = {
 
    { ngx_string("admin"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      admin_core_command_admin,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(admin_core_svr_conf_t, admin_flag),
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
    
    acscf->admin_flag = NGX_CONF_UNSET;
    ngx_str_null(&acscf->admin_page_dir);
    ngx_str_null(&acscf->ngx_main_conf);
    ngx_str_null(&acscf->upstream_conf_dir);
    ngx_str_null(&acscf->session_file_dir);
    ngx_str_null(&acscf->authfile_dir);
    acscf->session_max_expire = NGX_CONF_UNSET;
    
    return acscf;
    
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
    ngx_http_core_main_conf_t                       *hcmcf;
    ngx_http_handler_pt                             *h;
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
        if(ngx_open_tempfile(acscf->authfile.data,0,0) == -1){
            ngx_log_error(NGX_LOG_ERR,cf->log, 0, "Open the auth file :\"%V\"  error.Please check path primission.",&acscf->authfile);
            goto end;
        }
        
        if(acscf->session_max_expire == NGX_CONF_UNSET){
            acscf->session_max_expire = SESSION_MAX_EXPIRE;
        }
    }
    
    
    hcmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (hcmcf == NULL) {
        return NGX_ERROR;
    }
    
    h = ngx_array_push(&hcmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    
    *h = admin_core_init_handler;
    

    
    return NGX_OK;
    
    
end:
    ngx_free(tmp_file);
    return NGX_ERROR;

}

static ngx_int_t
admin_core_init_handler(ngx_http_request_t *r){
    ngx_str_t                                          *tmp_str,action;
    ngx_int_t                                           rc,num,j,login;
    ngx_uint_t                                          i;
    ngx_buf_t                                           *b;
    ngx_chain_t                                         out;
    admin_core_svr_conf_t                               *acscf;
    admin_core_form_input_ctx_t                         *ctx;
    admin_core_form_input_filed_value_t                 *fvp,fv;
    admin_core_form_input_handler_pt                    *handler;
    
    acscf = ngx_http_get_module_srv_conf(r,admin_core_module);
    if(acscf == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if(acscf->admin_flag == NGX_CONF_UNSET){
        return NGX_OK;
    }
    
    rc = admin_core_session_handler(r);
    if(rc == NGX_ERROR){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    login = 0;
    if(rc == NGX_DONE && r->method != NGX_HTTP_POST){
        return NGX_DECLINED;
    }
    
    if(rc == NGX_OK){
        login = 1;
    }
    
    admin_core_msg = NULL;
    
    if(r->method ==NGX_HTTP_POST ){
        ctx = ngx_http_get_module_ctx(r, admin_core_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(admin_core_form_input_ctx_t));
            if (ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            ctx->inputs = ngx_array_create(r->pool,1,sizeof(admin_core_form_input_filed_value_t));
            if(ctx->inputs == NULL){
                ngx_log_error(NGX_LOG_ERR,cf->log, 0, "Create array for input value error.");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_http_set_ctx(r, ctx, admin_core_module);
        }
        rc = ngx_http_read_client_request_body(r, admin_core_form_data_handler);
        
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
            (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }
        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
        }
        
        fvp = ctx->inputs.elts;
        action.len = 0;
        for(i=0;i<ctx->inputs.nelts;i++){
            fv = fvp[i];
            if(fv.name.len == (sizeof("action") -1)
               && ngx_strncmp(fv.name.data,"action",fv.name.len) == 0){
                action.data = fv.value.data;
                action.len = fv.value.len;
            }
        }
        
        if(action.len == 0 ){
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        if(login == 0 && (action.len != (sizeof("login")-1) || 
                ngx_strncmp(action.data,"login",action.len) != 0)){
            admin_core_msg = admin_core_get_error_msg(103);
            return ngx_http_internal_redirect(r, admin_core_msg->rewriteuri, &r->args);
        }
        handler = NULL;
        num = sizeof(form_routes)/sizeof(admin_core_form_action_route_t);
        for(j=0;j<num;j++){
            if(form_routes[j].action.len == action.len &&
                ngx_strncmp(form_routes[j].action.data,action.data,action.len) == 0){
                handler = form_routes[j].handler;
            }
        }
        if(handler == NULL){
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        rc = *handler(r,NULL);
        
        if(rc == NGX_ERROR){
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
    }
    
   
    
    
    tmp_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if(tmp_str == NULL){
        return NGX_ERROR;
    }
    ngx_str_set(tmp_str,"This is test admin page");
    
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = tmp_str->len;
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
    b->pos = tmp_str->data;
    b->last = b->pos + tmp_str->len;
    out.buf = b;
    out.next = NULL;
        
    return ngx_http_output_filter(r, &out);
        
}

static char *
admin_core_command_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    admin_core_svr_conf_t                      *acscf,**acscfp;
    admin_core_main_conf_t                     *acmcf;
    ngx_str_t                                  *values;

    values =  cf->args->elts;
    
    acscf = (admin_core_svr_conf_t *)conf;
    
    if( acscf->admin_flag != NGX_CONF_UNSET){
        return "is duplicate";
    }
    
    if (ngx_strcasecmp(values[1].data, (u_char *) "on") == 0) {
        acscf->admin_flag = 1;

    } else if (ngx_strcasecmp(values[1].data, (u_char *) "off") == 0) {
        acscf->admin_flag = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     values[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }
    
    acmcf = ngx_http_conf_get_module_main_conf(cf,admin_core_module);
    if(acmcf == NULL){
        return NGX_CONF_ERROR;
    }
    
    acscfp = ngx_array_push(&acmcf->admin_core_srv);
    *acscfp = acscf;
      
    return NGX_CONF_OK;
}

static ngx_int_t admin_core_session_handler(ngx_http_request_t *r){
    admin_core_svr_conf_t                           *acscf;
    ngx_table_elt_t                                 **cookies;
    ngx_str_t                                       *cookie,key,value,sess_file;
    ngx_uint_t                                      i,j,num,login;
    u_char                                          *p; 
    ngx_file_t                                      *file;
    ngx_int_t                                       fd;
    
        
    num = sizeof(session_datas)/sizeof(admin_core_session_line_data_t);
    for(i=0;i<num;i++){
        session_datas[i].data = ngx_pcalloc(r->pool,sizeof(union sess_field_data));
        if(session_datas[i].data == NULL){
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Alloc memory error");
            return NGX_ERROR;
        }
        if(session_datas[i].field_type == 1){
            session_datas[i].data->str_data.data = ngx_pcalloc(r->pool,sizeof(u_char)*COOKIE_VALUE_MAX_LEN);
            if(session_datas[i].data->str_data.data == NULL){
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Alloc memory error");
                return NGX_ERROR;
            }
            session_datas[i].data->str_data.len = 0;
        }
    }
    cookie = NULL;
    cookies = (ngx_table_elt_t **) r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        cookie = &cookies[i]->value;
        if(admin_core_get_cookie_key_and_value(cookie,&key,&value) != NGX_ERROR){
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,"Get cookie value error!");
            return NGX_ERROR;
        }
        for(j=0;j<num;j++){
            if(session_datas[j].field_name.len == key.len &&
                    ngx_strncmp(session_datas[j].field_name.data,key.data,key.len) == 0){
                if(session_datas[j].field_type == 1){
                    session_datas[j].data->str_data.data = value.data;
                    session_datas[j].data->str_data.len = value.len;
                }
                else{
                    session_datas[j].data->int_data = ngx_atoi(value.data,value.len);
                }
            }
        }
    }
    
    sess_file.data = ngx_palloc(r->pool,sizeof(u_char)*MAX_PATH_LEN);
    if(sess_file.data == NULL){
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Alloc memory error");
        return NGX_ERROR;
    }
    
    acscf = ngx_http_get_module_srv_conf(r,admin_core_module);
    
    login = 0;
    value = session_datas[0].data->str_data;
        
    if(value.len == 0 ){
        login = 0;
    }
    else{
        sess_file = acscf->session_file_dir;
        p = sess_file.data;
        p = &p[sess_file.len];
        ngx_cpystrn(p,session_datas[0].data->str_data.data,session_datas[0].data->str_data.len);
        file = ngx_palloc(r->pool,sizeof(ngx_file_t));
        if(file == NULL){
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Alloc memory error");
            return NGX_ERROR;
        }
        fd = ngx_open_file(sess_file.data,O_RDONLY,0,0600);
        if(fd == -1){
            login = 0;
        }
        else{
            file->fd = fd;
            file->offset = 0;
            file->name = sess_file;
            if(admin_core_get_sess_info(r,file) == NGX_ERROR){
                return NGX_ERROR;
            }
            login = 1;
            ngx_close_file(fd);
        }
    }
    
    if(admin_core_clean_sess_files(r) == NGX_ERROR){
        return NGX_ERROR;
    }
    
    if(login == 0){
        return NGX_DONE;        
    }
    else{
        return NGX_OK;
    }
}

static ngx_int_t
admin_core_get_cookie_key_and_value(ngx_str_t *linedata,ngx_str_t *key,ngx_str_t *value){
    u_char                              *p,*tmp;
    ngx_int_t                           endkey;
    ngx_uint_t                          i;
    
    if(linedata == NULL || linedata->len <1){
        return NGX_ERROR;
    }
    
    p = linedata->data;
    key->len = 0;
    value->len = 0;
    endkey = 0;
    for(i=0;i<linedata->len;i++){
        if(*p == ' '){
            p++;
            continue;
        }
        if(key->len == 0){
            tmp = key->data;
            *tmp = *p; 
            key->len = 1;
        }
        
        if(*p != '=' && endkey== 0){
            tmp++;
            *tmp = *p;
            key->len++;
        }
        
        if(*p == '='){
            tmp = value->data;
            endkey = 1; 
        }
        
        if(endkey == 1 && value->len == 0){
            *tmp = *p;
            value->len++;
            tmp++;
        }
        if(endkey == 1 && value->len != 0){
            *tmp = *p;
            value->len++;
            tmp++;
        }
        p++;
    }
    
    if(key->len == 0 || value->len == 0){
        return NGX_ERROR;
    }
    else{
        return NGX_OK;
    }
}

static ngx_int_t
admin_core_clean_sess_files(ngx_http_request_t *r){
    ngx_str_t                                       sess_file,tmp_file;
    admin_core_svr_conf_t                           *acscf;
    u_char                                          *p;
    ngx_int_t                                       ret,last_access;
    ngx_dir_t                                       dir;
    ngx_file_info_t                                 *fi;
    
    sess_file.data = ngx_palloc(r->pool,sizeof(u_char)*MAX_PATH_LEN);
    if(sess_file.data == NULL){
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Alloc memory error");
        return NGX_ERROR;
    }
    
    fi = ngx_palloc(r->pool,sizeof(ngx_file_info_t));
    if(fi == NULL){
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Alloc memory error");
        return NGX_ERROR;
    }
   
    acscf = ngx_http_get_module_srv_conf(r,admin_core_module);
    p = ngx_cpymem(sess_file.data, acscf->upstream_conf_dir.data, acscf->upstream_conf_dir.len );
    sess_file.len = acscf->upstream_conf_dir.len;
    
    ret = ngx_open_dir(&sess_file,&dir);
    if(ret == NGX_ERROR){
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                     "Can not open the session dir:\"%V\"",sess_file);
        return NGX_ERROR;
    }
    
    tmp_file = sess_file;
    while(ngx_read_dir(&dir) != NGX_ERROR){
        if(dir.de->d_type == DT_REG){
            p = tmp_file.data;
            p = &p[tmp_file.len];
            ngx_cpystrn(p,(u_char *)dir.de->d_name,dir.de->d_reclen);
            ngx_memzero(fi,sizeof(ngx_file_info_t));
            if(ngx_file_info(tmp_file.data,fi) == NGX_ERROR){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "Can not get the file:\"%V\" stat",tmp_file);
            }
            else{
                last_access = (ngx_int_t)fi->st_atim.tv_sec;
                if(ngx_time() - last_access >= acscf->session_max_expire ){
                    ngx_delete_file(tmp_file.data);
                }
            }
        }
    }
     
    return NGX_OK;    
}

static ngx_int_t
admin_core_get_sess_info(ngx_http_request_t *r,ngx_file_t *file){
    ngx_file_info_t                                 *fi;
    ngx_str_t                                       sess_file,*line_data,*key,*value;
    u_char                                          *buf;
    ngx_int_t                                       i,num;
    
    fi = ngx_palloc(r->pool,sizeof(ngx_file_info_t));
    if(fi == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory error");
        return NGX_ERROR;
    }
    
    buf = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    if(buf == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory error");
        return NGX_ERROR;
    }
    sess_file = file->name;
    if(ngx_file_info(sess_file.data,fi) == NGX_ERROR){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
             "Can not get the file:\"%V\" stat",sess_file);
        return NGX_ERROR;
    }
    
    file->info = *fi;
    file->log = r->connection->log;
    if(ngx_read_file(file,buf,fi->st_size,0) != -1){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Read session file error");
        return NGX_ERROR;
    }
    
    line_data = ngx_palloc(r->pool,sizeof(ngx_str_t));
    if(line_data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory error");
        return NGX_ERROR;
    }
    
    line_data->data = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    if(line_data->data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory error");
        return NGX_ERROR;
    }
    
    key = ngx_palloc(r->pool,sizeof(ngx_str_t));
    value = ngx_palloc(r->pool,sizeof(ngx_str_t));
    if(key == NULL || value == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory error");
        return NGX_ERROR;
    }
    
    key->data = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    value->data = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    if(key->data == NULL || value->data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory error");
        return NGX_ERROR;
    }
    
    key->len=0;
    ngx_memzero(key->data,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    
    value->len = 0;
    ngx_memzero(value->data,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    
    line_data->len = 0;
    ngx_memzero(line_data->data,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    
    num = sizeof(session_datas)/sizeof(admin_core_session_line_data_t);
    while((buf=admin_core_get_line_data_from_buf(buf,line_data)) != NULL){
        if(admin_core_get_cookie_key_and_value(line_data,key,value) == NGX_ERROR){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Can not get session key and session value");
            return NGX_ERROR;
        }
        for(i=0;i<num;i++){
            if(session_datas[i].field_name.len == key->len &&
                    ngx_strncmp(session_datas[i].field_name.data,key->data,key->len) == 0){
                if(session_datas[i].field_type == 0){
                    session_datas[i].data->int_data = ngx_atoi(value->data,sizeof(u_char)*value->len);
                }
                else{
                    session_datas[i].data->str_data = *value;
                }
            }
        }
    }
    
    return NGX_OK;
}

static u_char *
admin_core_get_line_data_from_buf(u_char *buf,ngx_str_t *line_data){
    u_char                                  *p;
    ngx_int_t                               len;
    
    p = line_data->data;
    while(*buf != '\0'){
        if(*buf == ' ' || *buf == '\t'){
            buf++;
            continue;
        }
        if(*buf == CR || *buf == LF){
            buf++;
            break;
        }
        *p = *buf;
        p++;
        buf++;
        len++;
    }
    if(*buf == CR || *buf == LF){
        buf++;
    }
    
    line_data->len = len;
    
    if(*buf == '\0'){
        buf = NULL;
    }
    
    return buf;
}

static void
admin_core_form_data_handler(ngx_http_request_t *r){
    ngx_chain_t                                 *cl;
    ngx_buf_t                                   *b;
    size_t                                      len = 0;
    u_char                                      *p, *last, *buf;
    ngx_str_t                                   tmp_str;
    
    
    if (r->headers_in.content_type == NULL
        || r->headers_in.content_type->value.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"content_type is %p", r->headers_in.content_type);
        return ;
    }
    
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Not found form field");
        return ;
    }
    
    /* more than one buffer...we should copy the data out... */
    if (r->request_body->bufs->next != NULL) {
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            b = cl->buf;

            if (b->in_file) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "form-input: in-file buffer found. aborted. "
                              "consider increasing your "
                              "client_body_buffer_size setting");

                return ;
            }

            len += b->last - b->pos;
        }
        
        if (len == 0) {
            return ;
        }
        
        buf = ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return ;
        }
        
        p = buf;
        last = p + len;
        
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }   
    }
    else{
        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0) {
            return ;
        }
        
        buf = b->pos;
        last = b->last;
        len =  b->last - b->pos;
    }
    
    tmp_str.data = buf; 
    tmp_str.len = len;
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"We got form contents are:\'%V\'",&tmp_str);
    admin_core_handler_form_value(r,&tmp_str);
    return ;
    
}

static void
admin_core_handler_form_value(ngx_http_request_t *r,ngx_str_t *data){
    admin_core_form_input_ctx_t                         *ctx;
    u_char                                              *p,*d;
    ngx_int_t                                           i,flag;
    ngx_str_t                                           name,value;
    admin_core_form_input_filed_value_t                 *field_value;
    
    ctx = ngx_http_get_module_ctx(r, admin_core_module);
    if(ctx == NULL){
        return; 
    }
    
    if(data->len <1){
        return;
    }
    
    name.data = ngx_alloc(sizeof(u_char)*COOKIE_VALUE_MAX_LEN,r->connection->log);
    if(name.data == NULL){
        return;
    }
    value.data = ngx_alloc(sizeof(u_char)*COOKIE_VALUE_MAX_LEN,r->connection->log);
    if(value.data == NULL){
        ngx_free(name.data);
        return;
    }
    
    name.len =0;
    value.len = 0;
    d = data->data;
    flag = 0;
    ngx_memzero(name.data,sizeof(u_char)*COOKIE_VALUE_MAX_LEN);
    ngx_memzero(value.data,sizeof(u_char)*COOKIE_VALUE_MAX_LEN);
    for(i=0;i<data->len;i++){
        if(name.len == 0 && flag == 0){
            p = name.data;
        }
        
        if(value.len == 0 && flag == 1){
            p = value.data;
        }
        
        if(*d == ' '){
            d++;
            continue;
        }
        
        if(*d == '='){
            flag = 1;
            d++;
            continue;
        }
        
        if(*d == '&'){
            field_value = ngx_array_push(&ctx->inputs);
            field_value->name.data = ngx_palloc(r->pool,sizeof(u_char)*name.len);
            field_value->value.data = ngx_palloc(r->pool,sizeof(u_char)*value.len);
            if(field_value->name.data == NULL || field_value->value.data == NULL){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Alloc memory for form data error");
                return ; 
            }
            ngx_cpystrn(field_value->name.data,name.data,name.len);
            field_value->name.len = name.len;
            ngx_cpystrn(field_value->value.data,value.data,value.len);
            field_value->value.len = value.len;
            ngx_memzero(name.data,sizeof(u_char)*COOKIE_VALUE_MAX_LEN);
            name.len = 0;
            ngx_memzero(value.data,sizeof(u_char)*COOKIE_VALUE_MAX_LEN);
            value.len = 0;
            flag = 0;
            d++;
            continue;
        }
        *p++ = *d++;
        if(flag == 0){
            name.len++;
        }
        else{
            value.len++;
        }
    }
    
    return; 
}

static ngx_int_t 
admin_core_do_login_post(ngx_http_request_t *r,void *data){
    admin_core_form_input_ctx_t                         *ctx;
    admin_core_form_input_filed_value_t                 *form_datap,form_data;
    ngx_uint_t                                          i;
    ngx_str_t                                           *username,*password,*line_data,*user,*pass,tmpstr;
    admin_core_svr_conf_t                               *acscf;
    ngx_file_info_t                                     *fi;
    u_char                                              *buf,*p;
    ngx_file_t                                          *file;
    ngx_fd_t                                            fd; 
    ngx_int_t                                           rc,found,len;
    u_char                                              *encrypted;
    
    admin_core_msg.msgno = 0;
    ctx = ngx_http_get_module_ctx(r, admin_core_module);
    if(ctx == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    
    form_datap = ctx->inputs.elts;
    username = password = NULL;
    for(i=0;i<ctx->inputs.nelts;i++){
        form_data = form_data[i];
        if(form_data.name.len == (sizeof("username") - 1) &&
            ngx_strncmp(form_data.name.data,"username",form_data.name.len)){
            username = &form_data.value;
        }
        
        if(form_data.name.len == (sizeof("password") - 1) &&
            ngx_strncmp(form_data.name.data,"password",form_data.name.len)){
            username = &form_data.value;
        }
    }
    
    if(username == NULL || password == NULL){
        admin_core_msg = admin_core_get_error_msg(100);
        return NGX_DONE;
    }
    
    acscf = ngx_http_get_module_srv_conf(r,admin_core_module);
    if(acscf == NULL){
        admin_core_msg = admin_core_get_error_msg(102);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    fi = ngx_palloc(r->pool,sizeof(ngx_file_info_t));
    if(fi == NULL){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    buf = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    if(buf == NULL){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }

    fd = ngx_open_file(acscf->authfile.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", acscf->authfile.data);

        return NGX_DONE;
    }
    
    if(ngx_file_info(acscf->authfile.data,fi) == NGX_ERROR){
        admin_core_msg = admin_core_get_error_msg(105);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    file.fd = fd;
    file->info = *fi;
    file->log = r->connection->log;
    if(ngx_read_file(file,buf,fi->st_size,0) != -1){
        admin_core_msg = admin_core_get_error_msg(105);
        if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
            ngx_close_file_n " \"%s\" failed", file->name.data);
    }
    
    line_data = ngx_palloc(r->pool,sizeof(ngx_str_t));
    if(line_data == NULL){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    line_data->data = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    if(line_data->data == NULL){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    user = ngx_palloc(r->pool,sizeof(ngx_str_t));
    pass = ngx_palloc(r->pool,sizeof(ngx_str_t));
    if(user == NULL || pass == NULL){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    user->data = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    pass->data = ngx_palloc(r->pool,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    if(user->data == NULL || pass->data == NULL){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    user->len=0;
    ngx_memzero(user->data,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    
    pass->len = 0;
    ngx_memzero(pass->data,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    
    line_data->len = 0;
    ngx_memzero(line_data->data,sizeof(u_char)*SESSION_MAX_CONTENT_LEN);
    
    found = 0;
    while((buf=admin_core_get_line_data_from_buf(buf,line_data)) != NULL){
        p = line_data->data;
        if(*p == '#'){                                                          //Skip comment line
            continue;
        }
        
        tmpstr.data = line_data->data;
        p = ngx_strstr(line_data->data,':');
        tmpstr.len =  p - tmpstr.data;
        p++;
        user->data = p;
        p = ngx_strstr(line_data->data,':');
        user->len = p - user->data;
        p++;
        pass->data = p;
        p = ngx_strstr(p,':');
        pass->len = pass->data - p;
        if(username->len == user->len &&
            ngx_strncmp(username->data,user->data,user->len) == 0){
            found = 1;
            session_datas[2].data->int_data = ngx_atoi(tmpstr.data,tmpstr.len);
            break;
        }
    }
    
    if(found == 0){
        admin_core_msg = admin_core_get_error_msg(104);
        admin_core_msg->rewriteuri = &action_uris[1].actionuri;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,&admin_core_msg->msgtxt);
        return NGX_DONE;
    }
    
    rc = ngx_crypt(r->pool,password->data, pass->data,
                   &encrypted);
    if (rc == NGX_OK) {
        if (ngx_strcmp(encrypted, pass->data) == 0) {
            return NGX_OK;
        }
        session_datas[3].data->str_data.data = username->data;
        session_datas[3].data->str_data.len = username->len;
        tmpstr.data = line_data->data;
        p = ngx_strstr(line_data->data,':');                                    //username
        p++;
        p = ngx_strstr(line_data->data,':');                                    //password
        p++;
        p = ngx_strstr(line_data->data,':');                                    //level
        p++;
        len = p - tmpstr.data;
        len = line_data->len - len;
        session_datas[4].data->int_data = ngx_atoi(p,len);
    }
    
}


static admin_core_msg_t * 
admin_core_get_error_msg(ngx_int_t errorno){
    ngx_int_t                                  i,num;
    admin_core_msg_t                           *ret;
    
    ret = NULL;
    
    if(errorno <MIN_ERROR_NO || errorno >MAX_ERROR_NO){
        errorno = MAX_ERROR_NO;
    }
    
    num = sizeof(admin_core_msgs)/sizeof(admin_core_msg_t);
    for(i=0;i<num;i++){
        if(i == errorno){
            ret = &admin_core_msgs[i];
        }
    }
    
    return ret;
}