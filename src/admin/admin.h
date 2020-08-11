/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   admin.h
 * Author: wangyuying
 *
 * Created on 2018年10月12日, 上午11:05
 */

#ifndef ADMIN_H
#define ADMIN_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ADMIN_PAGE_DIR
#define ADMIN_PAGE_DIR  "admin_pages"
#endif
    
#ifndef UPSTREAM_CONF_DIR
#define UPSTREAM_CONF_DIR  "upstreams"
#endif
    
#ifndef SESSION_DIR
#define SESSION_DIR  "sessions"
#endif

#define ADMIN_CORE_AUTH_FILE "authz/authz.data"
#define MAX_PATH_LEN  1024
#define DEFAULT_ACCESS_MODE 0777
#define COOKIE_VALUE_MAX_LEN 256
#define SESSION_MAX_EXPIRE 1800
#define SESSION_MAX_CONTENT_LEN 1024
#define MESSAGE_TYPE_SUCCESS 0
#define MESSAGE_TYPE_ERROR 1
#define MIN_ERROR_NO   100
#define MAX_ERROR_NO   10000
    
typedef struct {
    ngx_array_t                         admin_core_srv;                         /*admin_core_svr_conf_t */ 
}admin_core_main_conf_t;
    
typedef struct {
//    ngx_flag_t                          admin_flag;
    ngx_str_t                           admin_page_dir;
    ngx_str_t                           ngx_main_conf;
    ngx_str_t                           upstream_conf_dir;
    ngx_str_t                           session_file_dir;
    ngx_str_t                           authfile;
    ngx_int_t                           session_max_expire;

}admin_core_svr_conf_t;

typedef struct {
    ngx_flag_t                          admin_flag;
}admin_core_loc_conf_t;


union sess_field_data {
    ngx_str_t           str_data;
    ngx_int_t           int_data;
};
typedef struct {
    ngx_str_t                  field_name;
    ngx_int_t                  field_type;
    union sess_field_data      *data;
}admin_core_session_line_data_t;

admin_core_session_line_data_t session_datas[] = {
    {ngx_string("sessid"),1,NULL},
    {ngx_string("refresh_data"),0,NULL},
    {ngx_string("userid"),0,NULL},
    {ngx_string("user_name"),1,NULL},
    {ngx_string("user_level"),1,NULL}
};

ngx_str_t form_field_name[] = {
    ngx_string("username"),
    ngx_string("password")
};

typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  value;
}bzhy_admin_http_variable_t;
        
//typedef ngx_int_t (*admin_core_form_input_handler_pt) (ngx_http_request_t *r,void *data);  
/*
typedef struct {
    ngx_str_t                             action;
    admin_core_form_input_handler_pt      *handler;
}admin_core_form_action_route_t;

typedef struct {
    ngx_int_t                  actionno;
    ngx_str_t                  actionuri;
}admin_core_action_uri_t;

admin_core_action_uri_t   action_uris[] = {
    {0,ngx_string("/")},
    {1,ngx_string("/login.html")},                                               //Login page
    {2,ngx_string("/deny.html")},
    {3,ngx_string("/internal_error.html")}
};


typedef struct {
    ngx_int_t                msgno;                                             
    ngx_int_t                type;                                              
    ngx_str_t                msgtxt;
    ngx_str_t                *rewriteuri;                                       
}admin_core_msg_t;

admin_core_msg_t admin_core_msgs[] = {
    {100,MESSAGE_TYPE_ERROR,ngx_string("No username or password"),&action_uris[0].actionuri},
    {101,MESSAGE_TYPE_ERROR,ngx_string("Username or Password is incorrecty"),&action_uris[1].actionuri},
    {102,MESSAGE_TYPE_ERROR,ngx_string("Can not got configure"),&action_uris[0].actionuri},
    {103,MESSAGE_TYPE_ERROR,ngx_string("You are denied"),&action_uris[2].actionuri},
    {104,MESSAGE_TYPE_ERROR,ngx_string("Alloc memory error"),NULL},
    {105,MESSAGE_TYPE_ERROR,ngx_string("Server internal error"),&action_uris[3].actionuri},
    {10000,MESSAGE_TYPE_ERROR,ngx_string("Unkown error"),&action_uris[0].actionuri}
};
*/


#ifdef __cplusplus
}
#endif

#endif /* ADMIN_H */

