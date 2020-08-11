/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ngx_snmp_rpn.h
 * Author: wangyuying
 *
 * Created on 2018年8月23日, 上午11:11
 */

#ifndef NGX_SNMP_RPN_H
#define NGX_SNMP_RPN_H

#ifdef __cplusplus
extern "C" {
#endif

#define NGX_SNMP_RPN_STACK_END_FLAG      '#'
#define NGX_SNMP_RPN_ELEMENT_TYPE_OP      1
#define NGX_SNMP_RPN_ELEMENT_TYPE_VALUE   0
    
typedef union rpn_element{
    float                 value;
    u_char                op;
}rpn_element_u;

typedef struct __stack__{
    rpn_element_u              value; 
    int                        type;
    struct __stack__           *next;
}rpn_stack_t;

typedef struct __rpnList__{
    rpn_element_u              value; 
    int                        type;
    struct __rpnList__         *next;
}rpn_element_list_t;

typedef struct {
    rpn_element_u         value;
    int                   type;
}rpn_element_t;

typedef struct {
    ngx_str_t                   *obj_name;
    float                       *ret;
    ngx_snmp_item_value_t       *siv;
    u_char                      **cur_str;
    ngx_uint_t                  *pos;
    ngx_int_t                   obj_type;
    ngx_str_t                   *express;
}ngx_snmp_express_cal_parameters_t;

ngx_int_t
ngx_snmp_build_rpn_express(ngx_str_t *express,rpn_element_list_t **list,ngx_snmp_item_value_t *siv);
ngx_int_t 
ngx_snmp_rpn_init(rpn_stack_t **s,ngx_snmp_core_server_data_t  *server_data,ngx_snmp_item_value_t *siv);
ngx_int_t 
ngx_snmp_rpn_free_list(rpn_element_list_t *node);
ngx_int_t 
ngx_snmp_get_object_value(ngx_snmp_express_cal_parameters_t *ep);
ngx_int_t
ngx_snmp_rpn_push(rpn_stack_t **s,rpn_element_t *e,ngx_snmp_core_server_data_t  *server_data,ngx_snmp_item_value_t *siv);
ngx_int_t
ngx_snmp_rpn_pop(rpn_stack_t **s, rpn_element_t **e,ngx_snmp_core_server_data_t  *server_data,ngx_snmp_item_value_t *siv);
int  rpn_getoplevel(u_char op);
ngx_int_t 
ngx_snmp_rpn_cac_express(rpn_element_list_t *node,float *ret,ngx_snmp_item_value_t *siv);


#ifdef __cplusplus
}
#endif

#endif /* NGX_SNMP_RPN_H */

