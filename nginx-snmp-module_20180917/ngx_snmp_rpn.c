#include "ngx_snmp.h"
#include "ngx_snmp_rpn.h"
#include <ngx_http.h>

ngx_int_t
ngx_snmp_build_rpn_express(ngx_str_t *express,rpn_element_list_t **list,ngx_snmp_item_value_t *siv){
    rpn_stack_t                                              *rpn_stack;
    ngx_snmp_core_server_data_t                              *server_data;
    ngx_uint_t                                               i;
    ngx_str_t                                                *obj_name;
    u_char                                                   *p,*tmp_data,c;
    int                                                       num_flag,field_flag;
    rpn_element_list_t                                       *head,*tail,*node;
    float                                                    value;
    rpn_element_t                                            e,*ep;
    ngx_snmp_express_cal_parameters_t                        express_parameters;
    
    head = tail = NULL;
    server_data = siv->server_data;
    rpn_stack = NULL;
    obj_name = NULL;
    if(ngx_snmp_rpn_init(&rpn_stack,server_data,siv) != NGX_OK){
        return NGX_ERROR;
    }
    p = express->data;
    field_flag = num_flag = 0;
    
    obj_name = ngx_alloc(sizeof(ngx_str_t),server_data->log);
    if(obj_name ==  NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Alloc memory error");
        goto free_stack;
    }
    obj_name->data = NULL;
    obj_name->data = ngx_alloc((sizeof(u_char)*SNNP_BUFFER_LENGTH),server_data->log);
    if(obj_name->data == NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Alloc memory error");
        goto free_obj_name;
    }
    
    ep = ngx_alloc(sizeof(rpn_element_t),server_data->log);
    if(ep == NULL){
        goto free_obj_name_data;
    }
  
    for(i=0;i<express->len;i++){
        node = NULL;
                
        if((('0' <= *p && '9' >= *p) && (field_flag == 0)) || ('.' == *p && num_flag == 1)){
            if(num_flag  == 0){
                ngx_memzero(obj_name->data,(sizeof(u_char)*SNNP_BUFFER_LENGTH));
                num_flag = 1;
                tmp_data =  obj_name->data;
                *tmp_data = *p;
                obj_name->len = 1;
                tmp_data++;
            }
            else{
                *tmp_data = *p;
                tmp_data++;
                obj_name->len++;
            }
           // if(*pn != '='){
            if((i+1)<express->len){
                p++;
                continue;
            }
        }
        
        if(num_flag == 1){
            num_flag = 0;
            node = ngx_alloc(sizeof(rpn_element_list_t),server_data->log);
            if(node == NULL){
                goto free_ep;
            }
            if(tail == NULL){
                head = tail = node;
            }
            else{
                tail->next = node;
                tail = node;
            }
            
            *tmp_data = '\0';
            node->value.value = strtof((const char *)obj_name->data,NULL);     
            if(node->value.value == 0){
                goto free_ep;
            }
            node->type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
            node->next = NULL;
        }
        
        if( (('A' <= *p  && 'Z' >= *p) || ('a' <= *p  && 'z' >= *p)) || ((('.' == *p) || ('_' == *p)  
            || ('0' <= *p && '9' >= *p)) && field_flag == 1)){
            
            if(field_flag  == 0){
                field_flag = 1;
                ngx_memzero(obj_name->data,(sizeof(u_char)*SNNP_BUFFER_LENGTH));
                tmp_data =  obj_name->data;
                *tmp_data = *p;
                obj_name->len = 1;
                tmp_data++;
            }
            else{
                *tmp_data = *p;
                tmp_data++;
                obj_name->len++;
            }
            if((i+1)<express->len){
                p++;
                continue;
            }
        }
        
        if(field_flag == 1){
            field_flag = 0;
            node = ngx_alloc(sizeof(rpn_element_list_t),server_data->log);
            if(node == NULL){
                goto free_ep;
            }
            if(tail == NULL){
                head = tail = node;
            }
            else{
                tail->next = node;
                tail = node;
            }
            
            express_parameters.obj_name = obj_name;
            express_parameters.siv = siv;
            express_parameters.cur_str = &p;
            express_parameters.pos = &i;
            express_parameters.express = express;
            express_parameters.ret = &value;
            if(ngx_snmp_get_object_value(&express_parameters) == NGX_ERROR){
                ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Get the object value error");
                goto free_ep;
                return NGX_ERROR;
            }
            node->value.value = value;
            node->type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
            node->next = NULL;
            if(express_parameters.obj_type != NGX_SNMP_KEYWORD_TYPE_OBJ){
                continue;
            }
        }
        
        if('(' == *p){
            e.type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
            e.value.op = '(';
            ngx_snmp_rpn_push(&rpn_stack, &e,server_data,siv);
        }
        
        if(')' == *p){
            for(;;){
                ngx_snmp_rpn_pop(&rpn_stack, &ep,server_data,siv);
                if(ep->type != NGX_SNMP_RPN_ELEMENT_TYPE_OP){
                    goto free_ep;
                }
                c = ep->value.op;
                if('(' == c)  break;
                node = ngx_alloc(sizeof(rpn_element_list_t),server_data->log);
                if(node == NULL){
                    goto free_ep;
                }
                if(tail == NULL){
                    head = tail = node;
                }
                else{
                    tail->next = node;
                    tail = node;
                }
                node->value.op = c;
                node->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
                node->next = NULL;
            }
        }
        
        if('+' == *p || '-' == *p || '*' == *p || '/' == *p){
            if(rpn_getoplevel(rpn_stack->value.op)<rpn_getoplevel(*p)){
                e.type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
                e.value.op = *p;
                ngx_snmp_rpn_push(&rpn_stack, &e,server_data,siv);
            }
            else{
                for( ;; ){
                    ngx_snmp_rpn_pop(&rpn_stack, &ep,server_data,siv);
                    if(ep->type != NGX_SNMP_RPN_ELEMENT_TYPE_OP){
                        goto free_ep;
                    }
                    c = ep->value.op;
                    if(rpn_getoplevel(c)<rpn_getoplevel(*p)){
                        if(c != NGX_SNMP_RPN_STACK_END_FLAG){
                            e.type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
                            e.value.op = c; 
                            ngx_snmp_rpn_push(&rpn_stack, &e,server_data,siv);
                        }
                        e.type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
                        e.value.op = *p;
                        ngx_snmp_rpn_push(&rpn_stack, &e,server_data,siv);
                        break;
                    }
                    node = ngx_alloc(sizeof(rpn_element_list_t),server_data->log);
                    if(node == NULL){
                        goto free_ep;
                    }
                    if(tail == NULL){
                        head = tail = node;
                    }
                    else{
                        tail->next = node;
                        tail = node;
                    }
                    node->value.op = c;
                    node->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
                    node->next = NULL;
                }
            }
        }
        
        p++;
    };       
    
    for( ;; ){
        ngx_snmp_rpn_pop(&rpn_stack, &ep,server_data,siv);
        if(ep->type == NGX_SNMP_RPN_ELEMENT_TYPE_OP ){
            c = ep->value.op;
            if(c == NGX_SNMP_RPN_STACK_END_FLAG)  break;
        }
        node = ngx_alloc(sizeof(rpn_element_list_t),server_data->log);
        if(node == NULL){
            goto free_list;
        }
        if(tail == NULL){
            head = tail = node;
        }
        else{
            tail->next = node;
            tail = node;
        }
        if(ep->type == NGX_SNMP_RPN_ELEMENT_TYPE_OP){
            node->value.op = ep->value.op;
            node->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
        }
        else{
            node->value.value = ep->value.value;
            node->type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
        }
        node->next = NULL;
    }
    
    *list = head;
    
    return NGX_OK;
    
free_list:
    if(head != NULL){
        ngx_snmp_rpn_free_list(head);
    }
    

free_ep:
    ngx_free(ep);

free_obj_name_data:
    if(obj_name->data != NULL){
        ngx_free(obj_name->data);
    }

free_obj_name:
    if(obj_name != NULL){
        ngx_free(obj_name);
    }

free_stack:
    ngx_free(rpn_stack);
    return NGX_ERROR;
}

ngx_int_t 
ngx_snmp_rpn_init(rpn_stack_t **s,ngx_snmp_core_server_data_t  *server_data,ngx_snmp_item_value_t *siv){
    rpn_stack_t                 *p;
    
    p = ngx_alloc(sizeof(rpn_stack_t),server_data->log);
    if(p ==  NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "There is a error ocurred when allocing memory for initate stack for item:\"%V\"",&siv->item->name);
        return NGX_ERROR;
    }
    p->value.op = NGX_SNMP_RPN_STACK_END_FLAG;
    p->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
    p->next=NULL;
    
    *s = p;
    return NGX_OK;
}

ngx_int_t
ngx_snmp_rpn_push(rpn_stack_t **s,rpn_element_t *e,ngx_snmp_core_server_data_t  *server_data,ngx_snmp_item_value_t *siv){
    rpn_stack_t                 *p;
    
    p = ngx_alloc(sizeof(rpn_stack_t),server_data->log);
    if(p ==  NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "There is a error ocurred when allocing memory for initate stack for item:\"%V\"",&siv->item->name);
        return NGX_ERROR;
    }
    if(e->type == NGX_SNMP_RPN_ELEMENT_TYPE_OP ){
        p->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
        p->value.op = e->value.op;
    }
    else{
        p->type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
        p->value.value = e->value.value;
    }
    p->next=*s;
    *s=p;
    
    return NGX_OK;
}

ngx_int_t
ngx_snmp_rpn_pop(rpn_stack_t **s, rpn_element_t **e,ngx_snmp_core_server_data_t  *server_data,ngx_snmp_item_value_t *siv){
    rpn_stack_t                     *p;
    
    if((*s)->next){
        p = *s;
        if((*s)->type == NGX_SNMP_RPN_ELEMENT_TYPE_OP){
            (*e)->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
            (*e)->value.op = (*s)->value.op;
        }
        else{
            (*e)->type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
            (*e)->value.value = (*s)->value.value;
        }
        *s = (*s)->next;
        ngx_free(p);
        p=NULL;
    }
    else
    {
        (*e)->type = NGX_SNMP_RPN_ELEMENT_TYPE_OP;
        (*e)->value.op = NGX_SNMP_RPN_STACK_END_FLAG;
    }
    
    return NGX_OK;
}

int  rpn_getoplevel(u_char op){
    if(op=='+' || op=='-')
        return 1;
    if(op=='*' || op=='/')
        return 2;
    return 0;
}

ngx_int_t 
ngx_snmp_rpn_free_list(rpn_element_list_t *node){
    rpn_element_list_t           *next;
    
    next = node->next;
    if(next != NULL){
        ngx_snmp_rpn_free_list(next);
    }
    ngx_free(node);
    return NGX_OK;
}
  
ngx_int_t 
ngx_snmp_rpn_cac_express(rpn_element_list_t *node,float *ret,ngx_snmp_item_value_t *siv){
    rpn_stack_t                                             *rpn_stack;
    rpn_element_t                                            e,*ep;
    float                                                    x,y;
    u_char                                                     *p;
    ngx_snmp_core_server_data_t                              *server_data;
    
    server_data = siv->server_data;

    ep = ngx_alloc(sizeof(rpn_element_t),server_data->log);
    if(ep == NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Alloc memory error");
        return NGX_ERROR;
    }
    ngx_snmp_rpn_init(&rpn_stack,server_data,siv);
    
    while(node != NULL){
        if(node->type == NGX_SNMP_RPN_ELEMENT_TYPE_VALUE){
            e.type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
            e.value.value = node->value.value;
            ngx_snmp_rpn_push(&rpn_stack,&e,server_data,siv);
        }
        else{
            p = &(node->value.op);
            ngx_snmp_rpn_pop(&rpn_stack,&ep,server_data,siv);
            x = ep->value.value;
            ngx_snmp_rpn_pop(&rpn_stack,&ep,server_data,siv);
            y = ep->value.value;
            switch(*p){
                case '+':
                    e.type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
                    e.value.value = y + x;
                    ngx_snmp_rpn_push(&rpn_stack,&e,server_data,siv);
                    break;
                case '-':
                    e.type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
                    e.value.value = y - x;
                    ngx_snmp_rpn_push(&rpn_stack,&e,server_data,siv);
                    break;
                case '*':
                    e.type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
                    e.value.value = y * x;
                    ngx_snmp_rpn_push(&rpn_stack,&e,server_data,siv);
                    break;
                case '/':
                    e.type = NGX_SNMP_RPN_ELEMENT_TYPE_VALUE;
                    if(x == 0){
                        e.value.value = 0;
                    }
                    else{
                        e.value.value = y/x;
                    }
                    ngx_snmp_rpn_push(&rpn_stack,&e,server_data,siv);
                    break;
            }
        }
        node = node->next;
    }
    
    ngx_snmp_rpn_pop(&rpn_stack,&ep,server_data,siv);
    *ret = ep->value.value;
    
    ngx_free(ep);
    return NGX_OK;
}



ngx_int_t 
ngx_snmp_get_object_value(ngx_snmp_express_cal_parameters_t *ep){
    ngx_snmp_core_object_session_t                         *ossp,s;
    ngx_uint_t                                             *i,j,flag;
    //ngx_snmp_fun_handler_t                                 *node;
    ngx_snmp_fun_pt                                         fun_pt;
    ngx_str_t                                              *obj_name,fun_obj_name;
    ngx_snmp_item_value_t                                  *siv;
    ngx_snmp_core_server_data_t                            *server_data;
    ngx_snmp_express_cal_parameters_t                      fun_data;
    u_char                                                 **p;
    ngx_snmp_core_express_fun_handler_t                    fun_obj;
    char                                                   *ret;
    
    
    siv = ep->siv;
    server_data =  siv->server_data;
    obj_name = ep->obj_name;
    
    ret = ngx_snmp_core_getKeepworld(*obj_name,&fun_obj);
    fun_pt = NULL;
    if(ret == NGX_CONF_OK){
        fun_pt = fun_obj.ngx_snmp_fun_pt;
        if(fun_obj.keyword_type == NGX_SNMP_KEYWORD_TYPE_KEYWORD){
            if(fun_pt != NULL){
                ep->obj_type = NGX_SNMP_KEYWORD_TYPE_KEYWORD;
                return (*fun_pt)(ep);
            }
            else{
                ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                    "Internal error:no function for keyword:\"%V\"",obj_name);
                return NGX_ERROR;
            }
        }
        
        if(fun_obj.keyword_type == NGX_SNMP_KEYWORD_TYPE_FUN){
            fun_data.obj_name = &fun_obj_name;
            p = ep->cur_str;
            flag = 0;
            fun_data.obj_name->len = 0; 
            for(i=ep->pos;*i<ep->express->len;(*i)++){
                if( (('A' <= **p  && 'Z' >= **p) || ('a' <= **p  && 'z' >= **p)) && flag == 1 ){
                    flag = 2;
                    fun_data.obj_name->data = *p;
                }
                if(flag == 0 && **p == '('){
                    flag = 1;
                }
                if(flag  == 2 && **p == ')'){
                    flag = 3;
                    (*p)++;
                    break;
                }
                (*p)++;
                if(flag == 2){
                    fun_data.obj_name->len++;
                }
            }
                
            if(flag == 3){
                fun_data.ret = ep->ret;
                fun_data.siv = ep->siv;
                if(fun_pt != NULL){
                    if(((*fun_pt)(&fun_data)) == NGX_OK){
                        *(ep->ret) = *(fun_data.ret);
                        ep->obj_type = NGX_SNMP_KEYWORD_TYPE_FUN;
                        return NGX_OK;
                    }
                    else{
                        return NGX_ERROR;
                    }
                }
                else{
                    ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                        "Internal error:no function for keyword:\"%V\"",obj_name);
                    return NGX_ERROR;
                }
            }
                
            if(flag ==1 || flag ==2){
                ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                    ") no found in Keyword:\"%V\"",obj_name);
                return NGX_ERROR;
            }
                
            if(flag == 0){
                ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                   "( no found in Keyword:\"%V\"",obj_name);
                return NGX_ERROR;
            }
            
        }
                 
    }
          
    ossp = siv->object_session->elts;
    for(j=0;j<siv->object_session->nelts;j++){
        s = ossp[j];
        if(ngx_strcmp(&s.core_object->name,obj_name) == 0){
            if(s.value_type == SNMP_OBJECT_VALUETYPE_INT){
                *(ep->ret) = s.value;
                ep->obj_type = NGX_SNMP_KEYWORD_TYPE_OBJ;
            }
            else{
                *(ep->ret) = s.value*0.01;
                ep->obj_type = NGX_SNMP_KEYWORD_TYPE_OBJ;
            }
            return NGX_OK;
        }
    }
    
    return NGX_ERROR;
}