/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp.h"

typedef struct {
    ngx_str_t                            community;
    ngx_str_t                            *pdu_community; 
} ngx_snmp_v2c_group_t;


static void *
ngx_snmp_v2c_create_group_conf(ngx_conf_t *cf);
ngx_int_t ngx_snmp_v2c_requid_handler(ngx_snmp_core_object_session_t *s);
ngx_int_t 
ngx_snmp_v2c_head_handler(ngx_snmp_core_object_session_t *s);
ngx_int_t 
ngx_snmp_v2c_request_handler(ngx_snmp_core_object_session_t *s);
ngx_int_t 
ngx_snmp_v2c_finish_pdu_handler(ngx_snmp_core_object_session_t *s);
static ngx_int_t
ngx_snmp_v2c_post_conf(ngx_conf_t *cf);
ngx_int_t 
ngx_snmp_v2c_parse_pdu_handler(ngx_snmp_core_object_session_t *s);



static ngx_snmp_module_t  ngx_snmp_v2c_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_snmp_v2c_post_conf,                   /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_snmp_v2c_create_group_conf,           /* create group configuration */
    NULL,                                     /* merge group configuration */
    NULL,                                     /* create item configuration */
    NULL,                                     /* merge item configuration */
    NULL,                                     /* create object configuration */
    NULL                                      /* merge object configuration */
};

static ngx_command_t  ngx_snmp_v2c_commands[] = {
    { ngx_string("community"),
      NGX_SNMP_MAIN_CONF|NGX_SNMP_GROUP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_SNMP_GROUP_CONF_OFFSET,
      offsetof(ngx_snmp_v2c_group_t, community),
      NULL },
      
      ngx_null_command
};

ngx_module_t  ngx_snmp_v2c_module = {
    NGX_MODULE_V1,
    &ngx_snmp_v2c_module_ctx,             /* module context */
    ngx_snmp_v2c_commands,                 /* module directives */
    NGX_SNMP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_snmp_v2c_create_group_conf(ngx_conf_t *cf)
{
    ngx_snmp_v2c_group_t   *conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_snmp_v2c_group_t));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->pdu_community = ngx_pcalloc(cf->pool, sizeof(ngx_str_t *));
    if (conf->pdu_community == NULL) {
        return NULL;
    }
    
    conf->pdu_community->data = ngx_pcalloc(cf->pool, sizeof(u_char) * SNNP_BUFFER_LENGTH);
    if (conf->pdu_community->data == NULL) {
        return NULL;
    }
    conf->pdu_community->len = 0;
    
    return conf;
    
}

static ngx_int_t
ngx_snmp_v2c_post_conf(ngx_conf_t *cf)
{
    ngx_snmp_core_group_t               **scgs,*scg; 
    ngx_snmp_core_main_conf_t           *scmf; 
    ngx_uint_t                          i; 
    ngx_snmp_conf_ctx_t                 *ctx; 
    
    scmf = ngx_snmp_conf_get_module_main_conf(cf,ngx_snmp_core_module);
    
    if(scmf == NULL)
    {
        return NGX_ERROR;
    }
    
    scgs = scmf->groups.elts;
    for(i=0;i<scmf->groups.nelts;i++)
    {
        scg = scgs[i];
        if(scg->version == SNMP_VERSION_2C) 
        {  
            ctx =scg->ctx;
            scg->pdu_handler.requid_handler = ngx_snmp_v2c_requid_handler;
            scg->pdu_handler.head_handler = ngx_snmp_v2c_head_handler;
            scg->pdu_handler.request_hanlder = ngx_snmp_v2c_request_handler;
            scg->pdu_handler.finish_pdu_hander = ngx_snmp_v2c_finish_pdu_handler;
            scg->pdu_handler.parse_pdu_handler = ngx_snmp_v2c_parse_pdu_handler;
        }
    }
    
    return NGX_OK; 
}

/*
    SNMP_GET_REQUEST + Length + DATA_TYPE_INT + RequestIdLength + RequestID +DATA_TYPE_INT
 */
ngx_int_t 
ngx_snmp_v2c_requid_handler(ngx_snmp_core_object_session_t *s)
{
    ngx_int_t                                       sn,len,octlen,i,j; 
    u_char                                          *tmp_data,*ptmpstr_data; 
    ngx_str_t                                       *pdu_requid,tmp_str;
    
    sn = (ngx_int_t)ngx_time();
    s->sent_sn = sn;
    
    tmp_str.len = 0;
    tmp_str.data =  ngx_alloc( sizeof(u_char) * SNNP_BUFFER_LENGTH,s->pool->log);
    if(tmp_str.data == NULL)
    {
        return NGX_ERROR;
    }
    ptmpstr_data = tmp_str.data;
    
    pdu_requid = s->core_object->pdu_reqid;
    pdu_requid->len = 0;
        
    tmp_str.len = 0;
    j = 0;
    for(;sn>0;){
        i = sn & 0xFF;
        tmp_str.data[j] = i;
        j++;
	sn >>=8;
    }
    
    tmp_data = &(pdu_requid->data[(SNNP_BUFFER_LENGTH - pdu_requid->len -1)]);
    for(i=(j-1);i>-1;i--)
    {
        tmp_data[0] = tmp_str.data[i];
        tmp_data--;
    }
    pdu_requid->len += j;
    
    octlen = ngx_snmp_build_integer(j,tmp_str.data);
    tmp_data = &(pdu_requid->data[(SNNP_BUFFER_LENGTH - pdu_requid->len -1)]);
    for(i=(octlen-1);i>-1;i--)
    {
        tmp_data[0] = tmp_str.data[i];
        tmp_data--;
    }
    pdu_requid->len += octlen;
    
    tmp_data = &(pdu_requid->data[(SNNP_BUFFER_LENGTH - pdu_requid->len -1)]);
    tmp_data[0] = DATA_TYPE_INT;
    pdu_requid->len++;
    
    len = s->core_object->pdu_obj->len + pdu_requid->len-1;
    octlen = ngx_snmp_build_integer(len,tmp_str.data);
    
    tmp_data = &(pdu_requid->data[(SNNP_BUFFER_LENGTH - pdu_requid->len -1)]);
    for(i=(octlen-1);i>-1;i--)
    {
        tmp_data[0] = tmp_str.data[i];
        tmp_data--;
    }
    pdu_requid->len += octlen;
    
    tmp_data = &(pdu_requid->data[(SNNP_BUFFER_LENGTH - pdu_requid->len -1)]);
    tmp_data[0] = SNMP_GET_REQUEST;
    pdu_requid->len++;
    
    tmp_data = &(pdu_requid->data[(SNNP_BUFFER_LENGTH - pdu_requid->len)]);
    tmp_data = ngx_copy(pdu_requid->data,tmp_data,pdu_requid->len);
    
    tmp_str.data=ptmpstr_data;
    ngx_free(tmp_str.data);
    
    return NGX_OK;
}

/*
 *  errstat: DATA_TYPE_INT + DATA_TYPE_ONE + DATA_TYPE_ZERO + 
 *  errindex DATA_TYPE_INT + DATA_TYPE_ONE + DATA_TYPE_ZERO +
 *  DATA_TYPE_SEQ + TailLength + DATA_TYPE_SEQ + TailLength + 
 *  DATA_TYPE_OBJID + OidLength + Oid + DATA_TYPE_NULL + DATA_TYPE_ZERO + SNMP_STRING_END
 */

ngx_int_t 
ngx_snmp_v2c_request_handler(ngx_snmp_core_object_session_t *s)
{
    ngx_str_t                       tmp_str,*obj_pdu,oid_str;
    u_char                          *tmp_data,*tmp_oid,*ptmpstr_data;
    ngx_int_t                       i,j,flag,firstobj,secobj,nodeoid,octlen;
    
    tmp_str.len = 0;
    tmp_str.data = ngx_alloc( sizeof(u_char) * SNNP_BUFFER_LENGTH,s->pool->log);
    if(tmp_str.data == NULL)
    {
        return NGX_ERROR;
    }
    ptmpstr_data = tmp_str.data;
    
    obj_pdu = s->core_object->pdu_obj;
    obj_pdu->len = 0;
    
    ngx_memzero(tmp_str.data,(sizeof(u_char)*SNNP_BUFFER_LENGTH));
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = SNMP_STRING_END;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_ZERO;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_NULL;
    obj_pdu->len++;
    
    oid_str = s->core_object->oid;
    if(oid_str.len<2)
    {
        ngx_log_error(NGX_LOG_ERR,s->server_data->log, 0, "The object oid you input is too short");
        return NGX_ERROR;
    }
    
    j = flag = 0;
    tmp_oid = s->core_object->oid.data;
    for(i=0;i<(ngx_int_t)oid_str.len;i++)
    {
        if(tmp_oid[j] == '.')
        {
            if(flag == 0)
            {
                firstobj = ngx_atoi(tmp_oid,j);
            }
            else if(flag == 1)
            {
                secobj = ngx_atoi(tmp_oid,j);
                nodeoid = 40 * firstobj + secobj; 
            }
            else
            {
                nodeoid = ngx_atoi(tmp_oid,j);
            }
            if( flag != 0 ){
                octlen = ngx_snmp_build_integer(nodeoid,&(tmp_str.data[tmp_str.len]));
                tmp_str.len += octlen; 
            }
            tmp_oid = &(oid_str.data[i]);
            tmp_oid++;
            j = 0;
            flag++;
        }
        else
        {
            j++;
        }
    }
    
    if(oid_str.data[(i-1)] == '.')
    {
        ngx_log_error(NGX_LOG_ERR,s->server_data->log, 0, "The object oid you input is invalid");
        return NGX_ERROR;
    }
    else
    {
        if(flag == 1)
        {
            secobj = ngx_atoi(tmp_oid,j);
            nodeoid = 40 * firstobj + secobj; 
        }
        else
        {
            nodeoid = ngx_atoi(tmp_oid,j);
        }
        octlen = ngx_snmp_build_integer(nodeoid,&(tmp_str.data[tmp_str.len]));
        tmp_str.len += octlen; 
    }
    
    for(i=(tmp_str.len - 1);i>-1;i--)
    {
        tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
        tmp_data[0] = tmp_str.data[i];
        obj_pdu->len++;
    }
    
    octlen = ngx_snmp_build_integer(tmp_str.len,tmp_str.data);
    for(i=(octlen - 1);i>-1;i--)
    {
        tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
        tmp_data[0] = tmp_str.data[i];
        obj_pdu->len++;
    }
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_OBJID;
    obj_pdu->len++;
    
    octlen = ngx_snmp_build_integer((obj_pdu->len - 1),tmp_str.data);
    for(i=(octlen - 1);i>-1;i--)
    {
        tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
        tmp_data[0] = tmp_str.data[i];
        obj_pdu->len++;
    }
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_SEQ;
    obj_pdu->len++;
    
    octlen = ngx_snmp_build_integer((obj_pdu->len - 1),tmp_str.data);
    for(i=(octlen - 1);i>-1;i--)
    {
        tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
        tmp_data[0] = tmp_str.data[i];
        obj_pdu->len++;
    }
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_SEQ;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_ZERO;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_ONE;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_INT;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_ZERO;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_ONE;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len -1)]);
    tmp_data[0] = DATA_TYPE_INT;
    obj_pdu->len++;
    
    tmp_data = &(obj_pdu->data[(SNNP_BUFFER_LENGTH - obj_pdu->len)]);
    tmp_data = ngx_copy(obj_pdu->data,tmp_data,obj_pdu->len);
    
    tmp_str.data = ptmpstr_data; 
    ngx_free(tmp_str.data);
    
    return NGX_OK;
}
/*
 * DATA_TYPE_SEQ + TailLength + DATA_TYPE_INT + DATA_TYPE_ONE + VERSION +
 * DATA_TYPE_OCTSTR + CommunityLength + COMMUNITY 
 */
ngx_int_t 
ngx_snmp_v2c_head_handler(ngx_snmp_core_object_session_t *s)
{
    ngx_snmp_conf_ctx_t                             *ctx; 
    ngx_snmp_v2c_group_t                            *sv2gcf;
    ngx_snmp_core_group_t                           *scg; 
    ngx_str_t                                       *pdu_community,*pdu_requid,*pdu_obj,*pdu_head,tmp_str;
    ngx_int_t                                       i,len,octlen;
    u_char                                          *tmp_data,*ptmpstr_data;
    
    tmp_str.len = 0;
    tmp_str.data =  ngx_alloc( sizeof(u_char) * SNNP_BUFFER_LENGTH,s->pool->log);
    if(tmp_str.data == NULL)
    {
        return NGX_ERROR;
    }
    ptmpstr_data = tmp_str.data;
    
    ctx = s->core_object->ctx;
    sv2gcf = ctx->group_conf[ngx_snmp_v2c_module.ctx_index];
    scg = ctx->group_conf[ngx_snmp_core_module.ctx_index];
    pdu_community = &sv2gcf->community;
    pdu_requid = s->core_object->pdu_reqid;
    pdu_obj = s->core_object->pdu_obj;
    pdu_head = s->core_object->pdu_head;
    pdu_head->len = 0;
    
    for((i=(ngx_int_t)pdu_community->len -1);i>-1;i--)
    {
        tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
        tmp_data[0] = pdu_community->data[i];
        pdu_head->len++;
    }
    
    octlen = ngx_snmp_build_integer(pdu_community->len,tmp_str.data);
    for((i=octlen-1);i>-1;i--)
    {
        tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
        tmp_data[0] = tmp_str.data[i];
        pdu_head->len++;
    }
    
    tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
    tmp_data[0] = DATA_TYPE_OCTSTR;
    pdu_head->len++;
    
    tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
    tmp_data[0] = scg->version;
    pdu_head->len++;
    
    tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
    tmp_data[0] = DATA_TYPE_ONE;
    pdu_head->len++;
    
    tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
    tmp_data[0] = DATA_TYPE_INT;
    pdu_head->len++;
    
    len  =  pdu_head->len + pdu_requid->len + pdu_obj->len - 1;
    octlen = ngx_snmp_build_integer(len,tmp_str.data);
    for((i=octlen-1);i>-1;i--)
    {
        tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
        tmp_data[0] = tmp_str.data[i];
        pdu_head->len++;
    }
    
    tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len -1)]);
    tmp_data[0] = DATA_TYPE_SEQ;
    pdu_head->len++;
    
    tmp_data = &(pdu_head->data[(SNNP_BUFFER_LENGTH - pdu_head->len)]);
    tmp_data = ngx_copy(pdu_head->data,tmp_data,pdu_head->len);
    
    tmp_str.data = ptmpstr_data;
    ngx_free(tmp_str.data);
    
    return NGX_OK;
}


ngx_int_t 
ngx_snmp_v2c_finish_pdu_handler(ngx_snmp_core_object_session_t *s)
{
    ngx_str_t                                       *send_buf,*pdu_head,*pdu_requid,*pdu_obj;
    ngx_int_t                                       i,j;
        
    if(ngx_snmp_v2c_requid_handler(s) != NGX_OK)
    {
        return NGX_ERROR;
    }
    
    if(ngx_snmp_v2c_head_handler(s) !=  NGX_OK)
    {
        return NGX_ERROR;
    }
    
    send_buf = &s->send_buf;
    pdu_head = s->core_object->pdu_head;
    for(i=0;i<(ngx_int_t)pdu_head->len;i++)
    {
        send_buf->data[i] = pdu_head->data[i];
    }
    
    pdu_requid = s->core_object->pdu_reqid;
    for(j=0;j<(ngx_int_t)pdu_requid->len;j++)
    {
        send_buf->data[i++] = pdu_requid->data[j];
    }
    
    pdu_obj = s->core_object->pdu_obj;
    for(j=0;j<(ngx_int_t)pdu_obj->len;j++)
    {
        send_buf->data[i++] = pdu_obj->data[j];
    }
    send_buf->len = (i-1);
    
    return NGX_OK; 
}

ngx_int_t
ngx_snmp_move_oct(ngx_str_t *str,ngx_int_t num)
{
    ngx_int_t                   i; 
    u_char                      *data;
    
    data = str->data;
    if(data == NULL || str->len < 1 || num < 1)
    {
        return NGX_ERROR;
    }
    for(i=(str->len - 1);i>-1;i--)
    {
        data[(i+num)] = data[i];
    }
    return NGX_OK; 
}

/*
 * DATA_TYPE_SEQ + TotalLength + DATA_TYPE_INT + DATA_TYPE_ONE + VERSION +
 * DATA_TYPE_OCTSTR + CommunityLength + COMMUNITY+SNMP_GET_RESPONSE +
 * Length + DATA_TYPE_INT + RequestIdLength + RequestID +DATA_TYPE_INT +
 * errstat: DATA_TYPE_INT + DATA_TYPE_ONE + DATA_TYPE_ZERO + 
 *  errindex DATA_TYPE_INT + DATA_TYPE_ONE + DATA_TYPE_ZERO +
 *  DATA_TYPE_SEQ + TailLength + DATA_TYPE_SEQ + TailLength + 
 *  DATA_TYPE_OBJID + OidLength + Oid + variable-bindings
 */

ngx_int_t 
ngx_snmp_v2c_parse_pdu_handler(ngx_snmp_core_object_session_t *s){
    ngx_snmp_core_server_data_t                            *server_data; 
    ngx_str_t                                              *rev_buf,*tmp_str;
    u_char                                                 *recv;
    ngx_uint_t                                             i,j,k,total_octs_len,octs_len;
    ngx_int_t                                              type;
    
    server_data = s->server_data;
    ngx_log_error(NGX_LOG_DEBUG,server_data->log , 0, 
                "Now try to parseing SNMP PDU");
    
   octs_len = 0;
    rev_buf = &s->recv_buf;
    recv = rev_buf->data;
    
    //Get total PDUs length
    i=1;
    total_octs_len = recv[i];
    if(recv[i]> 0x80){
        octs_len = recv[i] & 0x7F;
        total_octs_len = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                total_octs_len <<= 8;
            }
            total_octs_len = total_octs_len | recv[i++];
        }
        i--;
    }
    
    //Skip version and Get community length 
    i += 5;
    octs_len = 0;
    k = recv[i];
    if(k > 0x80){                      //If community length is bigger than 127
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--;
    }
    i += k;
    
    if(recv[++i] != SNMP_GET_RESPONSE){   // A error occurred for parased error or data error
        ngx_log_error(NGX_LOG_ERR,server_data->log , 0, 
                "Get a invalid SNMP PDU");
        return NGX_ERROR;
    }
    
    //Get data length again and check it
    i++;
    k = recv[i];  
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--;
    }
   
    if( (k+i-1) != total_octs_len){
        ngx_log_error(NGX_LOG_ERR,server_data->log , 0, 
                "Get a invalid SNMP PDU");
        return NGX_ERROR;
    }
    
    //Get Requestid length
    i += 2;
    k = recv[i]; 
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--;
    }
    
    //Skip RequestID
    i++;
    i += k; 
    i += 2; 
    if(recv[i] != 0x00 || recv[(i+3)] != 0x00){
        ngx_log_error(NGX_LOG_ERR,server_data->log , 0, 
                "Have ocured a error");
        return NGX_ERROR;
    }
    
    /*
 
 *  DATA_TYPE_SEQ + TailLength + DATA_TYPE_SEQ + TailLength + 
 *  DATA_TYPE_OBJID + OidLength + Oid + variable-bindings
 */
    i += 5;
    k = recv[i];
    octs_len = 0;                       //Get PDU length again and check it 
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--;
    }
    
    if( (k+i-1) != total_octs_len){
        ngx_log_error(NGX_LOG_ERR,server_data->log , 0, 
                "Parseing PDU error");
        return NGX_ERROR;
    }
    
    i += 2;
    k = recv[i];    
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--;
    }
    
    i += 2;
    k = recv[i];    
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--; 
    }
    i++;
    
    //Skip OID
    i += k;
    
    //Get DataType
    type = recv[i++];
    
    //Get the message length and Check it
    k = recv[i];
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        i++;
        k = 0;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv[i++];
        }
        i--;
    }
    if( (k+i-1) != total_octs_len){
        ngx_log_error(NGX_LOG_ERR,server_data->log , 0, 
                "Parseing PDU error");
        return NGX_ERROR;
    }
    
    //Get the returned message
    tmp_str = &s->tmp_buf;
    tmp_str->len = 0;
    ngx_memzero(tmp_str->data,(size_t)(sizeof(u_char)*SNNP_BUFFER_LENGTH));
    tmp_str->len = k;
    i++;
    for(j=0;j<k;j++){
        tmp_str->data[j] = recv[i++];
    }
    tmp_str->data[++j] = '\0';
    
    s->data_type = type;
    ngx_log_error(NGX_LOG_DEBUG,server_data->log , 0, 
                "SNMP PDU data has been parsed.");
    
    return NGX_OK;
    
}