/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp.h"
#include <ngx_http.h>
#include "ngx_snmp_rpn.h"

extern ngx_module_t  ngx_snmp_module; 

static ngx_int_t 
ngx_snmp_http_init_process (ngx_cycle_t *cycle);
static  void 
snmp_query_event_handler(ngx_event_t *snmp_query_event);
static ngx_int_t 
ngx_snmp_http_rbtree_insert(ngx_snmp_core_server_data_t  *server_data);
static void 
ngx_snmp_try_send_data_to_server(ngx_snmp_core_server_data_t *server_data);
static ngx_int_t
ngx_snmp_get_peer(ngx_peer_connection_t *pc, void *data);
static void
ngx_snmp_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state);
static ngx_int_t
ngx_snmp_check_server_if_down(ngx_snmp_core_server_data_t  *server_data);
static void
ngx_snmp_oss_recv(ngx_event_t *rev);
static void
ngx_snmp_oss_dummy_send(ngx_event_t *wev);
static ngx_int_t
ngx_snmp_handle_object_session_error(ngx_snmp_core_object_session_t *oss);
static ngx_int_t
ngx_snmp_http_caculate_expression(ngx_snmp_item_value_t *siv);
static ngx_int_t
ngx_snmp_http_change_server_stats(ngx_snmp_core_object_session_t *oss,ngx_int_t stats);
static ngx_int_t
ngx_snmp_http_handler_received_data(ngx_snmp_core_object_session_t *oss);


static ngx_http_module_t  ngx_snmp_http_module_ctx = {     // 
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

static ngx_command_t  ngx_snmp_http_commands[] = {
   
    ngx_null_command
};

ngx_module_t  ngx_snmp_http_module = {
    NGX_MODULE_V1,
    &ngx_snmp_http_module_ctx,             /* module context */
    ngx_snmp_http_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type  */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_snmp_http_init_process,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t 
ngx_snmp_http_init_process (ngx_cycle_t *cycle){
    ngx_snmp_core_main_conf_t               *scmcf;
    static ngx_event_t                      snmp_query_event; 
    static ngx_connection_t                 dumb;
    ngx_slab_pool_t                         *shpool;
    ngx_snmp_timer_start_status_t           *start_status;
    ngx_queue_t                             *queue;
    ngx_snmp_server_data_queue_t            *server_data_queue;
    
    scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(cycle,ngx_snmp_core_module);
    if(scmcf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Can not get SNMP module main conf");
        return NGX_ERROR;
    }
        
    shpool = (ngx_slab_pool_t *) scmcf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    start_status = scmcf->start_status;
    
    if(start_status->is_start){
        start_status->running_process_num++;
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }
    
    start_status->is_start = 1; 
    start_status->running_process_num++;
    start_status->pid = ngx_getpid();
    ngx_shmtx_unlock(&shpool->mutex);
    
    for(queue = ngx_queue_head(&scmcf->server_data_queue);
        queue != ngx_queue_sentinel(&scmcf->server_data_queue);
        queue = ngx_queue_next(queue))
    {
        server_data_queue = ngx_queue_data(queue, ngx_snmp_server_data_queue_t, queue);        
        if(ngx_snmp_http_rbtree_insert(server_data_queue->server_data) == NGX_ERROR)
        {
            ngx_log_error(NGX_LOG_ERR,cycle->log, 0, "Insert Server \"%V\" data into red-black tree error",&server_data_queue->server_data->name);
            return NGX_ERROR;
        }
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Setting SNMP query event ");
    snmp_query_event.handler=snmp_query_event_handler;
    snmp_query_event.log=cycle->log; 
    snmp_query_event.data=&dumb; 
    dumb.fd=(ngx_socket_t)-1; 
    dumb.data = cycle;
    ngx_add_timer(&snmp_query_event, SNMP_TIMER_INTERVAL*1000);
    
    return NGX_OK;
}

static  void 
snmp_query_event_handler(ngx_event_t *snmp_query_event)
{ 
    static ngx_connection_t                 *dumb;
    ngx_cycle_t                             *cycle;
    ngx_snmp_core_main_conf_t               *scmcf;
    ngx_rbtree_node_t                       *node, *root, *sentinel;
    ngx_event_t                             *ev;
    ngx_snmp_core_server_data_t             *server_data;
    ngx_core_conf_t                         *ccf;
    ngx_slab_pool_t                         *shpool;
    ngx_snmp_timer_start_status_t           *start_status;
    ngx_pid_t                               pid; 
     
    ngx_log_error(NGX_LOG_DEBUG, snmp_query_event->log, 0, "SNMP query event handler has been called"); 
    
    dumb = (ngx_connection_t *)snmp_query_event->data;
    cycle = dumb->data;
    
    scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(cycle,ngx_snmp_core_module);
    if(scmcf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Can not get SNMP module main conf");
        return ;
    }
    
    pid = ngx_getpid();
    
    shpool = (ngx_slab_pool_t *) scmcf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    start_status = scmcf->start_status;
    if(start_status->pid != pid){
        ngx_del_timer(snmp_query_event);
        ngx_shmtx_unlock(&shpool->mutex);
        return;
    }
    
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_add_timer(snmp_query_event, SNMP_TIMER_INTERVAL*1000);
    
    sentinel = &scmcf->ngx_snmp_event_timer_sentinel;
    
    for( ;; ){
        root = scmcf->snmp_rbtree.root; 
        if (root == sentinel) {
            return;
        }
        
        node = ngx_rbtree_min(root, sentinel);
        
        if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
            return;
        }
        
        ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Get a SNMP query request");
        
        ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));
        server_data = (ngx_snmp_core_server_data_t *)ev->data;
        
        ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
        
        if(scmcf->start_status->running_process_num >= ccf->worker_processes){
            shpool = (ngx_slab_pool_t *) scmcf->shm_zone->shm.addr;
            ngx_shmtx_lock(&shpool->mutex);
            start_status = scmcf->start_status;
            if(start_status->is_start){
                start_status->is_start = 0;
                scmcf->start_status->running_process_num = ccf->worker_processes;
            }
            ngx_shmtx_unlock(&shpool->mutex);
        }
        
        ngx_snmp_try_send_data_to_server(server_data);
        ngx_rbtree_delete(&scmcf->snmp_rbtree,&ev->timer);
        ngx_snmp_http_rbtree_insert(server_data);
                
    }
         
    return ;
}

static ngx_int_t 
ngx_snmp_http_rbtree_insert(ngx_snmp_core_server_data_t  *server_data)
{
    ngx_cycle_t                             *cycle;
    ngx_msec_t                              key;
    ngx_event_t                             *ev;
    ngx_int_t                               interval;
    ngx_snmp_core_main_conf_t               *scmcf;
    
    
    cycle = server_data->cycle;
    if(server_data->down)
    {
        interval = SERVER_STATUS_CHECK_INTERVAL;
    }
    else {
        interval = server_data->group->interval;
    }
    
    ngx_time_update();
    key = ngx_current_msec + interval*1000;
    
    ev = ngx_palloc(cycle->pool, sizeof(ngx_event_t));
    if(ev == NULL){
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Alloc memory for ev error");
        return NGX_ERROR;
    }
    
    ev->timer.key = key;
    ev->data = server_data;
    scmcf = (ngx_snmp_core_main_conf_t *) ngx_snmp_cycle_get_module_main_conf(cycle,ngx_snmp_core_module);
    if(scmcf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Can not get SNMP module main conf");
        return NGX_ERROR;
    }
    
    ngx_rbtree_insert(&scmcf->snmp_rbtree, &(ev->timer));
    
    return NGX_OK;
}

static void 
ngx_snmp_try_send_data_to_server(ngx_snmp_core_server_data_t *server_data){
    
    ngx_array_t                                            *ar_item,*ar_oss;
    ngx_snmp_item_value_t                                  **sivp,*siv;
    ngx_int_t                                              rc,send_sn,error_flag,flag,ret;
    ngx_uint_t                                             i,j,error_item_count;
    ngx_snmp_core_object_session_t                         *ossp,*oss,*osspp;
    ngx_peer_connection_t                                  *pc;
    ngx_connection_t                                       *c;
    ngx_snmp_pdu_handler_t                                 pdu_handler; 
    ngx_snmp_core_group_t                                  *scg;
    ngx_slab_pool_t                                       *shpool;
    ngx_snmp_handler_pt                                    handler;
    struct sockaddr_in                                     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                                     *sin6;
#endif
    
    ar_item = server_data->item_value;
    sivp = ar_item->elts;
    send_sn = (ngx_int_t)ngx_time();
    error_item_count = 0;
    server_data->last_error_request_id = send_sn;
    
    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Now try sending SNMP query to Server:\"%V\"",&server_data->name);
    
    for(i=0;i<ar_item->nelts;i++){
        siv = sivp[i];
        shpool = (ngx_slab_pool_t *) siv->shm_zone->shm.addr;
        error_flag = 0;
        ngx_shmtx_lock(&shpool->mutex);
        siv->sent_sn = send_sn;
        siv->updatetime = (ngx_int_t)ngx_time();
        ngx_shmtx_unlock(&shpool->mutex);
        ar_oss = siv->object_session;
        ossp = ar_oss->elts;
        osspp = ar_oss->elts;
        
        ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, "Now starting send SNMP PDUs on Item : \"%V\" to Server : \"%V\"",&siv->item->name,&server_data->name);
        
        for(j=0;j<ar_oss->nelts;j++){
            oss = &ossp[j];
            oss->sent_sn = send_sn;
            pc = oss->pc;
            
            flag  = 0;
            if(pc->name == NULL || pc->connection == NULL){
                pc->name = &server_data->snmp_addrs->name;
                pc->local = NULL;
                pc->sockaddr = server_data->snmp_addrs->sockaddr;
                pc->socklen = server_data->snmp_addrs->socklen;
                pc->log = server_data->log;
                pc->data = ossp;
                pc->get = ngx_snmp_get_peer;
                pc->free = ngx_snmp_free_peer;
                pc->type = SOCK_DGRAM;
                flag = 1;
                switch(server_data->snmp_addrs->sockaddr->sa_family){
#if (NGX_HAVE_INET6)
                    case AF_INET6:
                        sin6 = (struct sockaddr_in6 *) pc->sockaddr; 
                        sin6->sin6_port = htons((in_port_t) server_data->group->port);
                        break;
#endif
                    default: /* AF_INET */
                        sin = (struct sockaddr_in *) pc->sockaddr;
                        sin->sin_port = htons((in_port_t)server_data->group->port);
                        break;
                }
            }
            else{
                c = pc->connection;
                if(c->fd == ((ngx_socket_t) -1)){
                    flag = 1;
                }
            }
            
            if(flag){
                rc = ngx_event_connect_peer(pc);
                if (rc != NGX_OK && rc != NGX_AGAIN )
                {
                    pc->connection = NULL; 
                    ngx_log_error(NGX_LOG_EMERG,server_data->log, 0,"Create snmp connection to server: \"%V\" failed",&server_data->name);
                    ngx_snmp_check_server_if_down(server_data);
                    return;
                }
            }
                      
            c = pc->connection;
            c->data = osspp;
            c->pool = oss->pool;
            c->read->handler = ngx_snmp_oss_recv;
            c->write->handler = ngx_snmp_oss_dummy_send;
            scg = ngx_snmp_get_module_group_conf(oss,ngx_snmp_core_module);
            pdu_handler = scg->pdu_handler;
            handler = pdu_handler.request_hanlder;
            
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(oss);
                    ngx_log_error(NGX_LOG_EMERG, server_data->log, 0, "Call request handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
            
            handler = pdu_handler.requid_handler;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(oss);
                    ngx_log_error(NGX_LOG_EMERG, server_data->log, 0, "Call requid handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
            
            handler = pdu_handler.head_handler;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(oss);
                    ngx_log_error(NGX_LOG_EMERG, server_data->log, 0, "Call head handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }
            
            handler = pdu_handler.finish_pdu_hander;
            if(handler != NGX_CONF_UNSET_PTR)
            {
                ret = (*handler)(oss);
                if(ret != NGX_OK)
                {
                    ngx_snmp_handle_object_session_error(oss);
                    ngx_log_error(NGX_LOG_EMERG, server_data->log, 0, "Call finish handler on Server: \"%V\" error",&server_data->name);
                    error_flag = 1;
                    break;
                }
            }

            if((c->send(c,oss->send_buf.data,oss->send_buf.len)) <((ssize_t)(oss->send_buf.len)))
            {
                ngx_log_error(NGX_LOG_EMERG, server_data->log, 0, "Sent request PDU to  Server: \"%V\" error",&server_data->name);
                ngx_snmp_handle_object_session_error(oss);
                error_flag = 1;
                if(c->read->timer_set)
                {
                    ngx_del_timer(c->read);
                }
                break;
            }
            osspp++;
        }
        
        if(error_flag == 1){
            error_item_count++;
            siv->value = -1;
        }
    }
        
    if(error_item_count >= ar_item->nelts){
        server_data->error_count++;
        ngx_snmp_check_server_if_down(server_data);
    }

    return ;
}

static ngx_int_t
ngx_snmp_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}

static void
ngx_snmp_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state)
{
    return; 
}

static ngx_int_t
ngx_snmp_check_server_if_down(ngx_snmp_core_server_data_t  *server_data)
{
    ngx_snmp_core_group_t                                  *scg;
    
    scg = server_data->group;
    server_data->flag = 1;
    server_data->error_count++;
    if(server_data->error_count >= scg->fall)
    {
        server_data->down = 1;
        server_data->last_down_time = (ngx_int_t)ngx_time();
        server_data->flag = 1;
        ngx_log_error(NGX_LOG_INFO, server_data->log, 0, "Server: \"%V\" has been changed to down because of too many errors",&server_data->name);
    }
    
    return NGX_OK; 
}

static void
ngx_snmp_oss_recv(ngx_event_t *rev)
{
    ngx_connection_t                                       *c;
    ngx_snmp_core_object_session_t                         *oss;
    ngx_str_t                                              *rev_buf;
    ngx_int_t                                              n,rc;
    ngx_snmp_handler_pt                                    handler;
    u_char                                                 *recv_buf;
    ngx_snmp_core_group_t                                  *scg;
    ngx_snmp_pdu_handler_t                                 pdu_handler; 
    ngx_snmp_core_server_data_t                           *server_data;
    
    c = rev->data;
    oss = c->data;
    server_data = oss->server_data;
    
    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, 
                "Try to receiveing SNMP response from server");
    
    if(rev->timedout){
        ngx_log_error(NGX_LOG_ERR, server_data->log, NGX_ETIMEDOUT, 
                "Receiving snmp data timed out");
        return; 
    }
    
    scg = ngx_snmp_get_module_group_conf(oss,ngx_snmp_core_module);
    pdu_handler = (ngx_snmp_pdu_handler_t)scg->pdu_handler;
            
    rev_buf = &(oss->recv_buf);
    recv_buf = rev_buf->data;
    ngx_memzero(recv_buf,(size_t)(sizeof(u_char)*SNNP_BUFFER_LENGTH));
    
    while(rev->ready){
        n = c->recv(c,recv_buf,(size_t)(sizeof(u_char)*SNNP_BUFFER_LENGTH));
        if(n == NGX_AGAIN){
            break;
        }
        if(n == NGX_ERROR){
            ngx_log_error(NGX_LOG_EMERG, server_data->log, NGX_ETIMEDOUT, 
                "Received a incorrect SNMP PDU ");
            ngx_snmp_http_change_server_stats(oss,1);
            return;
        }
    }
    
    if(pdu_handler.parse_pdu_handler == NGX_CONF_UNSET_PTR){
        ngx_log_error(NGX_LOG_EMERG,server_data->log, 0, 
                "No parse handler for received response PDU");
        ngx_snmp_http_change_server_stats(oss,1);
        return;        
    }
    
    handler =  pdu_handler.parse_pdu_handler;
    rc = (*handler)(oss);
    
    if(rc == NGX_OK){
        ngx_log_error(NGX_LOG_DEBUG, rev->log, 0, 
                "Get a correct SNMP response ");
        if(ngx_snmp_http_handler_received_data(oss) != NGX_OK){
            ngx_snmp_http_change_server_stats(oss,1);
        }
        else{
            ngx_snmp_http_change_server_stats(oss,0);
        }
    }
    else{
        ngx_log_error(NGX_LOG_ERR, rev->log, 0, 
                "The SNMP PDU just received is incorrectly.");
        ngx_snmp_http_change_server_stats(oss,1);
    }
   
    return; 
}

static void
ngx_snmp_oss_dummy_send(ngx_event_t *wev)
{
    return;
}

static ngx_int_t
ngx_snmp_handle_object_session_error(ngx_snmp_core_object_session_t *oss)
{
    ngx_snmp_item_value_t                                   *siv;
    ngx_snmp_core_server_data_t                             *ssd;
    ngx_slab_pool_t                                        *shpool;
    
    siv = oss->item_value;
    ssd = oss->server_data;
    
    oss->value = -1;
    oss->updatetime = (ngx_int_t)ngx_time();
    oss->error_count++;
    oss->last_stats = 1;
    if(siv->error_sn != oss->sent_sn)
    {
        shpool = (ngx_slab_pool_t *) siv->shm_zone->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        siv->error_sn = oss->sent_sn;
        siv->value = -1;
        siv->updatetime = oss->updatetime;
        siv->error_count++;
        ngx_shmtx_unlock(&shpool->mutex);
    }
    
    return NGX_OK;
}


static ngx_int_t
ngx_snmp_http_change_server_stats(ngx_snmp_core_object_session_t *oss,ngx_int_t stats){
    ngx_snmp_core_server_data_t                            *server_data; 
    ngx_array_t                                            *ar_item,*ar_oss;
    ngx_snmp_item_value_t                                  *sivp,siv;
    ngx_uint_t                                             i,item_flag,oss_flag;
    ngx_snmp_core_object_session_t                         *ossp,s;
    ngx_slab_pool_t                                        *shpool;
    
    server_data = oss->server_data;
    
    oss->updatetime = oss->updatetime;
    oss->last_stats = oss->stats;
    oss->received_sn = oss->sent_sn;
    oss->updatetime = (ngx_int_t)ngx_time();
    if(stats == 0){
        oss->stats = 0;
        oss->error_count = 0;
    }
    else{
        oss->stats = 1;
        oss->error_count++;
    }
    
    sivp = oss->item_value;
    ar_oss = sivp->object_session;
    oss_flag = 0;
    ossp = ar_oss->elts;
    for(i=0;i<ar_oss->nelts;i++){
        s = ossp[i];
        if(s.sent_sn != s.received_sn){
            return NGX_OK;
        }
        oss_flag++;
    }
    
    shpool = (ngx_slab_pool_t *) sivp->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    oss_flag = 0;
    if(stats == 0){
        for(i=0;i<ar_oss->nelts;i++){
            s = ossp[i];
            if(s.stats == 1){
                oss_flag++;
            }
        }
        
        if(oss_flag){
            sivp->received_sn = sivp->sent_sn;
            sivp->error_sn = sivp->sent_sn;
            sivp->last_value = sivp->value;
            sivp->last_updatetime = sivp->updatetime;
            sivp->last_stats = sivp->stats;
            sivp->value = 0;
            sivp->updatetime = (ngx_int_t)ngx_time();
            sivp->stats = 1;
            sivp->error_count++;
        }
        else{
            sivp->received_sn = sivp->sent_sn;
            sivp->last_value = sivp->value;
            sivp->last_updatetime = sivp->updatetime;
            sivp->last_stats = sivp->stats;
            sivp->updatetime = (ngx_int_t)ngx_time();
            if(ngx_snmp_http_caculate_expression(sivp) != NGX_OK){
                sivp->error_sn =  sivp->sent_sn;
                sivp->stats = 1;
                sivp->error_count++;
            }
            else{
                sivp->error_sn = 0;
                sivp->stats = 0;
                sivp->error_count = 0;
            }
        }
    }
    else{
        sivp->received_sn = sivp->sent_sn;
        sivp->error_sn = sivp->sent_sn;
        sivp->last_value = sivp->value;
        sivp->last_updatetime = sivp->updatetime;
        sivp->last_stats = sivp->stats;
        sivp->value = 0;
        sivp->updatetime = (ngx_int_t)ngx_time();
        sivp->stats = 1;
        sivp->error_count++;
    }
    
    ngx_shmtx_unlock(&shpool->mutex);
    ar_item = server_data->item_value;
    sivp = ar_item->elts;
    item_flag = 0;
    for(i=0;i<ar_item->nelts;i++){
        siv = sivp[i];
        if(siv.sent_sn != siv.received_sn){
            return NGX_OK;
        }
        if(siv.stats == 1){
            item_flag++;
        }
    }
    
    if(item_flag >= ar_item->nelts){
        server_data->last_error_request_id = siv.sent_sn;
        return ngx_snmp_check_server_if_down(server_data);
    }
    else{
        server_data->flag = 0;
        server_data->error_count = 0;
        server_data->down = 0;
    }
    
    return NGX_OK;
    
}

static ngx_int_t
ngx_snmp_http_caculate_expression(ngx_snmp_item_value_t *siv){
    ngx_snmp_core_object_session_t                         *ossp,s;
    ngx_str_t                                              express;
    ngx_snmp_core_server_data_t                            *server_data;
    char                                                   *data;
    u_char                                                 *tmp_data;
    ngx_uint_t                                             i;
    rpn_element_list_t                                     *list;
    float                                                  item_value;
    
    if(siv->object_session->nelts <2){
        ossp = siv->object_session->elts;
        s = ossp[0];
        siv->last_stats = siv->stats;
        siv->last_updatetime = siv->updatetime;
        siv->last_value = siv->value;
        siv->stats = 0;
        siv->updatetime = (ngx_int_t)ngx_time();
        if(s.value_type == SNMP_OBJECT_VALUETYPE_INT){
            siv->value = s.value;
        }
        else{
            siv->value = s.value * 0.01;
        }
        siv->error_count = 0;
        siv->received_sn = siv->sent_sn;
        return NGX_OK;
    }
    
    server_data = siv->server_data;
    if(siv->item->express.len<3){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "The express:\"%V\" of item:\"%V\" is inavlid",&siv->item->express,&siv->item->name);
        return NGX_ERROR;
    }
    
    tmp_data = siv->item->express.data;
    data = ngx_strchr((char *)tmp_data,'=');
    if(data == NULL){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "The express:\"%V\" of item:\"%V\" is inavlid",&siv->item->express,&siv->item->name);
        return NGX_ERROR;
    }
    data++;
    express.data = (u_char *)(&data[0]);
    i = express.data - tmp_data;
    express.len = siv->item->express.len - i;

   
    if(ngx_snmp_build_rpn_express(&express,&list,siv) != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Build RPN express for item:\"%V\" is errror",&siv->item->name);
        return NGX_ERROR;
    }
    
    if(ngx_snmp_rpn_cac_express(list,&item_value,siv)!= NGX_OK){
        ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Calculate express for item:\"%V\" is errror",&siv->item->name);
        return NGX_ERROR;
    }
        
    siv->error_count = 0;
    siv->last_stats = siv->stats;
    siv->last_updatetime = siv->updatetime;
    siv->last_value = siv->value;
    siv->received_sn = siv->sent_sn;
    siv->stats = 0;
    siv->updatetime = (ngx_int_t)ngx_time();
    siv->value = item_value;
    
    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, 
                "Get a value:%2f for item:\"%V\"",item_value, &siv->item->name);
    
    return NGX_OK;
}

static ngx_int_t
ngx_snmp_http_handler_received_data(ngx_snmp_core_object_session_t *oss){
    ngx_snmp_core_server_data_t                           *server_data;
    ngx_int_t                                              type,value;
    ngx_uint_t                                             i;
    ngx_str_t                                              oid;
    
    server_data = oss->server_data;
    type = oss->data_type;
    oid = oss->core_object->oid;
    
    switch(type){                                      //Ref: snmplib/mib.c sprint_realloc_by_type
        case DATA_TYPE_ZERO:
        case DATA_TYPE_BOOL:
        case DATA_TYPE_BITSTR:
        case DATA_TYPE_NULL:
        case DATA_TYPE_OBJID:
        case DATA_TYPE_SEQUENCE:
        case DATA_TYPE_ENUM:
        case DATA_TYPE_SEQ:
        case DATA_TYPE_IPADDRESS:
            ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Value of object:\"%V\" is a Bool,We can not using this type data",&oid);
            return NGX_ERROR;
            break;
        case DATA_TYPE_INT:
            if(oss->tmp_buf.data[0] & 0x80){
                value = -1;
            }
            else{
                value  = 0 ;
            }
            for(i=0;i<oss->tmp_buf.len;i++){
                value  = (value << 8) | oss->tmp_buf.data[i];
            }
            CHECK_OVERFLOW_S(value,1);
            oss->value_type = SNMP_OBJECT_VALUETYPE_INT;
            break;
        case DATA_TYPE_OCTSTR:
            value = ngx_atofp(oss->tmp_buf.data,oss->tmp_buf.len,2);
            CHECK_OVERFLOW_S(value,1);
            oss->value_type = SNMP_OBJECT_VALUETYPE_FLOAT;
            break;
        case DATA_TYPE_COUNTER:                    //Ref snmplib/snmp_api.c  4494
        case DATA_TYPE_UNSIGNED:
        case DATA_TYPE_TIMETICKS:
        case DATA_TYPE_COUNTER64:
            value = 0;
            if(oss->tmp_buf.data[0] & 0x80){
                value = ~value;
            }
            for(i=0;i<oss->tmp_buf.len;i++){
                value  = (value << 8) | oss->tmp_buf.data[i];
            }
            CHECK_OVERFLOW_U(value,2);
            oss->value_type = SNMP_OBJECT_VALUETYPE_INT;
            break;
        case DATA_TYPE_NOSUCHOBJECT:
            ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "No Such Object available on this agent for OID:\"%V\"",&oid);
            return NGX_ERROR;
            break;
        case DATA_TYPE_NOSUCHINSTANCE:
            ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "No Such Instance currently exists at OID:\"%V\"",&oid);
            return NGX_ERROR;
            break;
        case DATA_TYPE_ENDOFMIBVIEW:
            ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "No more variables left in this MIB View (It is past the end of the MIB tree) for OID:\"%V\"",&oid);
            return NGX_ERROR;
            break;
        default:
            ngx_log_error(NGX_LOG_ERR, server_data->log, 0, 
                "Get a Unknow type data for OID:\"%V\"",&oid);
            return NGX_ERROR;
            break;
    }
    
    oss->last_stats = oss->stats;
    oss->last_updatetime = oss->updatetime;
    oss->last_value = oss->value;
    oss->stats = 0;
    oss->updatetime = (ngx_int_t)ngx_time();
    oss->value = value;
    oss->error_count = 0;
    oss->received_sn = oss->sent_sn;
    ngx_log_error(NGX_LOG_DEBUG, server_data->log, 0, 
                "Get a value:%i for object:\"%V\"",value,&oid);
    return NGX_OK;
}
