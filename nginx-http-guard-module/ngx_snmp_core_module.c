/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp_core_module.h"

static ngx_snmp_module_t  ngx_snmp_core_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL ,                                   /* postconfiguration */

    ngx_snmp_core_create_main_conf,        /* create main configuration */
    ngx_snmp_core_init_main_conf,          /* init main configuration */

    ngx_snmp_core_create_group_conf,         /* create server configuration */
    ngx_snmp_core_merge_group_conf,          /* merge server configuration */

    ngx_snmp_core_create_item_conf,           /* create location configuration */
    ngx_snmp_core_merge_item_conf,             /* merge location configuration */
    
    ngx_snmp_core_create_object_conf,           /* create location configuration */
    ngx_snmp_core_merge_object_conf             /* merge location configuration */
};



ngx_module_t  ngx_snmp_core_module = {
    NGX_MODULE_V1,
    &ngx_snmp_core_module_ctx,             /* module context */
    ngx_snmp_core_commands,                /* module directives */
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

