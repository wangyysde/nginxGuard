/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   asn1.h
 * Author: wangyuying
 *
 * Created on 2018年6月19日, 下午10:36
 */

#ifndef ASN1_H
#define ASN1_H

#ifdef __cplusplus
extern "C" {
#endif

    
ngx_int_t 
ngx_snmp_build_integer(ngx_int_t value, u_char *buf);
static ngx_int_t
ngx_snmp_move_oct(ngx_str_t *str,ngx_int_t num);


#ifdef __cplusplus
}
#endif

#endif /* ASN1_H */

