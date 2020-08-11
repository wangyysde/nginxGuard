/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ngx_snmp.h"
#include "asn1.h"

ngx_int_t 
ngx_snmp_build_integer(ngx_int_t value, u_char **buf)
{
    ngx_int_t           len;
    
    len = 0;
    if(value < 0x80){
        buf[len++] = value;
    }
    else if(value < 0x4000){
        buf[len++] = ((value >> 7) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    else if (value < 0x200000) {
        buf[len++] = ((value >> 14) | 0x80);
        buf[len++] = ((value >> 7 & 0x7f) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    else if (value < 0x10000000 ) {
        buf[len++] = ((value >> 21) | 0x80);
        buf[len++] = ((value >> 14 & 0x7f) | 0x80);
        buf[len++] = ((value >> 7 & 0x7f) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    else{
        buf[len++] = ((value >> 28) | 0x80);
        buf[len++] = ((value >> 21 & 0x7f) | 0x80);
        buf[len++] = ((value >> 14 & 0x7f) | 0x80);
        buf[len++] = ((value >> 7 & 0x7f) | 0x80);
        buf[len++] = (value & 0x07f);
    }
    return len;
}

static ngx_int_t
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