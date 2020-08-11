/*
 * File:   snmpget.c
 * Author: wangyuying
 *
 * Created on 2017 12 05,4:37
 * Comments:
 * This program can get SNMP message from the remote host by given REMOTE IP, REMOTE PORT
 * COMMUNITY and Object OID via SNMP V2c.
 * Note:
 *    1. Today, this program is support SNMP V2c ONLY.
 *    2. Today, ONLY numberical OID is supported .
 * On successful, one of two type data will be returned:
 *    INTEGER (msg->type=0 or msg->type =1):
 *        msg->value is the return data
 *    STRING(msg->type=2): 
 *        msg->valuemsg is the return data
 *        msg->length is the string lenght
 * 
 * Website: http://www.bzhy.com
 * Email: net_use@bzhy.com
 * 
*/
#ifndef  _SNMPGET_H
#include "snmpget.h"
#endif

/*
 * Set snmp_session and the elements of snmp_session to NULL
 */
int  initate_snmp_session(snmp_session_t *snmp_session){
    if(snmp_session == NULL){
        return(0);
    }
    snmp_session->community = NULL;
    snmp_session->objoid = NULL; 
    snmp_session->remote_ip = NULL; 
    snmp_session->reqid = NULL;
    snmp_session->objoid_str =  NULL; 
    return(1);
}

/*
 * Set receive_msg and the elements of receive_msg to NULL
 */
int  initate_snmp_receive_msg(receive_msg_t *receive_msg){
    if(receive_msg == NULL){
        return(0);
    }
    receive_msg->msg = NULL;
    receive_msg->objoid = NULL;
    receive_msg->reqid = NULL; 
    return(1);
}

/*
 * Get the error message by snmp_errno 
 * Return: char pointer 
 */
char *snmp_strerror(int snmp_errno){
    char *tmperrmsg,*errmsg;
    int len;
    if(snmp_errno<200){
        tmperrmsg =  strerror(snmp_errno);
        len = strlen(tmperrmsg);
    }
    else{
        tmperrmsg = (char *)malloc(sizeof(char)*MAX_BUF_LENGTH);
        switch(snmp_errno){
            case SNMP_ERR_CODE_ALLOC:
                strncpy(tmperrmsg,"Alloc memory error",strlen("Alloc memory error"));
                len = strlen("Alloc memory error")+1;
                break;
            case SNMP_ERR_CODE_UNAVAIABLED_MSG:
                strncpy(tmperrmsg,"Received a unavaiabled message",strlen("Received a unavaiabled message"));
                len = strlen("Received a unavaiabled message")+1;
                break;
            case SNMP_ERR_CODE_STATUS:
                strncpy(tmperrmsg,"Status error",strlen("Status error"));
                len = strlen("Status error")+1;
                break;
            case SNMP_ERR_PARASE_ERR:
                strncpy(tmperrmsg,"Parameters error",strlen("Parameters error"));
                len = strlen("Parameters error")+1;
                break;
            case SNMP_ERR_UNREQUEST_MSG:
                strncpy(tmperrmsg,"Can not get the messages",strlen("Can not get the messages"));
                len = strlen("Can not get the messages")+1;
                break;
            case SNMP_ERR_UNKNOW_MSG:
                strncpy(tmperrmsg,"Get an unknown message",strlen("Get an unknown message"));
                len = strlen("Get an unknown message")+1;
                break;
            case SNMP_ERR_BUILD_PDU:
                strncpy(tmperrmsg,"Building PDU error",strlen("Building PDU error"));
                len = strlen("Building PDU error")+1;
                break;
            default:
                strncpy(tmperrmsg,"Unkown error",strlen("Unkown error"));
                len = strlen("Unkown error")+1;
                break;
        }
        tmperrmsg[len] = '\0';
    }
    errmsg = (char *)malloc(sizeof(char)*len);
    strncpy(errmsg,tmperrmsg,len);
    if(snmp_errno >= 200){
        free(tmperrmsg);
    }
    return(errmsg);
}

/*
 * Set snmp_oct and the elements of snmp_oct to NULL
 */
int  initate_snmp_oct(snmp_oct_t *oct_t){
    if(oct_t == NULL){
        return(0);
    }
    oct_t->ber_oct = NULL; 
    return(1);
}

/*
 *  Building BER encode for numberical OID 
 *  Parameters:
 *     unsigned int nodeoid: Numberical OID(OID node , not full OID) which will be encoded
 *     u_char *buf: A u_char pointer will be used to storage OCTS of encoded OID
 *     int len: The number of OCTS 
 * Return: 
 *     OCTS and the len  
 */
int snmp_build_ber(unsigned int nodeoid,u_char *buf,int len){
   
    if(len < 0){
        len = 0;
    }
    if(nodeoid < 0x80){
        buf[len] = nodeoid;
    }
    else if(nodeoid < 0x4000){
        buf[len++] = ((nodeoid >> 7) | 0x80);
        buf[len] = (nodeoid & 0x07f);
    }
    else if (nodeoid < 0x200000) {
        buf[len++] = ((nodeoid >> 14) | 0x80);
        buf[len++] = ((nodeoid >> 7 & 0x7f) | 0x80);
        buf[len] = (nodeoid & 0x07f);
    }
    else if (nodeoid < 0x10000000 ) {
        buf[len++] = ((nodeoid >> 21) | 0x80);
        buf[len++] = ((nodeoid >> 14 & 0x7f) | 0x80);
        buf[len++] = ((nodeoid >> 7 & 0x7f) | 0x80);
        buf[len] = (nodeoid & 0x07f);
    }
    else{
        buf[len++] = ((nodeoid >> 28) | 0x80);
        buf[len++] = ((nodeoid >> 21 & 0x7f) | 0x80);
        buf[len++] = ((nodeoid >> 14 & 0x7f) | 0x80);
        buf[len++] = ((nodeoid >> 7 & 0x7f) | 0x80);
        buf[len] = (nodeoid & 0x07f);
    }
    return(++len);
}

int snmp_build_objoid(snmp_session_t *snmp_session ){
    u_char *buf,*subobjoid,*tmpobjoid;
    int i,objlen,j,k;
    unsigned int firstobj,secobj,nodeoid;
    
    buf = subobjoid = tmpobjoid = NULL; 
    if(strlen((const char *)snmp_session->objoid_str)<1){
        return(0);
    }
    if(!(buf = (u_char *)malloc(sizeof(u_char)*MAX_BUF_LENGTH))){
        return(0);
    }
    buf = memset(buf,'\0',MAX_BUF_LENGTH);
    if(!(tmpobjoid = (u_char *)malloc(sizeof(u_char)*(strlen((const char *)snmp_session->objoid_str) + 1)))){
        goto free_buf;
    }
    tmpobjoid = memset(tmpobjoid,'\0',(strlen((const char *)snmp_session->objoid_str) + 1));
    strncpy((char *)tmpobjoid,(const char *)snmp_session->objoid_str,strlen((const char *)snmp_session->objoid_str));
    subobjoid = tmpobjoid;
    k = objlen = 0;
    for(;(tmpobjoid=(u_char *)strstr((const char *)tmpobjoid,"."));)
    {
        i = tmpobjoid - subobjoid ;
        tmpobjoid++;
        subobjoid[i] = '\0';
        if(k == 0){
            firstobj = atoi((const char *)subobjoid);
        }
        else if(k == 1){
            secobj = atoi((const char *)subobjoid);
            nodeoid = 40 * firstobj + secobj; 
        }
        else{
            nodeoid = atoi((const char *)subobjoid);
        }
        if( k !=0 ){
            j = 0;
            j = snmp_build_ber(nodeoid,buf,objlen);
            objlen = j;
        }
        subobjoid = tmpobjoid;
        k++;
    }
    if(subobjoid != tmpobjoid){
        if(k == 1){
            secobj = atoi((const char *)subobjoid);
            nodeoid = 40 * firstobj + secobj; 
        }
        else{
            nodeoid = atoi((const char *)subobjoid);
        }
        j = snmp_build_ber(nodeoid,buf,objlen);
        objlen = j;
    }
   
    if(!(snmp_session->objoid = (snmp_oct_t *)malloc(sizeof(snmp_oct_t)))){
        goto free_tmpobjoid;
    }
    if(!(snmp_session->objoid->ber_oct = (u_char *)malloc(sizeof(u_char)*objlen))){
        free(snmp_session->objoid);
        snmp_session->objoid =  NULL;
        goto free_tmpobjoid;
    }
    for(i=0;i<objlen;i++){
        snmp_session->objoid->ber_oct[i] = buf[i];
    }
    snmp_session->objoid->length = objlen;
    free(tmpobjoid);
    free(buf);
    return(objlen);
    

free_tmpobjoid:
    free(tmpobjoid);
free_buf:
    free(buf);
 return(0);
}

int snmp_build_reqid(snmp_session_t *snmp_session){
    time_t *t;
    u_char *tmp_octstr;
    tmp_octstr = NULL; 
    t =  NULL; 
    int i,j,k;
    if(!(t = (time_t *)malloc(sizeof(time_t)))){
        return(0);
    }
    if(!(tmp_octstr = (u_char *)malloc(sizeof(u_char)*10))){  //Oct size should not biger 10
        goto free_t;
    }
    time(t);
    i = (int)*t;
    k = 0;
    for(;i>0;){
	j = i & 0xFF;
        tmp_octstr[k] = j;
        k++;
	i >>=8;
    }
    if(!(snmp_session->reqid = (snmp_oct_t *)malloc(sizeof(snmp_oct_t)))){
        goto free_tmp_octstr;
    }
    if(!(snmp_session->reqid->ber_oct = (u_char *)malloc(sizeof(u_char) * k))){
        free(snmp_session->reqid);
        snmp_session->reqid = NULL; 
        goto free_tmp_octstr;
    }
    for(i=0;i<k;i++){
        snmp_session->reqid->ber_oct[i] = tmp_octstr[i];
    }
    snmp_session->reqid->length = k;
    
    free(tmp_octstr);
    free(t);
    return(k);

free_tmp_octstr:
   free(tmp_octstr);    
free_t:
    free(t);
return(0);
}

int snmp_build_getRequestPDU(snmp_oct_t *snmp_pdu, snmp_session_t *snmp_session){
 
    u_char *buf;
    u_int i,j;
    buf = NULL;    
 
    if(snmp_pdu == NULL || snmp_session == NULL){
        return(0);
    }
    if( snmp_session->objoid_str == NULL || strlen((const char *)snmp_session->objoid_str)<2){   //OID must be biger 2 bytes
        return(0);
    }
    if(!(buf = (u_char *)malloc(sizeof(u_char)*MAX_BUF_LENGTH))){
        return(0);
    }
    if(!snmp_build_objoid(snmp_session)){ 
        goto free_buf;
    }
    if(!snmp_build_reqid(snmp_session)){
        goto free_buf;
    }
    i = 0;
    switch(snmp_session->version){
        case SNMP_VERSION_2C:
            snmp_session->errstat = DATA_ZERO;
            snmp_session->errindex = DATA_ZERO;
            buf[i++] = DATA_TYPE_SEQ;
            buf[i++] = 23 + snmp_session->community_length + snmp_session->reqid->length + snmp_session->objoid->length;
            buf[i++] = DATA_TYPE_INT;
            buf[i++] = 0x01;
            buf[i++] = snmp_session->version;
            buf[i++] = DATA_TYPE_OCTSTR;
            buf[i++] = snmp_session->community_length;
            for(j = 0; j<snmp_session->community_length; j++){
                buf[i++] = snmp_session->community[j];
            }
            buf[i++] = SNMP_GET_REQUEST;
            buf[i++] = 16 + snmp_session->reqid->length + snmp_session->objoid->length;
            buf[i++] = DATA_TYPE_INT;
            buf[i++] = snmp_session->reqid->length;
            for(j = 0;j<snmp_session->reqid->length; j++){
                buf[i++] = snmp_session->reqid->ber_oct[j];
            }
            buf[i++] = DATA_TYPE_INT;
            buf[i++] = 0x01;
            buf[i++] = snmp_session->errstat;
            buf[i++] = DATA_TYPE_INT;
            buf[i++] = 0x01;
            buf[i++] = snmp_session->errindex;
            buf[i++] = DATA_TYPE_SEQ;
            //buf[i++] = 6 + octstr->length;    //6
            buf[i++] = 6 + snmp_session->objoid->length;
            buf[i++] = DATA_TYPE_SEQ;
           // buf[i++] = 4 + octstr->length;   //2
            buf[i++] = 4 + snmp_session->objoid->length;
            buf[i++] = DATA_TYPE_OBJID;
            buf[i++] = snmp_session->objoid->length;
            for(j = 0; j< snmp_session->objoid->length; j++){
                buf[i++] = snmp_session->objoid->ber_oct[j];
            }
            buf[i++] = 0x05;
            buf[i++] = 0x00;
            buf[i] = '\0';
            break;
        default:
            goto free_buf;
            break;  
    }
    if(!(snmp_pdu->ber_oct = (u_char *)malloc(sizeof(u_char)*i))){
        goto free_buf;
    }
    for(j = 0; j<i;j++){
       snmp_pdu->ber_oct[j] = buf[j]; 
    }
    snmp_pdu->length = i;
   free(buf);
   return(i);

free_buf:
    free(buf);
return(0);
}

int snmp_parase_response(u_char *recv_buf,receive_msg_t *receive_msg){
    unsigned long i,j,k,total_octs_len, octs_len;
    int snmp_errno;   
    if(receive_msg ==  NULL){
        return(0);
    }
    j = i = 0;
    snmp_errno = errno = 0;
    i++;                                    //Get Total length 
    total_octs_len = recv_buf[i];
    octs_len = 0;
    if(recv_buf[i]> 0x80){
        octs_len = recv_buf[i] & 0x7F;
        total_octs_len = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                total_octs_len <<= 8;
            }
            total_octs_len = total_octs_len | recv_buf[i++];
        }
        i--;
    }
    total_octs_len += i;
   //Skip version and Get community length 
    i += 5;
   // total_octs_len += -5;
    octs_len = 0;
    k = recv_buf[i];
    if(k > 0x80){                //If community length is bigger than 127 ?
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--;
    }
    i += k;
    if(recv_buf[++i] != SNMP_GET_RESPONSE){   // A error occurred for parased error or data error
        snmp_errno = SNMP_ERR_CODE_UNAVAIABLED_MSG;
        goto end;
    }
    
    //Get data length again and check it
    i++;
    k = recv_buf[i];      //
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--;
    }
    if( (k+i) != total_octs_len){
        snmp_errno = SNMP_ERR_PARASE_ERR;
        goto end;
    }
    i += 2;
    k = recv_buf[i];    // reqid length
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--;
    }
    if(!(receive_msg->reqid = (snmp_oct_t *)malloc(sizeof(snmp_oct_t)))){
        snmp_errno = SNMP_ERR_CODE_ALLOC;
        goto end;
    }
    if(!(receive_msg->reqid->ber_oct = (u_char *)malloc(sizeof(u_char)*k))){
        snmp_errno = SNMP_ERR_CODE_ALLOC;
        goto receive_msg_reqid;
    }
    receive_msg->reqid->length = k;
    i++;
    for(j=0;j<k;j++){    //Get reqid content
        receive_msg->reqid->ber_oct[j] = recv_buf[i++];
    }
    i += 2;
    receive_msg->errstat = recv_buf[i++];
    i += 2; 
    receive_msg->errindex = recv_buf[i++];
    if(receive_msg->errstat != 0x00 || receive_msg->errindex != 0x00){
        snmp_errno = SNMP_ERR_CODE_STATUS;
        goto receive_msg_reqid_ber_oct;
    }
    i++;
    k = recv_buf[i];    // reqid length
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--;
    }
    if( (k+i) != total_octs_len){
        snmp_errno = SNMP_ERR_PARASE_ERR;
        goto receive_msg_reqid_ber_oct;
    }
    i += 2;
    k = recv_buf[i];    
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--;
    }
    i += 2;
    k = recv_buf[i];    
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        k = 0;
        i++;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--; 
    }
    i++;
    if(!(receive_msg->objoid = (snmp_oct_t *)malloc(sizeof(snmp_oct_t)))){
        snmp_errno = SNMP_ERR_CODE_ALLOC;
        goto receive_msg_reqid_ber_oct;
    }
    if(!(receive_msg->objoid->ber_oct = (u_char *)malloc(sizeof(u_char)*k))){
        snmp_errno = SNMP_ERR_CODE_ALLOC;
        goto receive_msg_objoid;
    }
    for(j=0;j<k;j++){
        receive_msg->objoid->ber_oct[j] = recv_buf[i++];
    }
    receive_msg->objoid->length = k; 
    receive_msg->msg_type = recv_buf[i++];
    k = recv_buf[i];    // reqid message length
    octs_len = 0;
    if(k>0x80){
        octs_len = k & 0x7F;
        i++;
        k = 0;
        for(j=0;j<octs_len;j++){
            if(j != 0){
                k <<= 8;
            }
            k = k | recv_buf[i++];
        }
        i--;
    }
    if( (k+i) != total_octs_len){
        snmp_errno = SNMP_ERR_PARASE_ERR;
        goto receive_msg_objoid_ber_oct;
    }
    if(!(receive_msg->msg = (u_char *)malloc(sizeof(u_char) * k+1))){
        snmp_errno = SNMP_ERR_CODE_ALLOC;
        goto receive_msg_objoid_ber_oct;
    }
    receive_msg->msg_length = k;
    i++;
    for(j=0;j<k;j++){
        receive_msg->msg[j] = recv_buf[i++];
    }
    receive_msg->msg[++j] = '\0';
    return(0);

receive_msg_objoid_ber_oct:
    free(receive_msg->objoid->ber_oct);
    receive_msg->objoid->ber_oct = NULL;
receive_msg_objoid:
    free(receive_msg->objoid);
    receive_msg->objoid = NULL; 
receive_msg_reqid_ber_oct:
    free(receive_msg->reqid->ber_oct);
    receive_msg->reqid->ber_oct =  NULL; 
receive_msg_reqid:
    free(receive_msg->reqid);
    receive_msg->reqid = NULL; 
end:
    return(snmp_errno);
}

int snmp_get_response_msg(receive_msg_t *receive_msg,snmp_msg_t *msg){
    int i ; 
    long int value; 
    if(receive_msg == NULL || msg == NULL ){
        return(SNMP_ERR_CODE_UNAVAIABLED_MSG);
    }
    if(receive_msg->errindex != 0x00 || receive_msg->errstat != 0x00){
        return(SNMP_ERR_CODE_UNAVAIABLED_MSG);
    }
    //if(receive_msg->reqid->length != snmp_session->reqid->length || strncmp((const char *)receive_msg->reqid->ber_oct,(const char *)snmp_session->reqid->ber_oct,receive_msg->reqid->length) != 0){
    //    return(SNMP_ERR_UNREQUEST_MSG);
    //}
    switch(receive_msg->msg_type){
        case DATA_TYPE_BOOL:
            msg->type = 0;      //bool type
            if(receive_msg->msg[0] == 0x00){
                msg->value = 0;
                msg->length = 1; 
            }
            else{
                msg->value = 1;
                msg->length = 1; 
            }
            break;
        case DATA_TYPE_INT:   //int type
        case DATA_TYPE_COUNTER:
        case DATA_TYPE_UNSIGNED:
        case DATA_TYPE_COUNTER64:
        case DATA_TYPE_TIMETICKS:
            msg->type = 1;
            value  =0 ;
            for(i=0;i<receive_msg->msg_length;i++){
                if(i != 0){
                    value <<= 8;
                }
                value = value | receive_msg->msg[i];
            }
            msg->length = 1; 
            msg->value = value; 
            break; 
        case DATA_TYPE_OCTSTR:
            msg->type = 2; 
            if(!(msg->valuemsg = (u_char*)malloc((sizeof(u_char)*receive_msg->msg_length+1)))){
                return(SNMP_ERR_CODE_ALLOC);
                break; 
            }
            for(i = 0; i<receive_msg->msg_length;i++){
                msg->valuemsg[i] =  receive_msg->msg[i];
            }
            msg->valuemsg[i] = '\0';
            msg->length = receive_msg->msg_length;
            break;
        default:
            return(SNMP_ERR_UNKNOW_MSG);
            break;
    }
    return(0);
}

int snmp_get_msg(snmp_para_t *snmp_para,snmp_msg_t *msg){
    snmp_session_t *snmp_session;
    struct sockaddr_in server_addr;
    int snmp_err_code;
    u_char *recv_buf;
    receive_msg_t *receive_msg;
    snmp_oct_t *snmp_pdu;
    
    if(snmp_para == NULL || msg == NULL){
        snmp_err_code = SNMP_ERR_PARASE_ERR;
        goto end;
    }
    if(!(snmp_session = (snmp_session_t *)malloc(sizeof(snmp_session_t)))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto end;
    }
    initate_snmp_session(snmp_session);
    if(!(snmp_session->objoid_str = (u_char *)malloc(sizeof(u_char)*strlen((const char *)snmp_para->oid)+1))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto free_snmp_session; 
    }
    memset(snmp_session->objoid_str,'\0',(strlen((const char *)snmp_para->oid)+1));
    strncpy((char *)snmp_session->objoid_str,(const char *)snmp_para->oid,strlen((const char *)snmp_para->oid));
    snmp_session->version = snmp_para->snmp_version;
    if(!(snmp_session->community = (u_char *)malloc(sizeof(u_char) * strlen((const char *)snmp_para->community)))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto free_objoid_str;
    }
    strncpy((char *)snmp_session->community,(const char *)snmp_para->community,strlen((const char *)snmp_para->community));
    snmp_session->community_length = strlen((const char *)snmp_para->community);
    if(!(snmp_session->remote_ip = (char *)malloc(sizeof(char)*strlen((const char *)snmp_para->remote_add)+1))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto free_community;
    }
    strncpy(snmp_session->remote_ip,(const char *)snmp_para->remote_add,strlen((const char *)snmp_para->remote_add));
    snmp_session->remote_port = snmp_para->port;
    if(!(snmp_pdu = (snmp_oct_t *)malloc(sizeof(snmp_oct_t)))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto free_remote_ip;
    }
    initate_snmp_oct(snmp_pdu);
    if(!snmp_build_getRequestPDU(snmp_pdu,snmp_session)){
        snmp_err_code = SNMP_ERR_BUILD_PDU;
        goto free_snmp_pdu;
    }
    bzero(&server_addr,sizeof(server_addr));  
    server_addr.sin_family=AF_INET;  
    server_addr.sin_addr.s_addr=inet_addr(snmp_session->remote_ip);//这里不一�?  
    server_addr.sin_port=htons(snmp_session->remote_port);  
    errno = 0;
    snmp_session->socket_fd = socket(AF_INET,SOCK_DGRAM,0);
    if(snmp_session->socket_fd == -1){
        snmp_err_code =  errno;
        goto free_snmp_pdu;
    }
    errno = 0;
    if(sendto(snmp_session->socket_fd, snmp_pdu->ber_oct ,( sizeof(u_char) * snmp_pdu->length),0,(struct sockaddr *)&server_addr,sizeof(server_addr)) == -1){
        snmp_err_code =  errno;
	goto close_socket_fd;
    }
    if(!(recv_buf = (u_char *)malloc(sizeof(u_char)*MAX_BUF_LENGTH))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto close_socket_fd;
    }
    errno = 0; 
    if(!(recv(snmp_session->socket_fd,recv_buf,MAX_BUF_LENGTH,MSG_WAITALL))){
        snmp_err_code = errno;
        goto free_recv_buf;
    }
    if(!(receive_msg = (receive_msg_t *)malloc(sizeof(receive_msg_t)))){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto free_recv_buf;
    }
    if(!initate_snmp_receive_msg(receive_msg)){
        snmp_err_code = SNMP_ERR_CODE_ALLOC;
        goto free_receive_msg;
    }
    if((snmp_err_code=snmp_parase_response(recv_buf,receive_msg)) != 0){
        goto free_receive_msg; 
    }
    if((snmp_err_code=snmp_get_response_msg(receive_msg,msg)) != 0){
        goto free_receive_msg;
    }
    snmp_err_code = 0;
    goto free_receive_msg;

free_receive_msg:
   free(receive_msg);         
free_recv_buf:
    free(recv_buf);
close_socket_fd:
    close(snmp_session->socket_fd);
free_snmp_pdu:
    free(snmp_pdu);
    snmp_pdu = NULL; 
free_remote_ip:
    free(snmp_session->remote_ip);
    snmp_session->remote_ip = NULL;
free_community:
    free(snmp_session->community);
    snmp_session->community = NULL; 
free_objoid_str:
    free(snmp_session->objoid_str);
    snmp_session->objoid_str = NULL;
free_snmp_session:
    free(snmp_session);
    snmp_session = NULL;
end:
    return(snmp_err_code);        
}

int sample(char *remote_add, char *community,char *oid ){
    
    snmp_msg_t *msg;
    snmp_para_t *snmp_para;
    int snmp_errno;
    
    if(!(msg = (snmp_msg_t *)malloc(sizeof(snmp_msg_t)))){
        printf("Alloc memory error!\n");
        return(1);
    }
    if(!(snmp_para = (snmp_para_t *)malloc(sizeof(snmp_para_t)))){
        free(msg);
        printf("Alloc memory error!\n");
        return(1);
    }
    snmp_para->remote_add = (u_char *)malloc(sizeof(u_char)*strlen(remote_add));
    strncpy((char *)snmp_para->remote_add,remote_add,strlen((const char *)remote_add));
    snmp_para->port = 161;
    snmp_para->snmp_version = SNMP_VERSION_2C;
    snmp_para->community = (u_char *)malloc(sizeof(u_char)*strlen(community));
    strncpy((char *)snmp_para->community,community,strlen((const char *)community));
    snmp_para->oid = (u_char *)malloc(sizeof(u_char)*strlen(oid));
    strncpy((char *)snmp_para->oid,oid,strlen((const char *)oid));
    if((snmp_errno = snmp_get_msg(snmp_para,msg)) != 0){
        printf("ERROR:%s\n",snmp_strerror(snmp_errno));
        return(2);
    }
    if(msg->type == 2){
        printf("Received:%s\n",msg->valuemsg);
    }
    else{
        printf("Received:%d\n",(int)msg->value);
    }
    return(0);
}
