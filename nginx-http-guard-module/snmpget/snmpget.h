#ifndef  _SNMPGET_H
#define _SNMPGET_H 1
#endif
#ifndef _STDIO_H
#include <stdio.h>
#endif
#ifndef _STDLIB_H
#include <stdlib.h>
#endif
#ifndef _UNISTD_H
#include <unistd.h>
#endif
#ifndef _STRING_H
#include <string.h>
#endif
#ifndef _ERRNO_H
#include <errno.h>
#endif

#ifndef _SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifndef _NETINET_IN_H
#include <netinet/in.h>
#endif
#ifndef _ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifndef _TIME_H
#include <time.h>
#endif
#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif
#ifndef _SYS_PRCTL_H
#include <sys/prctl.h>
#endif


#define DEFAULT_COMMUNITY "public"
#define MAX_BUF_LENGTH 512
#define DATA_TYPE_BOOL  0x01
#define DATA_TYPE_INT   0x02
#define DATA_TYPE_OCTSTR  0x04
#define DATA_TYPE_NULL  0x05
#define DATA_TYPE_OBJID  0x06
#define DATA_TYPE_ENUM  0x0A
#define DATA_TYPE_SEQ  0x30
#define DATA_TYPE_IPADDRESS 0x40
#define DATA_TYPE_COUNTER 0x41
#define DATA_TYPE_UNSIGNED 0x42
#define DATA_TYPE_TIMETICKS 0x43
#define DATA_TYPE_COUNTER64 0x46
#define DATA_ZERO  0x00
#define SNMP_VERSION_1 0x00
#define SNMP_VERSION_2C 0x01
#define SNMP_VERSION_2 0x02
#define SNMP_VERSION_3 0x03
#define SNMP_GET_REQUEST 0xA0
#define SNMP_GET_NEXT_REQUEST 0xA1
#define SNMP_GET_RESPONSE 0xA2
#define SNMP_SET_REQUEST 0xA3
#define SNMP_TRAP 0xA4

//It is the system's errno that the number of errno before 133 
#define SNMP_ERR_CODE_ALLOC  201
#define SNMP_ERR_CODE_UNAVAIABLED_MSG  202
#define SNMP_ERR_CODE_STATUS 203
#define SNMP_ERR_PARASE_ERR  204
#define SNMP_ERR_UNREQUEST_MSG 205 
#define SNMP_ERR_UNKNOW_MSG  206
#define SNMP_ERR_BUILD_PDU  207


typedef struct {
    u_char *ber_oct;
    unsigned int length;
} snmp_oct_t;

typedef struct  {
       long     version;
       u_char   *community;
       long     community_length;
       snmp_oct_t *reqid;
       long     errstat;
       long     errindex;
       int      socket_fd;
       char     *remote_ip;
       int      remote_port;
       snmp_oct_t *objoid;
       u_char  *objoid_str;
       
} snmp_session_t;

typedef struct {
    long    msg_type;
    u_char   *msg;
    long     msg_length;
    snmp_oct_t *reqid;
    long     errstat;
    long     errindex;
    snmp_oct_t *objoid;
    
} receive_msg_t;

typedef struct {
    int     type;
    long int  length;
    u_char     *valuemsg;
    long int    value; 
} snmp_msg_t;

typedef struct {
   u_char *remote_add;
   int  port;
   int socket_type;
   int  snmp_version; 
   u_char *community; 
   u_char *oid; 
} snmp_para_t;

int snmp_get_msg(snmp_para_t *snmp_para,snmp_msg_t *msg);
char *snmp_strerror(int snmp_errno); 
int  initate_snmp_session(snmp_session_t *snmp_session);
int  initate_snmp_oct(snmp_oct_t *oct_t);
int snmp_build_getRequestPDU(snmp_oct_t *snmp_pdu, snmp_session_t *snmp_session);
int  initate_snmp_receive_msg(receive_msg_t *receive_msg);
int snmp_get_response_msg(receive_msg_t *receive_msg,snmp_msg_t *msg);
int snmp_parase_response(u_char *recv_buf,receive_msg_t *receive_msg);
char *snmp_strerror(int snmp_errno);