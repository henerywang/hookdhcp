#ifndef _ZH_DHCP_TRAP_H
#define _ZH_DHCP_TRAP_H


#include <linux/in.h>

/* verify this strutcure with RFC sname and file may be wrong*/
/* Reference: taken from dhcp user space tool <include/dhcp.h>*/
//#define DBG_DHCP_TRAP
#if defined(DBG_DHCP_TRAP)
	#define DBGP_DHCP_TRAP(format, arg...) 	  \
		do {printk(format , ## arg);}while(0)
#else
	#define DBGP_DHCP_TRAP(format, arg...)
#endif
extern int dhcp_filter_enable;
extern struct list_head dhcp_db_list;

#define DHCP_UDP_OVERHEAD	(20 + /* IP header */			\
			        8)   /* UDP header */
#define DHCP_SNAME_LEN		64
#define DHCP_FILE_LEN		128
#define DHCP_FIXED_NON_UDP	236
#define DHCP_FIXED_LEN		(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
						/* Everything but options. */
#define BOOTP_MIN_LEN		300

#define DHCP_MTU_MAX		1500
#define DHCP_MTU_MIN            576

#define DHCP_MAX_OPTION_LEN	(DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN (DHCP_MTU_MIN - DHCP_FIXED_LEN)

typedef struct dhcp_packet {
 u_int8_t  op;		/* 0: Message opcode/type */
	u_int8_t  htype;	/* 1: Hardware addr type (net/if_types.h) */
	u_int8_t  hlen;		/* 2: Hardware addr length */
	u_int8_t  hops;		/* 3: Number of relay agent hops from client */
	u_int32_t xid;		/* 4: Transaction ID */
	u_int16_t secs;		/* 8: Seconds since client started looking */
	u_int16_t flags;	/* 10: Flag bits */
	struct in_addr ciaddr;	/* 12: Client IP address (if already in use) */
	struct in_addr yiaddr;	/* 16: Client IP address */
	struct in_addr siaddr;	/* 18: IP address of next server to talk to */
	struct in_addr giaddr;	/* 20: DHCP relay agent IP address */
	unsigned char chaddr [16];	/* 24: Client hardware address */
	char sname [DHCP_SNAME_LEN];	/* 40: Server name */
	char file [DHCP_FILE_LEN];	/* 104: Boot filename */
	unsigned char magic_cookie[4];/*dhcp magic cookie*/
	unsigned char options [DHCP_MAX_OPTION_LEN];
				/* 212: Optional parameters
			  (actual length dependent on MTU). */
}dhcpheader_t;

#define IP_LEN 4
#define ZH_MAC_LEN 6
typedef struct host_info{
    u_int8_t ip[IP_LEN];
    u_int8_t host_name[DHCP_SNAME_LEN];
    u_int8_t vendor[DHCP_SNAME_LEN];
    unsigned char chaddr [ZH_MAC_LEN];

} host_info_t;

typedef struct{
    struct list_head list;
    host_info_t dhcp_info;
}dhcp_db_t;

/* BOOTP (rfc951) message types */
#define	BOOTREQUEST	1
#define BOOTREPLY	2

extern int br_dhcp_filter_enter(struct sk_buff *skb);
extern int dhcp_filter_enable;

extern int br_dhcp_filter_init(void);
extern void br_dhcp_filter_exit(void);
extern void debug_host_info_t(host_info_t *info);
extern int is_request_header(dhcpheader_t *dhcp_header);
extern void get_host_info(dhcpheader_t *dhcp_header,host_info_t * host_info);
extern void dhcp_info_db_add(host_info_t *info);
extern void dhcp_info_db_debug(void);

#endif	/* _RTL_DNS_TRAP_H */


