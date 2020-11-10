#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/netfilter_bridge.h>
#include "zh_dhcptrap.h"

/**********************************
description:
***********************************/
unsigned int dhcp_hook(const struct nf_hook_ops *ops,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct iphdr *ip;
	struct udphdr *udp;
  struct ethhdr *eth = eth_hdr(skb);
	dhcpheader_t *dhcp_hdr = NULL;
  host_info_t tmp_info;

    if(!dhcp_filter_enable)
        return NF_ACCEPT;
	if (!skb)
        return NF_ACCEPT;

    if(!eth)
        return NF_ACCEPT;


	if(skb->protocol != htons(0x0800)) //get ip data
		return NF_ACCEPT;

	ip = ip_hdr(skb);
	if(ip->protocol != 17) //get udp data
		return NF_ACCEPT;

	udp = (struct udphdr *)(ip+1);
	if( (udp != NULL) && (ntohs(udp->dest) != 67) ) //DNS req
	{
		return NF_ACCEPT;
	}

  dhcp_hdr = (dhcpheader_t*)((void*)udp + sizeof(struct udphdr));
	if(is_request_header(dhcp_hdr) == 1)
	{
		memset(&tmp_info,0,sizeof(host_info_t));
		get_host_info(dhcp_hdr,&tmp_info);
        dhcp_info_db_add(&tmp_info);
        //dhcp_info_db_debug();
	}

	return NF_ACCEPT;
}

struct nf_hook_ops dhcp_ops = {
	.list =  {NULL,NULL},
	.hook = dhcp_hook,
	.pf = NFPROTO_BRIDGE,
	.hooknum = NF_BR_PRE_ROUTING,
	.priority = NF_BR_PRI_FIRST+1
};

static int __init zh_dhcp_init(void)
{
    nf_register_hook(&dhcp_ops);
    br_dhcp_filter_init();

	printk(" init ok\n");

	return 0;
}

static void __exit zh_dhcp_exit(void)
{
	nf_unregister_hook(&dhcp_ops);
    br_dhcp_filter_exit();
	printk("exit dhcp_hook\n");
}
MODULE_LICENSE("GPL");
module_init(zh_dhcp_init);
module_exit(zh_dhcp_exit);

/**********************************
description: dns respone data
***********************************/


/**********************************
description: forge dns respone data
***********************************/
