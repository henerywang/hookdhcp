#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <linux/ctype.h>
#include "zh_dhcptrap.h"



#define CONFIG_RTL_PROC_NEW
struct proc_dir_entry *proc_root = NULL;
struct list_head dhcp_db_list;
struct proc_dir_entry *dhcpstrap_proc_root = NULL;
static DEFINE_MUTEX(zh_dhcp_mutex);


#define DHCP_PROC_ROOT "dhcpstrap"
#define DHCP_PROC_ENABLE "dhcp_enable"

int dhcp_filter_enable = 1;

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define OPTION_FIELD		0
#define FILE_FIELD		1
#define SNAME_FIELD		2

/* miscellaneous defines */
#define MAC_BCAST_ADDR		(unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2

#define DHCP_PADDING		0x00
#define DHCP_OPTION_OVER	0x34
#define DHCP_END		0xFF
#define DHCP_HOST_NAME		0x0c
#define DHCP_REQUESTED_IP	0x32
#define DHCP_VENDOR	        0x3c


#if 1
int is_request_header(dhcpheader_t *dhcp_header)
{
	if(dhcp_header == NULL)
	{
		return 0;
	}
	DBGP_DHCP_TRAP("dhcp info = 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x",dhcp_header->options[0],dhcp_header->options[1],dhcp_header->options[2],dhcp_header->options[3],dhcp_header->options[4],dhcp_header->options[5]);
	if(dhcp_header->options[2] == 0x03)
		return 1;
    return 0;

}

static unsigned char *_get_option(dhcpheader_t *dhcpheader, int code)
{
	int i, length;
	unsigned char *optionptr=NULL;
	int over = 0, done = 0, curr = OPTION_FIELD;

	optionptr = (unsigned char *)dhcpheader->options;
	i = 0;
	length = 308;
	while (!done) {
		if (i >= length) {
			DBGP_DHCP_TRAP("bogus packet, option fields too long.");
			return NULL;
		}
		if (optionptr[i + OPT_CODE] == code) {
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				DBGP_DHCP_TRAP("bogus packet, option fields too long.");
				return NULL;
			}
			return optionptr + i + 2;
		}
		switch (optionptr[i + OPT_CODE]) {
		case DHCP_PADDING:
			i++;
			break;
		case DHCP_OPTION_OVER:
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				DBGP_DHCP_TRAP("bogus packet, option fields too long.");
				return NULL;
			}
			over = optionptr[i + 3];
			i += optionptr[OPT_LEN] + 2;
			break;
		case DHCP_END:
			if (curr == OPTION_FIELD && over & FILE_FIELD) {
				optionptr = (unsigned char *)dhcpheader->file;
				i = 0;
				length = 128;
				curr = FILE_FIELD;
			} else if (curr == FILE_FIELD && over & SNAME_FIELD) {
				optionptr = (unsigned char *)dhcpheader->sname;
				i = 0;
				length = 64;
				curr = SNAME_FIELD;
			} else done = 1;
			break;
		default:
			i += optionptr[OPT_LEN + i] + 2;
		}
	}
	return NULL;
}

#endif

#define UNKOWN_HOST "unkown"
void get_host_info(dhcpheader_t *dhcp_header,host_info_t * host_info)
{
  unsigned char * host_name = _get_option(dhcp_header,DHCP_HOST_NAME);
  unsigned char * ip = _get_option(dhcp_header,DHCP_REQUESTED_IP);
  unsigned char * vendor = _get_option(dhcp_header,DHCP_VENDOR);

  //DBGP_DHCP_TRAP("host_name=%s\n",host_name);
  if(host_name !=NULL)
    memcpy(host_info->host_name,host_name,(int)host_name[-1]);
  else
  	memcpy(host_info->host_name,UNKOWN_HOST,strlen(UNKOWN_HOST));

  if(vendor !=NULL)
    memcpy(host_info->vendor,vendor,(int)vendor[-1]);
  else
  	memcpy(host_info->vendor,UNKOWN_HOST,strlen(UNKOWN_HOST));

  if(ip !=NULL)
    memcpy(host_info->ip,ip,4);
  memcpy(host_info->chaddr,dhcp_header->chaddr,6);
  return;
}

void debug_host_info_t(host_info_t *info)
{
    printk("host_name=%s\n",info->host_name);
    printk("ip=%d.%d.%d.%d\n",info->ip[0],info->ip[1],info->ip[2],info->ip[3]);
    printk("vendor=%s\n",info->vendor);
    printk("mac=%x:%x:%x:%x:%x:%x\n",info->chaddr[0],info->chaddr[1],info->chaddr[2],info->chaddr[3],info->chaddr[4],info->chaddr[5]);
}

static int dhcptrap_en_read(struct seq_file *s, void *v)
{
    dhcp_db_t *db_tmp;
	seq_printf(s,"dhcp_hook_enable : %d\n",dhcp_filter_enable);
    seq_printf(s,"domain\t ip\t endor\t mac\n");
    mutex_lock(&zh_dhcp_mutex);
    list_for_each_entry(db_tmp, &dhcp_db_list, list)
    {
        seq_printf(s,"%s\t",db_tmp->dhcp_info.host_name);
        seq_printf(s,"%d.%d.%d.%d\t",db_tmp->dhcp_info.ip[0],db_tmp->dhcp_info.ip[1],db_tmp->dhcp_info.ip[2],db_tmp->dhcp_info.ip[3]);
        seq_printf(s,"%s\t",db_tmp->dhcp_info.vendor);
        seq_printf(s,"%x:%x:%x:%x:%x:%x\n",db_tmp->dhcp_info.chaddr[0],db_tmp->dhcp_info.chaddr[1],db_tmp->dhcp_info.chaddr[2],db_tmp->dhcp_info.chaddr[3],db_tmp->dhcp_info.chaddr[4],db_tmp->dhcp_info.chaddr[5]);
	}
    mutex_unlock(&zh_dhcp_mutex);

	return 0;
}
static int dhcpstrap_en_write(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
	char tmpbuf[80];

	if (count < 2)
		return -EFAULT;

	if (buffer && !copy_from_user(tmpbuf, buffer, count))  {
		tmpbuf[count] = '\0';
		if (tmpbuf[0] == '0')
			dhcp_filter_enable = 0;
		else if (tmpbuf[0] == '1')
			dhcp_filter_enable = 1;
		return count;
	}
	return -EFAULT;
}
#ifdef CONFIG_RTL_PROC_NEW
int dhcptrap_en_proc_open(struct inode *inode, struct file *file)
{
	return(single_open(file, dhcptrap_en_read,NULL));
}
int dhcpstrap_en_proc_write(struct file * file, const char __user * userbuf,
		     size_t count, loff_t * off)
{
	return dhcpstrap_en_write(file,userbuf,count,off);
}

struct file_operations dhcptrap_en_proc_fops= {
        .open           = dhcptrap_en_proc_open,
        .write		    = dhcpstrap_en_proc_write,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};
#endif
////////
////////

static void dhcptrap_create_proc(void)
{
#if 1
	dhcpstrap_proc_root = proc_mkdir(DHCP_PROC_ROOT,proc_root);
	if(dhcpstrap_proc_root){
		proc_create_data(DHCP_PROC_ENABLE,0,dhcpstrap_proc_root,&dhcptrap_en_proc_fops,NULL);
	}
	//if (!get_nl_eventd_sk())
	//	rtk_eventd_netlink_init();
#endif

}
static void dhcptrap_destroy_proc(void)
{
	if(dhcpstrap_proc_root){
		remove_proc_entry(DHCP_PROC_ENABLE, dhcpstrap_proc_root);
		remove_proc_entry(DHCP_PROC_ROOT, proc_root);
	}
}

void dhcp_info_db_add(host_info_t *info)
{
    dhcp_db_t *db_tmp;
    mutex_lock(&zh_dhcp_mutex);
    list_for_each_entry(db_tmp, &dhcp_db_list, list)
    {
		if(!memcmp(db_tmp->dhcp_info.chaddr,info->chaddr,ZH_MAC_LEN))
        {
            memcpy((char *)&db_tmp->dhcp_info,(char *)info,sizeof(host_info_t));
            mutex_unlock(&zh_dhcp_mutex);
            return;
        }
	}
    mutex_unlock(&zh_dhcp_mutex);
    db_tmp = kzalloc(sizeof(dhcp_db_t),GFP_ATOMIC);
    memset(db_tmp,0,sizeof(dhcp_db_t));
    memcpy((char *)&db_tmp->dhcp_info,(char *)info,sizeof(host_info_t));
    list_add(&db_tmp->list,&dhcp_db_list);
    return;
}

void dhcp_info_db_debug(void)
{
    dhcp_db_t *db_tmp;
    mutex_lock(&zh_dhcp_mutex);
    list_for_each_entry(db_tmp, &dhcp_db_list, list)
    {
        debug_host_info_t(&db_tmp->dhcp_info);
	}
    mutex_unlock(&zh_dhcp_mutex);
    return;
}

void dhcp_info_db_clean(void)
{
    dhcp_db_t *db_tmp,*p;
    mutex_lock(&zh_dhcp_mutex);
    list_for_each_entry_safe(db_tmp,p, &dhcp_db_list, list)
    {
        debug_host_info_t(&db_tmp->dhcp_info);
        list_del(&db_tmp->list);
        kfree(db_tmp);
	}
    mutex_unlock(&zh_dhcp_mutex);
    return;
}


void dhcp_info_db_init(void)
{
    INIT_LIST_HEAD(&dhcp_db_list);
}

int  br_dhcp_filter_init(void)
{
    printk("init proc\n");
	dhcptrap_create_proc();
    dhcp_info_db_init();

	return 0;
}

void  br_dhcp_filter_exit(void)
{

	dhcptrap_destroy_proc();
    dhcp_info_db_clean();

}


