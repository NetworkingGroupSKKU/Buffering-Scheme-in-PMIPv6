#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/types.h>

#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/mutex.h>
#include <net/sock.h>

#include "ro_trigger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Networking Lab SKKU");
MODULE_DESCRIPTION("Router Optimization for PMIPv6");

#define RCV_SKB_FAIL(err) do { netlink_ack(skb, nlh, (err)); return; } while (0)
#define DEBUG 1

static struct nf_hook_ops nfho;
static unsigned int peer_pid = 0;
static struct sock *nl_sk = NULL;

static LIST_HEAD(policy_list);
static LIST_HEAD(ro_list);

/*--------------------------------------------------*/
/* MNs information RO management					*/
/*--------------------------------------------------*/
void __policy_add_entry(lma_policy_entry_t *entry)
{
   list_add_tail(&entry->list, &policy_list);
}

void __policy_clean_list (void)
{
	lma_policy_entry_t *entry, *next;
	list_for_each_entry_safe(entry, next, &policy_list, list) {
		list_del(&entry->list);
	}
}

void __policy_dump (void)
{
	lma_policy_entry_t *i;
	int total = 0;
	list_for_each_entry(i, &policy_list, list)
		printk("[POLICY-DUMP]: item %d, lma_adr %s, mn_prefix %s, self : %d \n", ++total, i->lma_addr, i->mn_prefix, i->lmaself);
}
/*--------------------------------------------------*/
/* RO MNs information management					*/
/*--------------------------------------------------*/
void __ro_add_entry(ro_mn_entry_t *entry)
{
   list_add_tail(&entry->list, &ro_list);
}

void __ro_delete_entry (char *mn_addr)
{
	ro_mn_entry_t *entry, *next;
	list_for_each_entry_safe(entry, next, &ro_list, list) {
		if ((strcmp(entry->mn1_addr, mn_addr) == 0) || (strcmp(entry->mn2_addr, mn_addr) == 0))
			list_del(&entry->list);
	}
}

void __ro_clean_list (void)
{
	ro_mn_entry_t *entry, *next;
	list_for_each_entry_safe(entry, next, &ro_list, list) {
		list_del(&entry->list);
	}
}

void __ro_dump (void)
{
	ro_mn_entry_t *i;
	int total = 0;
	list_for_each_entry(i, &ro_list, list)
		printk("[RO-DUMP]: Queue: address %d: %s %s\n", ++total, i->mn1_addr, i->mn2_addr);
}

/*------------------------------------------------------
  netlink function
 -------------------------------------------------------*/
void ro_data_ready (struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    int pid, flags, nlmsglen, skblen, type;
    char mn_addr[64];
    lma_policy_entry_t *entry = NULL;

    if(skb == NULL) {
        printk("skb is NULL \n");
        return ;
    }

	skblen = skb->len;
	if (skblen < sizeof(*nlh))
		return;

	nlh = nlmsg_hdr(skb);
	nlmsglen = nlh->nlmsg_len;
	if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
		return;

	pid = nlh->nlmsg_pid;
	flags = nlh->nlmsg_flags;

	if(pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
		RCV_SKB_FAIL(-EINVAL);

	if (flags & MSG_TRUNC)
		RCV_SKB_FAIL(-ECOMM);

	if (peer_pid) {
		if (peer_pid != pid) {
				RCV_SKB_FAIL(-EBUSY);
		}
	}
	else
		peer_pid = pid;

	type = nlh->nlmsg_type;

	if (type == 1) {	// remove RO entry
		strcpy(mn_addr, (char*)NLMSG_DATA(nlh));
		__ro_delete_entry(mn_addr);
#if DEBUG > 0
		printk(KERN_INFO "[RO]: received netlink mn_addr: %s\n", mn_addr);
#endif
	}
	else if (type == 2) {	// add policy
		entry = kmalloc(sizeof (lma_policy_entry_t), GFP_KERNEL);
		strcpy(entry->mn_prefix, (char *)NLMSG_DATA(nlh));
		strcpy(entry->lma_addr, (char *)(NLMSG_DATA(nlh)+64));
		entry->lmaself = *(unsigned int *)(NLMSG_DATA(nlh)+128);
		__policy_add_entry(entry);
#if DEBUG > 0
	__policy_dump();
#endif
	}
}

void ro_receive (void)
{
    nl_sk = netlink_kernel_create(&init_net, NETLINK_RO, 0, ro_data_ready, NULL, THIS_MODULE);
}

struct sk_buff* ro_build_packet_message(ro_msg_t *data)
{
	sk_buff_data_t old_tail;
	size_t size = 0;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	ro_msg_t *pmsg;

	size = NLMSG_SPACE(sizeof(ro_msg_t));
	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb)
		goto nlmsg_failure;

	old_tail = skb->tail;
	nlh = NLMSG_PUT(skb, 0, 0, 0, size - sizeof(*nlh));
	pmsg = NLMSG_DATA(nlh);
	memset(pmsg, 0, sizeof(*pmsg));
	pmsg->btrigger = 1;
	strcpy(pmsg->str_srcaddr, data->str_srcaddr);
	strcpy(pmsg->str_dstaddr, data->str_dstaddr);
	strcpy(pmsg->lma_srcaddr, data->lma_srcaddr);
	strcpy(pmsg->lma_dstaddr, data->lma_dstaddr);

	nlh->nlmsg_len = skb->tail - old_tail;
	return skb;

nlmsg_failure:
	printk(KERN_ERR "ro_netlink: error creating packet message\n");
	return NULL;
}

int ro_send_trigger (struct in6_addr* src_addr, struct in6_addr* dst_addr, ro_msg_t *data)
{
	int status = -EINVAL;
	struct sk_buff *nskb;

#if DEBUG > 0
	printk("[RO]: Send trigger to user space \n");
#endif

	nskb = ro_build_packet_message(data);
	if (nskb == NULL)
		return status;

	if (!peer_pid)
		goto err_out_free_nskb;

	/* netlink_unicast will either free the nskb or attach it to a socket */
	status = netlink_unicast(nl_sk, nskb, peer_pid, MSG_DONTWAIT);
	if (status < 0)
		printk("[RO]: Send trigger failed \n");
	return status;

err_out_free_nskb:
	kfree_skb(nskb);
	return status;
}

/*---------------------------------------------------------------
 * ro_trigger function
 ----------------------------------------------------------------*/
int ro_check_trigger(struct in6_addr* src_addr, struct in6_addr* dst_addr, ro_msg_t *msg)
{
	ro_mn_entry_t *element;
	lma_policy_entry_t *policy_entry;
	char str_src[64];
	char str_dst[64];
	int match_src = 0;
	int match_dst = 0;

	sprintf(str_src, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(src_addr));
	sprintf(str_dst, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(dst_addr));

/*#if DEBUG > 0
	printk("[RO - Check]: src addr %s \n", str_src);
	printk("[RO - Check]: dst addr %s \n", str_dst);
#endif*/

	list_for_each_entry(element, &ro_list, list) {
		if (element != NULL) {
			if (((strcmp(element->mn1_addr, str_src) == 0) && (strcmp(element->mn2_addr, str_dst) == 0))
				|| 	((strcmp(element->mn1_addr, str_dst) == 0) && (strcmp(element->mn2_addr, str_src) == 0)))
#if DEBUG > 0
				printk("[RO] Already trigger %s - %s \n", str_src, str_dst);
#endif
				return 0;
		}
	}

	list_for_each_entry(policy_entry, &policy_list, list) {
		if (policy_entry != NULL) {
			if ((strstr(str_src, policy_entry->mn_prefix) != NULL) && (policy_entry->lmaself)) {
				strcpy(msg->str_srcaddr, str_src);
				strcpy(msg->lma_srcaddr, policy_entry->lma_addr);
				match_src = 1;
			}
			if (strstr(str_dst, policy_entry->mn_prefix) != NULL) {
				strcpy(msg->str_dstaddr, str_dst);
				strcpy(msg->lma_dstaddr, policy_entry->lma_addr);
				match_dst = 1;
			}
			if (match_src && match_dst)
				break;
		}
	}

	if (match_src && match_dst) {
#if DEBUG > 0
		printk("[RO] trigger RO %s - %s\n", str_src, str_dst);
#endif
		msg->btrigger = 1;
		return 1;
	}
	return 0;
}

unsigned int hook_func(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	struct ipv6hdr *ip6_header;
	struct sk_buff *sock_buff;
	ro_msg_t ro_msg;
	ro_mn_entry_t *entry;

	sock_buff = skb;
	if(!sock_buff) {
	   printk(KERN_INFO "[RO]  skb is null \n");
	   return NF_ACCEPT;
	}

	ip6_header = (struct ipv6hdr *)skb_network_header(sock_buff);
	if (ip6_header == NULL) {
		printk(KERN_INFO "[RO]  ip6_header is null \n");
		return NF_ACCEPT;
	}

	memset(&ro_msg, 0, sizeof(ro_msg_t));
	if (ro_check_trigger(&ip6_header->saddr, &ip6_header->daddr, &ro_msg)) {
		entry = kmalloc(sizeof (ro_mn_entry_t), GFP_KERNEL);
		sprintf(entry->mn1_addr, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(&ip6_header->saddr));
		sprintf(entry->mn2_addr, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(&ip6_header->daddr));
		__ro_add_entry(entry);
		ro_send_trigger(&ip6_header->saddr, &ip6_header->daddr, &ro_msg);
	}
	printk("[RO] Exit hook func \n");
	return NF_ACCEPT;
}

int __init init_main(void)
{
	printk(KERN_INFO "Initializing Netlink Socket");
	ro_receive();

	printk(KERN_INFO "Initializing hook function");
	nfho.hook     = hook_func;
	nfho.hooknum  = 4 ;   //NF_IP_POST_ROUTING
	nfho.pf       = PF_INET6;
	nfho.priority = NF_IP_PRI_SELINUX_LAST;
	nf_register_hook(&nfho);
	printk(KERN_INFO "Successfully Initialized module");
	return 0;
}

void __exit cleanup_main(void)
{
	nf_unregister_hook(&nfho);
	sock_release(nl_sk->sk_socket);
	printk(KERN_INFO "[RO] Successfully unloaded module \n");
}

module_init(init_main);
module_exit(cleanup_main);

