#define PMIP
#ifdef HAVE_CONFIG_H
#	include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "pmip_ro.h"
#include "debug.h"
#include "conf.h"
#include "util.h"
#include "rtnl.h"
#include "tunnelctl.h"
#include "pmip_msgs.h"
#include "pmip_hnp_cache.h"
#include "pmip_tunnel.h"

#define IN6_ARE_PREFIX_EQUAL(a,b) \
        ((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0])     \
         && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1]))

#define BUFSIZE	65536

struct ro_msg {
	char str_srcaddr[64];
	char lma_srcaddr[64];
	char str_dstaddr[64];
	char lma_dstaddr[64];
	int  btrigger;
};

/***************global variable*********************/
static struct ro_handle* ro_h;
static pthread_t ro_listener;

static LIST_HEAD(tnlinfo_list);
static unsigned int tnlinfo_total;

/****************************************************************************
 *
 * tunnel/route/rule information management at MAG
 *
 ****************************************************************************/
int _delete_tunnel_route_rule(tnlinfo_list_entry_t *item)
{
	int res = 0;

	dbg("===============> type: %d \n", item->type);
	res = route_del(item->tunnel, RT6_TABLE_PMIP_RO, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, &in6addr_any, 0, NULL);
	if (res < 0)
		dbg("ERROR Del route \n");
	if (item->type == 0 || item->type == 1) {
		res = rule_del(NULL, RT6_TABLE_PMIP_RO, IP6_RULE_PRIO_PMIP6_RO, RTN_UNICAST, &in6addr_any, 0, &item->mn_addr, 128, 0);
		if (res < 0)
			dbg("ERROR Del rule \n");

	}
	else if (item->type == 2) {
		res = rule_del(NULL, RT6_TABLE_PMIP_RO, IP6_RULE_PRIO_PMIP6_RO, RTN_UNICAST, &item->mn_addr, 128, &in6addr_any, 0, 0);
		if (res < 0)
			dbg("ERROR Del rule \n");
	}

	res = pmip_tunnel_del(item->tunnel);
	if (res < 0)
		dbg("ERROR Del tunnel \n");

	return 0;
}

void pmip_tunnel_add_entry(tnlinfo_list_entry_t *entry)
{
   list_add_tail(&entry->list, &tnlinfo_list);
   tnlinfo_total++;
}

int pmip_tunnel_del_entry(struct in6_addr* mn_addr, struct in6_addr* mag_addr)
{
	struct list_head *pos, *q;
	tnlinfo_list_entry_t *i;
	int res = 0;
	list_for_each_safe(pos, q, &tnlinfo_list) {
		i = list_entry(pos, tnlinfo_list_entry_t, list);
		if (IN6_ARE_ADDR_EQUAL(&i->mn_addr, mn_addr) && IN6_ARE_ADDR_EQUAL(&i->mag_addr, mag_addr)) {
			res = _delete_tunnel_route_rule(i);
			list_del(&i->list);
			SAFE_FREE(i);
			tnlinfo_total--;
			break;
		}
	}
    return res;
}

int pmip_tunnel_clean_list (void)
{
	struct list_head *pos, *q;
	tnlinfo_list_entry_t *i;
	int res = 0;
	list_for_each_safe(pos, q, &tnlinfo_list) {
		i = list_entry(pos, tnlinfo_list_entry_t, list);
		res = _delete_tunnel_route_rule(i);
		list_del(&i->list);
		SAFE_FREE(i);
	}
	tnlinfo_total = 0;
	return res;
}

int pmip_tunnel_exist_entry (struct in6_addr* mn_addr, struct in6_addr* mag_addr)
{
	struct list_head *pos, *q;
	tnlinfo_list_entry_t *i;

	list_for_each_safe(pos, q, &tnlinfo_list) {
		i = list_entry(pos, tnlinfo_list_entry_t, list);
		if (IN6_ARE_ADDR_EQUAL(&i->mn_addr, mn_addr) && IN6_ARE_ADDR_EQUAL(&i->mag_addr, mag_addr))
			return 1;
	}

	return 0;
}

int pmip_tunnel_get_info_fpmip(/*in*/struct in6_addr* mn_prefix, /*out*/struct in6_addr* mn_addr, struct in6_addr* mag_addr )
{
	struct list_head *pos, *q;
	tnlinfo_list_entry_t *i;

	list_for_each_safe(pos, q, &tnlinfo_list) {
		i = list_entry(pos, tnlinfo_list_entry_t, list);
		if (IN6_ARE_PREFIX_EQUAL(&i->mn_addr, mn_prefix)) {
			if (i->type == 2) {
				if (mn_addr != NULL)
					*mn_addr = i->mn_addr;
				if (mag_addr != NULL)
					*mag_addr = i->mag_addr;
				return 0;
			}
			break;
		}
	}

	return -1;
}

/****************************************************************************
 *
 * Netlink functions at LMA
 *
 ****************************************************************************/
/**
 * Private interface
 */
enum {
	RO_ERR_NONE = 0,
	RO_ERR_IMPL,
	RO_ERR_HANDLE,
	RO_ERR_SOCKET,
	RO_ERR_BIND,
	RO_ERR_BUFFER,
	RO_ERR_RECV,
	RO_ERR_NLEOF,
	RO_ERR_ADDRLEN,
	RO_ERR_STRUNC,
	RO_ERR_RTRUNC,
	RO_ERR_NLRECV,
	RO_ERR_SEND,
	RO_ERR_RECVBUF,
	RO_ERR_TIMEOUT
};
#define RO_MAXERR RO_ERR_TIMEOUT

struct ro_errmap_t {
	int errcode;
	char *message;
} ro_errmap[] = {
	{ RO_ERR_NONE, "Unknown error" },
	{ RO_ERR_IMPL, "Error implementation" },
	{ RO_ERR_HANDLE, "Unable to create netlink handle" },
	{ RO_ERR_SOCKET, "Unable to create netlink socket" },
	{ RO_ERR_BIND, "Unable to bind netlink socket" },
	{ RO_ERR_BUFFER, "Unable to allocate buffer" },
	{ RO_ERR_RECV, "Failed to receive netlink message" },
	{ RO_ERR_NLEOF, "Received EOF on netlink socket" },
	{ RO_ERR_ADDRLEN, "Invalid peer address length" },
	{ RO_ERR_STRUNC, "Sent message truncated" },
	{ RO_ERR_RTRUNC, "Received message truncated" },
	{ RO_ERR_NLRECV, "Received error from netlink" },
	{ RO_ERR_SEND, "Failed to send netlink message" },
	{ RO_ERR_RECVBUF, "Receive buffer size invalid" },
	{ RO_ERR_TIMEOUT, "Timeout"}
};

static int ro_errno = RO_ERR_NONE;

static char *ro_strerror(int errcode)
{
	if (errcode < 0 || errcode > RO_MAXERR)
		errcode = RO_ERR_IMPL;
	return ro_errmap[errcode].message;
}

static ssize_t ro_netlink_sendmsg (const struct msghdr *msg, unsigned int flags)
{
	int status = sendmsg(ro_h->fd, msg, flags);
	if (status < 0)
		ro_errno = RO_ERR_SEND;
	return status;
}

static ssize_t ro_netlink_recvfrom(unsigned char *buf, size_t len, int timeout)
{
	unsigned int addrlen;
	int status;
	struct nlmsghdr *nlh;

	if (len < sizeof(struct nlmsgerr)) {
		ro_errno = RO_ERR_RECVBUF;
		return -1;
	}
	addrlen = sizeof(ro_h->peer);

	if (timeout != 0) {
		int ret;
		struct timeval tv;
		fd_set read_fds;

		if (timeout < 0) {
			/* non-block non-timeout */
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		} else {
			tv.tv_sec = timeout / 1000000;
			tv.tv_usec = timeout % 1000000;
		}

		FD_ZERO(&read_fds);
		FD_SET(ro_h->fd, &read_fds);
		ret = select(ro_h->fd+1, &read_fds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR) {
				return 0;
			} else {
				ro_errno = RO_ERR_RECV;
				return -1;
			}
		}
		if (!FD_ISSET(ro_h->fd, &read_fds)) {
			ro_errno = RO_ERR_TIMEOUT;
			return 0;
		}
	}
	status = recvfrom(ro_h->fd, buf, len, 0,
	                      (struct sockaddr *)&ro_h->peer, &addrlen);
	if (status < 0) {
		ro_errno = RO_ERR_RECV;
		return status;
	}
	if (addrlen != sizeof(ro_h->peer)) {
		ro_errno = RO_ERR_RECV;
		return -1;
	}
	if (ro_h->peer.nl_pid != 0) {
		ro_errno = RO_ERR_RECV;
		return -1;
	}
	if (status == 0) {
		ro_errno = RO_ERR_NLEOF;
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_flags & MSG_TRUNC || nlh->nlmsg_len > status) {
		ro_errno = RO_ERR_RTRUNC;
		return -1;
	}
	return status;
}

/*
 * Create and initialise an ipq handle.
 */
struct ro_handle *ro_create_handle()
{
	int status;
	struct ro_handle *h;

	h = (struct ro_handle *)malloc(sizeof(struct ro_handle));
	if (h == NULL) {
		ro_errno = RO_ERR_HANDLE;
		return NULL;
	}
	memset(h, 0, sizeof(struct ro_handle));

    h->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_RO);

	/* source addr */
	memset(&h->local, 0, sizeof(struct sockaddr_nl));
	h->local.nl_family = AF_NETLINK;
	h->local.nl_pid = getpid();
	h->local.nl_groups = 0;
	h->local.nl_pad = 0;
	status = bind(h->fd, (struct sockaddr *)&h->local, sizeof(h->local));
	if (status == -1) {
		ro_errno = RO_ERR_BIND;
		close(h->fd);
		free(h);
		return NULL;
	}

	/* destination addr */
	memset(&h->peer, 0, sizeof(struct sockaddr_nl));
	h->peer.nl_family = AF_NETLINK;
	h->peer.nl_pid = 0;		/* destined to kernel */
	h->peer.nl_groups = 0;
	h->peer.nl_pad = 0;

	return h;
}

int ro_destroy_handle()
{
	if (ro_h) {
		close(ro_h->fd);
		free(ro_h);
	}
	return 0;
}

struct ro_msg *ro_get_packet(const unsigned char *buf)
{
    return NLMSG_DATA((struct nlmsghdr *)(buf));
}

void* pmip_ro_listener()
{
	int status;
	unsigned char buf[BUFSIZE];
	struct in6_addr mn1_addr;
	struct in6_addr mn2_addr;
	struct in6_addr lma1_addr;
	struct in6_addr lma2_addr;
	pmip_entry_t *bce1 = NULL, *bce2 = NULL;

	struct ro_msg *pmsg;
	do {
		/* read packets from buffer */
		status = ro_netlink_recvfrom(buf, BUFSIZE, 0);
		if (status > 0) {
			pmsg = ro_get_packet(buf);
			if (strstr(pmsg->str_dstaddr, ":") != NULL) {
				dbg("Trigger src addr %s, dest addr %s, src mag %s, dst mag %s \n", pmsg->str_srcaddr, pmsg->str_dstaddr, pmsg->lma_srcaddr, pmsg->lma_dstaddr);
				// convert string address to in6_addr
				inet_pton(AF_INET6, pmsg->str_srcaddr, &mn1_addr);
				inet_pton(AF_INET6, pmsg->str_dstaddr, &mn2_addr);
				inet_pton(AF_INET6, pmsg->lma_srcaddr, &lma1_addr);
				inet_pton(AF_INET6, pmsg->lma_dstaddr, &lma2_addr);

				struct in6_addr hw1_address = eth_address2hw_address(mn1_addr);
				struct in6_addr hw2_address = eth_address2hw_address(mn2_addr);

				if (strcmp(pmsg->lma_srcaddr, pmsg->lma_dstaddr) == 0) { // the same lma
					bce1 = pmip_cache_get(&conf.OurAddress, &hw1_address);
					bce2 = pmip_cache_get(&conf.OurAddress, &hw2_address);
					if (bce1 && bce2) {
						dbg("Send ROI to mag \n");
						mh_send_roi(&mn1_addr, &mn2_addr, &bce1->mn_serv_mag_addr, &bce2->mn_serv_mag_addr);
					}
					if (bce1)
						pmipcache_release_entry(bce1);
					if (bce2)
						pmipcache_release_entry(bce2);
				}
				else {	// 2 LMA
					bce1 = pmip_cache_get(&conf.OurAddress, &hw1_address);
					if (bce1) {
						dbg("Send ROT to other LMA \n");
						mh_send_rot(&mn1_addr, &mn2_addr, &bce1->mn_serv_mag_addr, &lma2_addr);
						pmipcache_release_entry(bce1);
					}
				}
			}
		}
		else
			dbg("get error message from kernel \n");
	} while (1);
	return 0;
}

/**
 * Public interface
 **/

void pmip_ro_setup_policy()
{
	lma_policy_entry_t policy;
	struct in6_addr lma_addr;

	memset(&policy, 0, sizeof(lma_policy_entry_t));
	strcpy(policy.lma_addr, "2001:100:0:0:0:0:0:1");
	strcpy(policy.mn_prefix, "2001:100:10");
	inet_pton(AF_INET6, "2001:100:0:0:0:0:0:1", &lma_addr);
	if (IN6_ARE_ADDR_EQUAL(&conf.OurAddress, &lma_addr))
		policy.lmaself = 1;
	pmip_ro_send_policy(&policy);

	memset(&policy, 0, sizeof(lma_policy_entry_t));
	strcpy(policy.lma_addr, "2002:100:0:0:0:0:0:1");
	strcpy(policy.mn_prefix, "2002:100:10");
	inet_pton(AF_INET6, "2002:100:0:0:0:0:0:1", &lma_addr);
	if (IN6_ARE_ADDR_EQUAL(&conf.OurAddress, &lma_addr))
		policy.lmaself = 1;
	pmip_ro_send_policy(&policy);
}

int pmip_ro_send_mn_info(struct in6_addr* mn_addr)
{
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh;
	char str_addr[64];

	sprintf(str_addr, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(mn_addr));

	/* Fill the netlink message header */
	nlh = (struct nlmsghdr *)malloc(MSG_LEN_RO);
	memset(nlh , 0 ,MSG_LEN_RO);
	strcpy((char*)NLMSG_DATA(nlh), str_addr);
	nlh->nlmsg_len =MSG_LEN_RO;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 1;
	nlh->nlmsg_type = 1;	// send to remove MN in RO

	/*iov structure */
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	/* msg */
	memset(&msg,0,sizeof(msg));
	msg.msg_name = (void *) &ro_h->peer ;
	msg.msg_namelen=sizeof(ro_h->peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ro_netlink_sendmsg(&msg, 0);
	return 0;
}

int pmip_ro_send_policy(lma_policy_entry_t *entry)
{
	struct msghdr msg;
	struct iovec iov[2];
	struct nlmsghdr nlh;
	size_t tlen;

	tlen = sizeof(nlh) + sizeof(lma_policy_entry_t);
	memset(&nlh, 0, sizeof(nlh));
	nlh.nlmsg_len = tlen;
	//nlh.nlmsg_pid = getpid();
	nlh.nlmsg_pid = ro_h->local.nl_pid;
	nlh.nlmsg_flags = 1;
	nlh.nlmsg_type = 2;	// send policy

	dbg("mn_prefix : %s \n", entry->mn_prefix);
	/*iov structure */
	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = entry;
	iov[1].iov_len = sizeof(lma_policy_entry_t);

	/* msg */
	memset(&msg,0,sizeof(msg));
	msg.msg_name = (void *) &ro_h->peer ;
	msg.msg_namelen=sizeof(ro_h->peer);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	ro_netlink_sendmsg(&msg, 0);
	return 0;
}

int pmip_ro_init()
{
	ro_h = ro_create_handle();
	if (ro_h == NULL) {
		dbg("Error msg: %s \n", ro_strerror(ro_errno));
		return -1;
	}

	pthread_create(&ro_listener, NULL, pmip_ro_listener, NULL);
	return 0;
}

void pmip_ro_cleanup()
{
	dbg("Cleanup RO \n");
	ro_destroy_handle();
	pthread_cancel(ro_listener);
	pthread_join(ro_listener, NULL);
	pmip_tunnel_clean_list();
}
