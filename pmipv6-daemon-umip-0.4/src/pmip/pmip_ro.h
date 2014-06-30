#ifndef __PMIP_RO_H__
#    define __PMIP_RO_H__

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <pthread.h>
#include "list.h"

#define NETLINK_RO	17
#define MSG_LEN_RO	256

struct ro_handle
{
	int fd;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
};

typedef struct tnlinfo_list_entry {
	struct list_head list;
	struct in6_addr mn_addr;	// address of MN which attaches to mag_addr
	struct in6_addr mag_addr;   // mag is friend mag (mag2)
	int				tunnel;
	int				type;		//type = 0 using for RO, type=1 using for FPMIP at pMAG, type=2 FPMIP at nMAG
} tnlinfo_list_entry_t;

typedef struct lma_policy_entry {
	char mn_prefix[64];
	char lma_addr[64];
	unsigned int lmaself;
} lma_policy_entry_t;

void pmip_tunnel_add_entry(tnlinfo_list_entry_t *entry);
int pmip_tunnel_del_entry(struct in6_addr* mn_addr, struct in6_addr* mag_addr);
int pmip_tunnel_exist_entry (struct in6_addr* mn_addr, struct in6_addr* mag_addr);
int pmip_tunnel_clean_list (void);
int pmip_tunnel_get_info_fpmip(struct in6_addr* mn_prefix/*in*/, struct in6_addr* mn_addr, struct in6_addr* mag_addr /*out*/);

int pmip_ro_init();
void pmip_ro_cleanup();
int pmip_ro_send_policy(lma_policy_entry_t *entry);
void pmip_ro_setup_policy();
int pmip_ro_send_mn_info(struct in6_addr* mn_addr);

#endif
