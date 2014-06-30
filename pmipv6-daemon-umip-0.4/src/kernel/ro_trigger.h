#ifndef __RO_TRIGGER_H__
#define __RO_TRIGGER_H__

#define SAFE_FREE(p) { if (p != NULL) kfree(p); p = NULL; }
#define NETLINK_RO 17
#define NIP6ADDR(addr) \
        ntohs((addr)->s6_addr16[0]), \
        ntohs((addr)->s6_addr16[1]), \
        ntohs((addr)->s6_addr16[2]), \
        ntohs((addr)->s6_addr16[3]), \
        ntohs((addr)->s6_addr16[4]), \
        ntohs((addr)->s6_addr16[5]), \
        ntohs((addr)->s6_addr16[6]), \
        ntohs((addr)->s6_addr16[7])

typedef struct ro_msg {
	char str_srcaddr[64];
	char lma_srcaddr[64];
	char str_dstaddr[64];
	char lma_dstaddr[64];
	int  btrigger;
} ro_msg_t;

// contain a pair MN for RO
typedef struct ro_mn_entry {
	struct list_head list;
	char mn1_addr[64];
	char mn2_addr[64];
} ro_mn_entry_t;

typedef struct lma_policy_entry {
	struct list_head list;
	char mn_prefix[64];
	char lma_addr[64];
	unsigned int lmaself;
} lma_policy_entry_t;

int ro_send_trigger (struct in6_addr* src_addr, struct in6_addr* dst_addr, ro_msg_t *data);

#endif
