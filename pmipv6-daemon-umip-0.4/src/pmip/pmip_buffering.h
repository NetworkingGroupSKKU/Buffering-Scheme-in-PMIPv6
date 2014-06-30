#ifndef __PMIP_BUFFERING_H__
#    define __PMIP_BUFFERING_H__

#include <netinet/ip6.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <assert.h>
#include "list.h"
#include "util.h"

typedef struct packet_list {
	struct list_head list;
	ipq_packet_msg_t* pmsg;
} packet_list_t;

typedef struct packet_hash_entry {
	packet_list_t* 	packet_list;			/* store packet buffer of MN */
	struct in6_addr mn_address;
	int				path_id;				/* use in ETM method to identify buffered packet of the same MN, defaul 0: old path, 1: newpath */
	int 			is_reinject;			/* = 1 is reinjecting */
	struct timeval  time_start;				/* time when buffer first packet to caculate packet_rate */
	struct timeval  time_end;				/* time when buffer end packet before reinject to caculate packet_rate */
	unsigned long	num_packets;			/* total packet buffering in lowlatency time*/
	unsigned int	packet_rate;
	unsigned int	waite_sequence;
	int 			flushing_radio;
	/*struct tq_elem tqe;*/					/* using remove packet list of MN when expired */
} packet_hash_entry_t;

typedef struct packet_hash {
	int buckets;
	packet_hash_entry_t **hash_buckets;
} packet_hash_t;

void pmip_add_rule(struct in6_addr* mn_addr, int flag);
int pmip_buffering_init();
int pmip_buffering_start(struct in6_addr* mn_addr, int path_id);
void pmip_buffering_reinject(struct in6_addr* mn_addr, int path_id);
int pmip_buffering_cleanup();
int query_mag_index(int _index);	// if _index != 0 then set index else return 1 or 2 for mag1 or mag2, respectivelly.
#endif
