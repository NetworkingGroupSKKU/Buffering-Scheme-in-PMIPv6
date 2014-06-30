#define PMIP
#ifdef HAVE_CONFIG_H
#	include <config.h>
#endif

#include "pmip_buffering.h"
#include "debug.h"
#include "conf.h"
#include <netinet/ip6mh.h>
#include "pmip_mag_proc.h"

#define BUFSIZE 		65536

#define ADD_GENERAL_RULE 		"ip6tables -t mangle -A PREROUTING -d %s -p udp --dport 9079:9080 -j QUEUE"
#define DEL_GENERAL_RULE		"ip6tables -t mangle -D PREROUTING -d %s -p udp --dport 9079:9080 -j QUEUE"

#define ADD_MAG_RULE_FPMIP	 	"ip6tables -t mangle -A PREROUTING -d %s -p udp --dport 9079:9080 -j QUEUE"
#define DEL_MAG_RULE_FPMIP		"ip6tables -t mangle -D PREROUTING -d %s -p udp --dport 9079:9080 -j QUEUE"

#ifdef NAMYEONG_PAPER
#define ADD_MAG_RULE_TNL1 	"ip6tables -t mangle -A PREROUTING -d %s -i ip6tnl1 -j QUEUE"
#define DEL_MAG_RULE_TNL1	"ip6tables -t mangle -D PREROUTING -d %s -i ip6tnl1 -j QUEUE"

#define ADD_MAG_RULE_TNL2 	"ip6tables -t mangle -A PREROUTING -d %s -i ip6tnl2 -j QUEUE"
#define DEL_MAG_RULE_TNL2	"ip6tables -t mangle -D PREROUTING -d %s -i ip6tnl2 -j QUEUE"
#endif

#define DEL_ALL_RULE 	"ip6tables -t mangle -F"
#define POOL_MAX 10
#define LOG_REMAINING_PACKET  0

/* ip queue handle */
static struct ipq_handle *h;
/* buffer pool */
static packet_hash_t hash_pool;

/* thread to receive packets */
static pthread_t pb_listener;
static int exit_thread;
static int created_thread;
static int remaining_packets;
pthread_rwlock_t buffer_lock;

/**************************************************************************************
 * Buffer data structure
 *
 ***************************************************************************************/
int buff_hash_init(packet_hash_t *h)
{
	h->hash_buckets = (packet_hash_entry_t **)malloc(POOL_MAX * sizeof(packet_hash_entry_t *));
	if (!h->hash_buckets)
		return -ENOMEM;
	memset(h->hash_buckets, 0, POOL_MAX * sizeof(packet_hash_entry_t *));
	h->buckets = 0;

	return 0;
}

void buff_hash_cleanup(packet_hash_t *h)
{
	int i;
	assert(h);

	for(i=0; i < h->buckets; i++)
		SAFE_FREE(h->hash_buckets[i]);
	SAFE_FREE(h->hash_buckets);
}

void *buff_hash_get(packet_hash_t *h, const struct in6_addr *mn_addr, int path_id)
{
	assert(h);
	assert(mn_addr);
	int i;

	for (i=0; i<h->buckets; i++) {
		if (IN6_ARE_ADDR_EQUAL(&h->hash_buckets[i]->mn_address, mn_addr) && (h->hash_buckets[i]->path_id == path_id))
			return (h->hash_buckets[i]);
	}

	return NULL;
}

int buff_hash_add(packet_hash_t *h, packet_hash_entry_t *elem)
{
	h->hash_buckets[h->buckets++] = elem;
	return 0;
}

void buff_hash_delete(packet_hash_t *h, const struct in6_addr *mn_addr)
{
	int i,j;
	for (i=0; i<h->buckets; i++) {
		if (IN6_ARE_ADDR_EQUAL(&h->hash_buckets[i]->mn_address, mn_addr)) {
			SAFE_FREE(h->hash_buckets[i]);
			for (j=i+1; j<h->buckets; j++)
				h->hash_buckets[j-1] = h->hash_buckets[j];
			h->buckets--;
		}
	}
}


/**************************************************************************************
 * Iptables rule & buffer management
 *
 ***************************************************************************************/
static int pkg_buffering_add_rule(struct in6_addr* mn_addr, const char* rule)
{
	char str[INET6_ADDRSTRLEN];
	char cmd[256];

	if (mn_addr == NULL || rule == NULL)
		return -1;
	inet_ntop(AF_INET6, mn_addr, str, INET6_ADDRSTRLEN);
	sprintf(cmd, rule, str);
	dbg("Rule: %s \n", cmd);
	return(system(cmd));
}

/* if mn_addr is NULL then del all rules */
static int pkg_buffering_del_rule(struct in6_addr* mn_addr, const char* rule)
{
	char str[INET6_ADDRSTRLEN];
	char cmd[128];
	if (mn_addr == NULL)
		return(system(DEL_ALL_RULE));
	else if (rule != NULL) {
		inet_ntop(AF_INET6, mn_addr, str, INET6_ADDRSTRLEN);
		sprintf(cmd, rule, str);
		return(system(cmd));
	}
}

static void pkg_buffering_clean(struct in6_addr* mn_addr, int path_id)
{
	struct list_head *pos, *q;
	packet_list_t *element;
	packet_hash_entry_t *hash_item;

	pthread_rwlock_wrlock(&buffer_lock);

	hash_item = (packet_hash_entry_t*)buff_hash_get(&hash_pool, mn_addr, path_id);
	if (hash_item != NULL) {
		list_for_each_safe(pos, q, &hash_item->packet_list->list) {
			element = list_entry(pos, packet_list_t, list);
			list_del(pos);
			SAFE_FREE(element->pmsg);
			SAFE_FREE(element);
		}
		buff_hash_delete(&hash_pool, mn_addr);
	}
	pthread_rwlock_unlock(&buffer_lock);
}

static void pkg_buffering_clean_each(int index)
{
	struct list_head *pos, *q;
	packet_list_t *element;
	packet_hash_entry_t *hash_item;

	pthread_rwlock_wrlock(&buffer_lock);

	hash_item = hash_pool.hash_buckets[index];
	if (hash_item != NULL) {
		list_for_each_safe(pos, q, &hash_item->packet_list->list) {
			element = list_entry(pos, packet_list_t, list);
			list_del(pos);
			SAFE_FREE(element->pmsg);
			SAFE_FREE(element);
		}
	}
	pthread_rwlock_unlock(&buffer_lock);
}

static void pkg_buffering_clean_all()
{
	int i;
	for (i=0; i<hash_pool.buckets; i++)
		pkg_buffering_clean_each(i);
	buff_hash_cleanup(&hash_pool);
}

/* add packet_list_t item to pool */
static void pkg_buffering_add_pool(packet_list_t *element, struct in6_addr* mn_addr, int path_id)
{
	packet_hash_entry_t *hash_item;

	pthread_rwlock_wrlock(&buffer_lock);
	hash_item = (packet_hash_entry_t *)buff_hash_get(&hash_pool, mn_addr, path_id);

	if (hash_item != NULL) {
		dbg("Add packet which has len: %d msg_id: %lu \n", element->pmsg->data_len, element->pmsg->packet_id);
		/* update packets list information */
		if (!hash_item->is_reinject) {
			if (list_empty(&hash_item->packet_list->list))
				gettimeofday(&hash_item->time_start, NULL);
			else
				gettimeofday(&hash_item->time_end, NULL);
			hash_item->num_packets++;
		}
		/* add packet to list tail */
		remaining_packets++;
		list_add_tail(&(element->list), &(hash_item->packet_list->list));
	}
	else
		dbg("hash_item is NULL. \n");
	pthread_rwlock_unlock(&buffer_lock);
}

/**************************************************************************************
 *  Specific Functions For Paper Implementation
 *
 ***************************************************************************************/
/* function is used to log remaining packet in buffer for statistic */
void * log_remaining_packet(void *data)
{
	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], timebuf[64];
	FILE *file;

	file = fopen("/home/fig4.csv","a+"); /* apend file (add text to a file or create a file if it does not exist.*/
	while (!exit_thread) {
		gettimeofday(&tv, NULL);
		nowtime = tv.tv_sec;
		nowtm = localtime(&nowtime);
		strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
		snprintf(timebuf, sizeof timebuf, "%s.%06d", tmbuf, (int)tv.tv_usec);
		fprintf(file,"%s, %d\n", timebuf, remaining_packets);
		fflush(file);
		sleep(1);
	}
	dbg("\n====> remaining packet = %lu \n", remaining_packets);
	fprintf(file,"%s, %d\n", timebuf, remaining_packets);
	fclose(file); /*done!*/

	dbg("===>Exit thread\n");
	exit_thread = 0;
	created_thread = 0;
}


#ifdef NAMYEONG_PAPER
int cal_timeout()
{
	int ret;  //milli second
	mag_timeout.ttl_max_op = 44;  // 40 hops ~= 200 ms delay
	mag_timeout.ttl_max_np = 4;
	mag_timeout.ttl_max_rs = 42;
	mag_timeout.l_mtu = 1500;
	mag_timeout.l_ro_setup = sizeof(struct ip6_hdr) + sizeof(struct ip6_mh_ros) + 16; //16 is size of mobility header option
	mag_timeout.t_rs = 200;
	mag_timeout.t_one_hop = ((mag_timeout.l_mtu*(mag_timeout.t_rs/2))/mag_timeout.l_ro_setup)/mag_timeout.ttl_max_rs;
	ret = mag_timeout.t_one_hop * (mag_timeout.ttl_max_op - mag_timeout.ttl_max_np);
	dbg("l_ro_setup = %d\n", mag_timeout.l_ro_setup);
	return ret;
}

void * _timeout_reinject(void* data)
{
	struct in6_addr* mn_addr;
	mn_addr = (struct in6_addr*) data;
	if (mn_addr != NULL) {
		int timeout = cal_timeout();
		if (timeout > 5000 || timeout < 1000)
			timeout = 2000;
		usleep(timeout * TIME_SEC_MSEC);  // sleep micro second
		pmip_buffering_reinject(mn_addr, 0);
	}
}

void avoid_outofseq_packets(packet_list_t *element, struct ip6_hdr *ip6)
{
	unsigned int proto;
	packet_hash_entry_t *hash_item;

	if (!is_mag())
		return;

	proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	if (proto == 44) {  // fragmentation header
		hash_item = (packet_hash_entry_t *)buff_hash_get(&hash_pool, &ip6->ip6_dst, 0);
		if (hash_item != NULL) {
			struct ip6_frag* frag = (struct ip6_frag*)(m->payload + sizeof(struct ip6_hdr));
			unsigned short offset = ntohs(frag->ip6f_offlg);
			unsigned int ident  = ntohl(frag->ip6f_ident);

			if (hash_item->waite_sequence == -1) {
				hash_item->waite_sequence = ident - 1;
				dbg("\n ***** extension header %u, offset= %u, ident = %u, waitpkg = %u, timeout=%d ms ***\n\n", proto, offset, ident, hash_item->waite_sequence, cal_timeout());
				pkg_buffering_add_rule(&hash_item->mn_address, ADD_MAG_RULE_TNL1);
			}
			else if (hash_item->waite_sequence > 0) {
				if (ident < hash_item->waite_sequence) {
					dbg("packet in old path with ident=%u \n", ident);
					ipq_set_verdict(h, element->pmsg->packet_id, NF_ACCEPT, 0, NULL);
					break;
				}
				else if (ident == hash_item->waite_sequence) {
					ipq_set_verdict(h, element->pmsg->packet_id, NF_ACCEPT, 0, NULL);
					dbg("Last Packet in old path arrived !\n");
					if (hash_item->is_reinject == 0) {
						//dbg("Packets of old path arrived. Start re-inject at MAG: ident=%u \n", ident);
						//pmip_buffering_reinject(&hash_item->mn_address);
						dbg("All Packets of old path arrived with last ident=%u. But waite timeout to re-inject \n", ident);
					}
					break;
				}
			}
		}
	}

}

#endif

#ifdef USE_SMARTBUFF
void * _delay_adding_rule(void* data)
{

	struct in6_addr* mn_addr;
	mn_addr = (struct in6_addr*) data;
	if (mn_addr != NULL) {
		usleep((0.99) * TIME_SEC_MSEC);
		pkg_buffering_add_rule(mn_addr, ADD_GENERAL_RULE);
	}
}
#endif

void pmip_add_rule(struct in6_addr* mn_addr, int flag)
{
#ifdef LMA_BUFFERING
		pkg_buffering_add_rule(mn_addr, ADD_GENERAL_RULE);
#endif
#ifdef NAMYEONG_PAPER
		pkg_buffering_add_rule(mn_addr, ADD_MAG_RULE_TNL2);
		pthread_t thread;
		pthread_create(&thread, NULL, _timeout_reinject, (void*)mn_addr);
#endif
#ifdef USE_FPMIP
		pkg_buffering_add_rule(mn_addr, ADD_MAG_RULE_FPMIP);
#endif
#ifdef USE_SMARTBUFF
		if (flag == 1 || flag ==2)	// store flag to identify MAG1 or MAG2
			query_mag_index(flag);
		if (flag == 1)	// at MAG1
			pthread_create(&thread, NULL, _delay_adding_rule, (void*)mn_addr);
		else if (flag == 2) // at MAG2
			pkg_buffering_add_rule(mn_addr, ADD_MAG_RULE_FPMIP);
#endif

}

/**************************************************************************************
 * General Functions for Packet Buffering
 *
 ***************************************************************************************/
int query_mag_index(int _index)
{
	static int index = 0;
	if (_index != 0)
		index = _index;
	else
		return index;
}
static void* pkg_buffering_listener()
{
	int status;
	unsigned char buf[BUFSIZE];

	packet_list_t *element;
	ipq_packet_msg_t *pmsg;
	do {
		/* read packets from buffer */
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status > 0) {
			switch (ipq_message_type(buf)) {
				case NLMSG_ERROR:
					dbg("Received error message %d\n", ipq_get_msgerr(buf));
					break;
				case IPQM_PACKET: {
					//dbg("Receive packet!\n");
					/* adding packet to pool */
					ipq_packet_msg_t *m = ipq_get_packet(buf);
					pmsg = (ipq_packet_msg_t*)malloc(sizeof(ipq_packet_msg_t) + m->data_len);
					memcpy(pmsg, m, sizeof(ipq_packet_msg_t) + m->data_len);

					element = (packet_list_t *)malloc(sizeof(packet_list_t));
					element->pmsg = pmsg;

					struct ip6_hdr *ip6 = (struct ip6_hdr *)m->payload;
#ifdef NAMYEONG_PAPER
					avoid_outofseq_packets(element, ip6);
#endif
#ifdef ETM_METHOD
					if (strcmp("ip6tnl2", pmsg->indev_name) == 0) {
						pkg_buffering_add_pool(element, &ip6->ip6_dst, 1);
						dbg("**************** Packets via the new path **************** \n");
					}
					else
#endif
					 pkg_buffering_add_pool(element, &ip6->ip6_dst, 0);
					break;
				}
				default:
					dbg("Unknown message type!\n");
					break;
			}
		}
		else
			dbg("ipq_read error return: %s\n",ipq_errstr());
	} while (1);
	return 0;
}

int pmip_buffering_start(struct in6_addr* mn_addr, int path_id)
{
	dbg("Start buffering packets to buffering \n");

#ifdef LMA_BUFFERING
	if (is_lma())
		pmip_add_rule(mn_addr, 0);
#endif
	int ret = 0;
	packet_list_t *head;
	packet_hash_entry_t *hash_item = NULL;
	pthread_rwlock_wrlock(&buffer_lock);

	/* check MN existed in buffer pool */
	hash_item = buff_hash_get(&hash_pool, mn_addr, path_id);
	if (hash_item != NULL) {
		dbg("Packet buffering did for the MN \n");
		hash_item->is_reinject = 0; // stop re-inject
		pthread_rwlock_unlock(&buffer_lock);
		return 0;
	}

	hash_item = (packet_hash_entry_t *)malloc(sizeof(packet_hash_entry_t));
	head = (packet_list_t *)malloc(sizeof(packet_list_t));
	memset(hash_item, 0, sizeof(packet_hash_entry_t));

	hash_item->packet_list = head;
	INIT_LIST_HEAD(&hash_item->packet_list->list);
	memcpy(&hash_item->mn_address, mn_addr, sizeof(struct in6_addr));
	hash_item->waite_sequence = -1;
	hash_item->path_id = path_id;
	hash_item->flushing_radio = 10;
	if (path_id == 1) // new path
		hash_item->flushing_radio = 1;

	dbg("add hash item %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(mn_addr));
	ret = buff_hash_add(&hash_pool, hash_item);

#if LOG_REMAINING_PACKET > 0
	if (created_thread == 0) {
		pthread_t thread;
		pthread_create(&thread, NULL, log_remaining_packet, NULL);
		created_thread = 1;
	}
	else
		dbg("Not exit thread yet \n");
#endif
	pthread_rwlock_unlock(&buffer_lock);
	return ret;
}

void * _pkt_reinject(void* data)
{
	struct list_head *pos;
	packet_list_t *element;
	packet_hash_entry_t* hash_item;

	hash_item = (packet_hash_entry_t*) data;

	if (hash_item != NULL) {
		/* loop to reinject all packets in buffering */
		list_for_each(pos, &hash_item->packet_list->list) {
			element = list_entry(pos, packet_list_t, list);
			dbg("Foward packet which has msg_id: %lu \n", element->pmsg->packet_id);
			ipq_set_verdict(h, element->pmsg->packet_id, NF_ACCEPT, 0, NULL);
			/* control packet rate */
			//usleep(1000000/hash_item->packet_rate);
			usleep(1000000/(128 * hash_item->flushing_radio));
			remaining_packets--;
			if (hash_item->is_reinject == 0)
				break;
		}

		if (hash_item->is_reinject == 1) {
			dbg("Finish re-inject packets: packet rate = %u \n", hash_item->packet_rate);
			remaining_packets = 0;
#if LOG_REMAINING_PACKET > 0
			exit_thread = 1;
#endif
			if (is_mag()) { // mag is cleanup buffering when finish re_injecting because mag starts buffering in FSM module
#ifdef USE_FPMIP
				// clean up tunnel at mag2, then send HAC message
				mag_cleanup_for_fpmip(&hash_item->mn_address);
#endif
#ifdef USE_SMARTBUFF
				if (query_mag_index(0) == 2)
					mag_cleanup_for_fpmip(&hash_item->mn_address);
#endif
				pmip_buffering_cleanup();
			}
			else {		// lma start buffering in init program.
				/* del iptable rule and clean buffer */
				pkg_buffering_del_rule(NULL, NULL);
				pkg_buffering_clean(&hash_item->mn_address, hash_item->path_id);
			}
		}
	}
}

#ifdef ETM_METHOD
void * _etm_reinject(void* data)
{
	struct list_head *pos;
	packet_list_t *element;
	packet_hash_entry_t* hash_item;

	hash_item = (packet_hash_entry_t*) data;

	if (hash_item != NULL) {
		/* loop to reinject all packets in buffering */
		list_for_each(pos, &hash_item->packet_list->list) {
			element = list_entry(pos, packet_list_t, list);
			dbg("Foward packet which has msg_id: %lu \n", element->pmsg->packet_id);
			ipq_set_verdict(h, element->pmsg->packet_id, NF_ACCEPT, 0, NULL);
			/* control packet rate */
			//usleep(1000000/hash_item->packet_rate);
			usleep(1000000/(128 * hash_item->flushing_radio));
			if (hash_item->is_reinject == 0)
				break;
		}

		if (hash_item->is_reinject == 1) {
			if (hash_item->path_id == 0) {
				// clean up tunnel at mag2, then send HAC message
				mag_cleanup_for_fpmip(&hash_item->mn_address);
				// flushing packet in new path
				pmip_buffering_reinject(&hash_item->mn_address, 1);
			}
			else {
				dbg("Finish re-inject packets in new path\n");
				pmip_buffering_cleanup();
			}
		}
	}
}

#endif

void pmip_buffering_reinject(struct in6_addr* mn_addr, int path_id)
{
	pthread_t thread;
	packet_hash_entry_t* hash_item;
	double elapse;
	/* check MN existed in buffer pool */
	pthread_rwlock_wrlock(&buffer_lock);
	hash_item = buff_hash_get(&hash_pool, mn_addr, path_id);
	if (hash_item != NULL) {
		if (hash_item->is_reinject == 0) {
			hash_item->is_reinject = 1;
			/*calculate packets rate */
			elapse = ts2msec(hash_item->time_end) - ts2msec(hash_item->time_start); // milli seconds
			if (elapse != 0) {
				hash_item->packet_rate = (hash_item->num_packets*TIME_SEC_MSEC)/elapse;
			}
			else {
				hash_item->packet_rate = hash_item->num_packets;
			}
			dbg("\n Packet rate = %u\n", hash_item->packet_rate);
			/* forward to MN faster */
			hash_item->packet_rate = hash_item->packet_rate * 1.2 + 0.5;
			hash_item->num_packets = 0;
#ifdef ETM_METHOD
			pthread_create(&thread, NULL, _etm_reinject, (void*)hash_item);
#else
			pthread_create(&thread, NULL, _pkt_reinject, (void*)hash_item);
#endif
		}
	}
	else {
		dbg("Hash item is null. \n");
	}
	pthread_rwlock_unlock(&buffer_lock);
}

int pmip_buffering_init()
{
	int ret;
	h = ipq_create_handle(0, PF_INET6);
	if (!h)
		return -1;

	ret = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (ret < 0)
		return -1;

	 if (pthread_rwlock_init(&buffer_lock, NULL))
	    return -1;

	buff_hash_init(&hash_pool);
	pthread_create(&pb_listener, NULL, pkg_buffering_listener, NULL);
#if LOG_REMAINING_PACKET > 0
	exit_thread = 0;
	created_thread = 0;
#endif
	return 0;
}

int pmip_buffering_cleanup()
{
	dbg("Clean up buffering\n");

#if LOG_REMAINING_PACKET > 0
	exit_thread = 1;
#endif
	pkg_buffering_del_rule(NULL,NULL);
	pkg_buffering_clean_all();
	ipq_destroy_handle(h);
	pthread_cancel(pb_listener);
	pthread_join(pb_listener, NULL);
}



