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
#include "../list.h"

typedef struct packet_list {
	struct list_head list;
	ipq_packet_msg_t* pmsg;
} packet_list_t;

#define BUFSIZE 		65536

/* ip queue handle */
static struct ipq_handle *h;
static count_packet = 0;

LIST_HEAD(pkg_list);

#define SAFE_FREE(p) { if (p != NULL) free(p); p = NULL; }
/*=============================== main functions =============================================*/
int delay_init()
{
	pthread_t thread;
	int ret;
	h = ipq_create_handle(0, PF_INET6);
	if (!h)
		return -1;

	ret = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (ret < 0)
		return -1;

	return 0;
}

int delay_cleanup()
{
	printf("Clean up buffering\n");
	ipq_destroy_handle(h);
//	pthread_cancel(pthread);
//	pthread_join(pthread, NULL);
}

void * _pkg_reinject()
{
	struct list_head *pos;
	packet_list_t *element;
	int is_first = 1;
	static unsigned int count = 0;
	do {
		usleep(100);
		if (!list_empty(&pkg_list)) {
			if (is_first) {
				is_first = 0;
				//usleep(200000);
				//sleep(2);
				printf("receive number packets in delay: %d\n", count_packet);
			}
			pos = pkg_list.next;
			element = list_entry(pos, packet_list_t, list);
			ipq_set_verdict(h, element->pmsg->packet_id, NF_ACCEPT, 0, NULL);
			printf("Sending packet id = %lu, number packet = %u \n", element->pmsg->packet_id, ++count);
			usleep(5000); // 5ms send 1 pkg
			list_del(pos);
			SAFE_FREE(element);
		}
	} while (1);
}

int main(void)
{
	int status;
	unsigned char buf[BUFSIZE];

	packet_list_t *element;
	ipq_packet_msg_t *pmsg;

	delay_init();

	pthread_t thread;
	pthread_create(&thread, NULL, _pkg_reinject, NULL);

	do {
		/* read packets from buffer */
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status > 0) {
			switch (ipq_message_type(buf)) {
				case NLMSG_ERROR:
					printf("Received error message %d\n", ipq_get_msgerr(buf));
					break;
				case IPQM_PACKET: {
					/* adding packet to pool */
					ipq_packet_msg_t *m = ipq_get_packet(buf);
					pmsg = (ipq_packet_msg_t*)malloc(sizeof(ipq_packet_msg_t) + m->data_len);
					memcpy(pmsg, m, sizeof(ipq_packet_msg_t) + m->data_len);

					element = (packet_list_t *)malloc(sizeof(packet_list_t));
					element->pmsg = pmsg;
					list_add_tail(&(element->list), &pkg_list);
					count_packet++;
					break;
				}
				default:
					printf("Unknown message type!\n");
					break;
			}
		}
		else
			printf("ipq_read error return: %s\n",ipq_errstr());
	} while (1);
	return 0;
}


