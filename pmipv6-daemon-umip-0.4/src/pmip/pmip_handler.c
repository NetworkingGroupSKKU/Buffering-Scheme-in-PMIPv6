/*! \file pmip_handler.c
* \brief
* \author OpenAir3 Group
* \date 12th of October 2010
* \version 1.0
* \company Eurecom
* \project OpenAirInterface
* \email: openair3@eurecom.fr
*/
#define PMIP
#define PMIP_HANDLER_C
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
//---------------------------------------------------------------------------------------------------------------------
#include "pmip_fsm.h"
#include "pmip_handler.h"
#include "pmip_lma_proc.h"
#include "pmip_mag_proc.h"
#include "pmip_msgs.h"
//---------------------------------------------------------------------------------------------------------------------
#include "ndisc.h"
#ifdef ENABLE_VT
#    include "vt.h"
#endif
#include "debug.h"
#include "conf.h"
//---------------------------------------------------------------------------------------------------------------------
struct in6_addr *link_local_addr(struct in6_addr *id)
{
    static struct in6_addr ADDR;
    ADDR = in6addr_any;
    ADDR.s6_addr32[0] = htonl(0xfe800000);
//copy the MN_ID.
    memcpy(&ADDR.s6_addr32[2], &id->s6_addr32[2], sizeof(ip6mnid_t));
    return &ADDR;
}
//---------------------------------------------------------------------------------------------------------------------
struct in6_addr *CONVERT_ID2ADDR(struct in6_addr *result, struct in6_addr *prefix, struct in6_addr *id)
{
    *result = in6addr_any;
    memcpy(&result->s6_addr32[0], &prefix->s6_addr32[0], sizeof(ip6mnid_t));
    memcpy(&result->s6_addr32[2], &id->s6_addr32[2], sizeof(ip6mnid_t));
    return result;
}
//---------------------------------------------------------------------------------------------------------------------
struct in6_addr *get_mn_addr(pmip_entry_t * bce)
{
    CONVERT_ID2ADDR(&bce->mn_addr, &bce->mn_prefix, &bce->mn_suffix);
    return &bce->mn_addr;
}
//---------------------------------------------------------------------------------------------------------------------
struct in6_addr *solicited_mcast(struct in6_addr *id)
{
//NUD_ADDR converts an ID into a Multicast Address for NS Unreachability!
    static struct in6_addr ADDR2;
    ADDR2 = in6addr_any;
    ADDR2.s6_addr32[0] = htonl(0xff020000);
    ADDR2.s6_addr32[1] = htonl(0x00000000);
    ADDR2.s6_addr32[2] = htonl(0x00000001);
    ADDR2.s6_addr[12] = 0xff;
    //copy the least 24 bits from the MN_ID.
    memcpy(&ADDR2.s6_addr[13], &id->s6_addr[13], 3 * sizeof(u_int8_t));
    return &ADDR2;
}
//---------------------------------------------------------------------------------------------------------------------
void pmip_timer_retrans_pbu_handler(struct tq_elem *tqe)
{
    pthread_rwlock_wrlock(&pmip_lock);
    printf("-------------------------------------\n");
    if (!task_interrupted()) {
    pmip_entry_t *e = tq_data(tqe, pmip_entry_t, tqe);
    pthread_rwlock_wrlock(&e->lock);
    //dbg("Retransmissions counter : %d\n", e->n_rets_counter);
    if (e->n_rets_counter == 0) {
        pthread_rwlock_unlock(&e->lock);
        free_iov_data((struct iovec *) &e->mh_vec, e->iovlen);
        dbg("No PBA received from LMA....\n");
        dbg("Abort Trasmitting the PBU....\n");
        pmip_cache_delete(&e->our_addr, &e->mn_hw_address);
        return;
    } else {
//Decrement the N trasnmissions counter.
        e->n_rets_counter--;
        struct in6_addr_bundle addrs;
        addrs.src = &conf.OurAddress;
        addrs.dst = &conf.LmaAddress;
//sends a PBU
        dbg("Send PBU again....\n");
        pmip_mh_send(&addrs, e->mh_vec, e->iovlen, e->link);
//add a new task for PBU retransmission.
        struct timespec expires;
        clock_gettime(CLOCK_REALTIME, &e->add_time);
        tsadd(e->add_time, conf.NRetransmissionTime, expires);
        add_task_abs(&expires, &e->tqe, pmip_timer_retrans_pbu_handler);
        dbg("PBU Retransmissions timer is triggered again....\n");
        pthread_rwlock_unlock(&e->lock);
    }
    }
    pthread_rwlock_unlock(&pmip_lock);
}
//---------------------------------------------------------------------------------------------------------------------
void pmip_timer_bce_expired_handler(struct tq_elem *tqe)
{
    pthread_rwlock_wrlock(&pmip_lock);
    printf("-------------------------------------\n");
    if (!task_interrupted()) {
    pmip_entry_t *e = tq_data(tqe, pmip_entry_t, tqe);
    pthread_rwlock_wrlock(&e->lock);
    dbg("Retransmissions counter : %d\n", e->n_rets_counter);
    if (e->n_rets_counter == 0) {
        free_iov_data((struct iovec *) &e->mh_vec, e->iovlen);
        if (is_mag()) {
        ++e->seqno_out;
        mag_dereg(e, 1);
        }
//Delete existing route for the deleted MN
        if (is_lma()) {
        lma_dereg(e, 0, 0);
        pmipcache_release_entry(e);
        pmip_bce_delete(e);
        }
        return;
    }
    if (is_mag()) {
        dbg("Send NS for Neighbour Reachability for:%x:%x:%x:%x:%x:%x:%x:%x iif=%d\n", NIP6ADDR(&e->mn_hw_address), e->link);
//Create NS for Reachability test!
        ndisc_send_ns(e->link, &conf.MagAddressIngress, solicited_mcast(&e->mn_suffix), get_mn_addr(e));
    }
    if (is_lma()) {
		lma_dereg(e, 0, 0);
        pmipcache_release_entry(e);
        pmip_bce_delete(e);
    }
    struct timespec expires;
    clock_gettime(CLOCK_REALTIME, &e->add_time);
    tsadd(e->add_time, conf.NRetransmissionTime, expires);
// Add a new task for deletion of entry if No Na is received.
    add_task_abs(&expires, &e->tqe, pmip_timer_bce_expired_handler);
    dbg("Start the Timer for Retransmission/Deletion ....\n");
//Decrements the Retransmissions counter.
    e->n_rets_counter--;
    pthread_rwlock_unlock(&e->lock);
    }
    pthread_rwlock_unlock(&pmip_lock);
}

/**
* Handlers defined for MH and ICMP messages.
**/

/*!
* check if address is solicited multicast
* \param addr
* \return value <> 0 if true
*/
static inline int ipv6_addr_is_solicited_mcast(const struct in6_addr *addr)
{
    return (addr->s6_addr32[0] == htonl(0xff020000)
        && addr->s6_addr32[1] == htonl(0x00000000)
        && addr->s6_addr32[2] == htonl(0x00000001)
        && addr->s6_addr[12] == 0xff);
}

/*!
* check if address is multicast
* \param addr
* \return value <> 0 if true
*/
static inline int ipv6_addr_is_multicast(const struct in6_addr *addr)
{
    return (addr->s6_addr32[0] & htonl(0xFF000000)) == htonl(0xFF000000);
}

/*!
* check if address is linklocal
* \param addr
* \return value <> 0 if true
*/
static inline int ipv6_addr_is_linklocal(const struct in6_addr *addr)
{
    return IN6_IS_ADDR_LINKLOCAL(addr);
}

/*!
* handler called when receiving a router solicitation
*/
//hip
static void pmip_mag_recv_rs(const struct icmp6_hdr *ih, ssize_t len, const struct in6_addr *saddr, const struct in6_addr *daddr, int iif, int hoplimit)
{
 /*   dbg("\n");
    dbg("Router Solicitation received \n");
    printf("-------------------------------------\n");
    dbg("Router Solicitation (RS) Received iif %d\n", iif);
    dbg("Received RS Src Addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(saddr));
    dbg("Received RS Dst addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(daddr));*/
    msg_info_t rs_info;
    bzero(&rs_info, sizeof(rs_info));
    icmp_rs_parse(&rs_info, (struct nd_router_solicit *) ih, saddr, daddr, iif, hoplimit);
    mag_fsm(&rs_info);
}

/*!
* handler called when receiving a proxy binding acknowledgment
*/
static void pmip_mag_recv_pba(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives PBA \n", getcurrenttime(strtime));
/*    printf("=====================================\n");
    dbg("Proxy Binding Acknowledgement (PBA) Received\n");
    dbg("Received PBA Src Addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(in_addrs->src));
    dbg("Received PBA Dst addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(in_addrs->dst));*/
//define the values for calling the parsing function
//call the parsing function
    struct ip6_mh_binding_ack *pba;
//call the fsm function.
    msg_info_t info;
    pba = (struct ip6_mh_binding_ack *) ((void *) mh);
    mh_pba_parse(&info, pba, len, in_addrs, iif);
    mag_fsm(&info);
}

/*!
* handler called when receiving a proxy binding update
*/
static void pmip_lma_recv_pbu(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] LMA receives PBU \n", getcurrenttime(strtime));
/*    printf("=====================================\n");
    dbg("Proxy Binding Update (PBU) Received\n");
    dbg("Received PBU Src Addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(in_addrs->src));
    dbg("Received PBU Dst addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(in_addrs->dst));*/
//define the values for the parsing function
//call the parsing function
    struct ip6_mh_binding_update *pbu = (struct ip6_mh_binding_update *) mh;
//call the fsm function.
    msg_info_t info;
    bzero(&info, sizeof(info));
    mh_pbu_parse(&info, pbu, len, in_addrs, iif);
    //dbg("Call LMA_FSM for process \n");
    lma_fsm(&info);
}

/*!
* handler called when MAG receive a neighbor advertisement
*/
static void pmip_mag_recv_na(const struct icmp6_hdr *ih, ssize_t len, const struct in6_addr *saddr, const struct in6_addr *daddr, int iif, int hoplimit)
{
// define the MN identifier
//struct in6_addr id = in6addr_any;
    struct nd_neighbor_advert *msg = (struct nd_neighbor_advert *) ih;
//Check target is not link local address.
    if (ipv6_addr_is_linklocal(&msg->nd_na_target)) {
    return;
    }
//Check target is not multicast.
    if (ipv6_addr_is_multicast(&msg->nd_na_target)) {
    return;
    }
    if (len - sizeof(struct nd_neighbor_advert) > 0) {
/*    printf("-------------------------------------\n");
    dbg("Neighbor Advertisement (NA) Received\n");
    dbg("Received NA Src Addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(saddr));
    dbg("Received NA Dst addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(daddr));*/
    msg_info_t na_info;
    bzero(&na_info, sizeof(na_info));
    icmp_na_parse(&na_info, (struct nd_neighbor_advert *) ih, saddr, daddr, iif, hoplimit);
    mag_fsm(&na_info);
    }
    return;
}

/******************************************************************************
 * Anh Khuong: add for new features or papers
 *
 ******************************************************************************/
static void pmip_lma_recv_rot(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] LMA receives ROT \n", getcurrenttime(strtime));
//call the parsing function
    struct ip6_mh_rot *rot;
//call the fsm function.
    msg_info_t info;
    rot = (struct rot *) ((void *) mh);
    mh_rot_parse(&info, rot, len, in_addrs, iif);
    lma_fsm(&info);
}

static void pmip_mag_recv_roi(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives ROI \n", getcurrenttime(strtime));
//call the parsing function
    struct ip6_mh_roi *roi;
//call the fsm function.
    msg_info_t info;
    roi = (struct roi *) ((void *) mh);
    mh_roi_parse(&info, roi, len, in_addrs, iif);
    mag_fsm(&info);
}

static void pmip_mag_recv_ros(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives ROS  \n", getcurrenttime(strtime));
//call the parsing function
    struct ip6_mh_ros *ros;
//call the fsm function.
    msg_info_t info;
    ros = (struct ros *) ((void *) mh);
    mh_ros_parse(&info, ros, len, in_addrs, iif);
    mag_fsm(&info);
}

static void pmip_mag_recv_rosa(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives ROSA \n", getcurrenttime(strtime));
}

static void pmip_mag_recv_etm(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives ETM  \n", getcurrenttime(strtime));
	//call the parsing function, call the fsm function.
    struct ip6_mh_etm *etm;
    msg_info_t info;
    etm = (struct etm *) ((void *) mh);
    mh_etm_parse(&info, etm, len, in_addrs, iif);
    mag_fsm(&info);
}

static void pmip_mag_recv_hi(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives HI  \n", getcurrenttime(strtime));
	//call the parsing function, call the fsm function.
    struct ip6_mh_hi *hi;
    msg_info_t info;
    hi = (struct hi *) ((void *) mh);
    mh_hi_parse(&info, hi, len, in_addrs, iif);
    mag_fsm(&info);
}

static void pmip_mag_recv_ha(const struct ip6_mh *mh, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG receives HA \n", getcurrenttime(strtime));

	//call the parsing function
	struct ip6_mh_ha *ha;
	msg_info_t info;
	ha = (struct ha *) ((void *) mh);
	mh_ha_parse(&info, ha, len, in_addrs, iif);
	mag_fsm(&info);
}
/******************************************************************************
 * Anh Khuong: End
 ******************************************************************************/

struct icmp6_handler pmip_mag_rs_handler = {
    .recv = pmip_mag_recv_rs
};

struct mh_handler pmip_mag_pba_handler = {
    .recv = pmip_mag_recv_pba
};

struct mh_handler pmip_lma_pbu_handler = {
    .recv = pmip_lma_recv_pbu
};
struct icmp6_handler pmip_mag_recv_na_handler = {
    .recv = pmip_mag_recv_na
};

// Anh Khuong add
struct mh_handler pmip_mag_roi_handler = {
    .recv = pmip_mag_recv_roi
};

struct mh_handler pmip_mag_ros_handler = {
    .recv = pmip_mag_recv_ros
};

struct mh_handler pmip_mag_rosa_handler = {
    .recv = pmip_mag_recv_rosa
};

struct mh_handler pmip_lma_rot_handler = {
    .recv = pmip_lma_recv_rot
};

struct mh_handler pmip_mag_etm_handler = {
    .recv = pmip_mag_recv_etm
};

struct mh_handler pmip_mag_hi_handler = {
    .recv = pmip_mag_recv_hi
};

struct mh_handler pmip_mag_ha_handler = {
    .recv = pmip_mag_recv_ha
};
// end

