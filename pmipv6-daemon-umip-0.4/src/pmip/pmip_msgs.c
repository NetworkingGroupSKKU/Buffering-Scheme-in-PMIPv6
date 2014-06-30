/*! \file pmip_msgs.c
* \brief creates new options and sends and parses PBU/PBA
* \author OpenAir3 Group
* \date 12th of October 2010
* \version 1.0
* \company Eurecom
* \project OpenAirInterface
* \email: openair3@eurecom.fr
*/
#define PMIP
#define PMIP_MSGS_C
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <errno.h>
//---------------------------------------------------------------------------------------------------------------------
#include "pmip_msgs.h"
//---------------------------------------------------------------------------------------------------------------------
#ifdef ENABLE_VT
#    include "vt.h"
#endif
#include "debug.h"
#include "conf.h"
#include "pmip_mag_proc.h"
#include "pmip_hnp_cache.h"
//---------------------------------------------------------------------------------------------------------------------
/*! \var struct sock mh_sock
\brief Global var declared in mipl component
*/
extern struct sock mh_sock;
/* We can use these safely, since they are only read and never change */
static const uint8_t _pad1[1] = { 0x00 };
static const uint8_t _pad2[2] = { 0x01, 0x00 };
static const uint8_t _pad3[3] = { 0x01, 0x01, 0x00 };
static const uint8_t _pad4[4] = { 0x01, 0x02, 0x00, 0x00 };
static const uint8_t _pad5[5] = { 0x01, 0x03, 0x00, 0x00, 0x00 };
static const uint8_t _pad6[6] = { 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t _pad7[7] = { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
//---------------------------------------------------------------------------------------------------------------------
static int create_opt_pad(struct iovec *iov, int pad)
{
    if (pad == 2)
    iov->iov_base = (void *) _pad2;
    else if (pad == 4)
    iov->iov_base = (void *) _pad4;
    else if (pad == 6)
    iov->iov_base = (void *) _pad6;
    /* Odd pads do not occur with current spec, so test them last */
    else if (pad == 1)
    iov->iov_base = (void *) _pad1;
    else if (pad == 3)
    iov->iov_base = (void *) _pad3;
    else if (pad == 5)
    iov->iov_base = (void *) _pad5;
    else if (pad == 7)
    iov->iov_base = (void *) _pad7;
    iov->iov_len = pad;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
static inline int optpad(int xn, int y, int offset)
{
    return ((y - offset) & (xn - 1));
}
//---------------------------------------------------------------------------------------------------------------------
static int mh_try_pad(const struct iovec *in, struct iovec *out, int count)
{
    size_t len = 0;
    int m, n = 1, pad = 0;
    struct ip6_mh_opt *opt;
    out[0].iov_len = in[0].iov_len;
    out[0].iov_base = in[0].iov_base;
    len += in[0].iov_len;
    for (m = 1; m < count; m++) {
    opt = (struct ip6_mh_opt *) in[m].iov_base;
    switch (opt->ip6mhopt_type) {
    case IP6_MHOPT_BREFRESH:
        pad = optpad(2, 0, len);    /* 2n */
        break;
    case IP6_MHOPT_ALTCOA:
        pad = optpad(8, 6, len);    /* 8n+6 */
        break;
    case IP6_MHOPT_NONCEID:
        pad = optpad(2, 0, len);    /* 2n */
        break;
    case IP6_MHOPT_BAUTH:
        pad = optpad(8, 2, len);    /* 8n+2 */
        break;
    }
    if (pad > 0) {
        create_opt_pad(&out[n++], pad);
        len += pad;
    }
    len += in[m].iov_len;
    out[n].iov_len = in[m].iov_len;
    out[n].iov_base = in[m].iov_base;
    n++;
    }
    if (count == 1) {
    pad = optpad(8, 0, len);
    create_opt_pad(&out[n++], pad);
    }
    return n;
}
//---------------------------------------------------------------------------------------------------------------------
static size_t mh_length(struct iovec *vec, int count)
{
    size_t len = 0;
    int i;
    for (i = 0; i < count; i++) {
    len += vec[i].iov_len;
    }
    return len;
}
//---------------------------------------------------------------------------------------------------------------------
struct in6_addr get_node_id(struct in6_addr *mn_addr)
{
    struct in6_addr result;
    result = in6addr_any;
    memcpy(&result.s6_addr32[2], &mn_addr->s6_addr32[2], sizeof(ip6mnid_t));
    return result;
}
//---------------------------------------------------------------------------------------------------------------------
struct in6_addr get_node_prefix(struct in6_addr *mn_addr)
{
    struct in6_addr result;
    result = in6addr_any;
    memcpy(&result.s6_addr32[0], &mn_addr->s6_addr32[0], PLEN / 8);
    return result;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_home_net_prefix(struct iovec *iov, struct in6_addr *Home_Network_Prefix)
{
    ip6_mh_opt_home_net_prefix_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_home_net_prefix_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_home_net_prefix_t *) iov->iov_base;
    opt->ip6hnp_type = IP6_MHOPT_HOM_NET_PREX;
    opt->ip6hnp_len = 18;   //18 bytes
    opt->ip6hnp_reserved = 0;
    opt->ip6hnp_prefix_len = 128;   //128 bits
    opt->ip6hnp_prefix = *Home_Network_Prefix;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_mn_identifier(struct iovec *iov, int flags, ip6mnid_t * MN_ID)
{
    ip6_mh_opt_mn_identifier_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_mn_identifier_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_mn_identifier_t *) iov->iov_base;
    opt->ip6mnid_type = IP6_MHOPT_MOB_IDENTIFIER;
    opt->ip6mnid_len = 10;  //set to 10 bytes.
    opt->ip6mnid_flags = flags;
    opt->mn_identifier = *MN_ID;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_time_stamp(struct iovec *iov, ip6ts_t * Timestamp)
{
    ip6_mh_opt_time_stamp_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_time_stamp_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_time_stamp_t *) iov->iov_base;
    opt->ip6mots_type = IP6_MHOPT_TIME_STAMP;
    opt->ip6mots_len = 8;   // set to 8 bytes.
    opt->time_stamp = *Timestamp;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_link_local_add(struct iovec *iov, struct in6_addr *LinkLocal)
{
    ip6_mh_link_local_add_t *opt;
    size_t optlen = sizeof(ip6_mh_link_local_add_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_link_local_add_t *) iov->iov_base;
    opt->ip6link_type = IP6_MHOPT_LINK_ADDR;
    opt->ip6link_len = 16;  //set to 16 bytes
    opt->ip6link_addr = *LinkLocal;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_dst_mn_addr(struct iovec *iov, struct in6_addr *dst_mn_addr)
{
    ip6_mh_opt_dst_mn_addr_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_dst_mn_addr_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_dst_mn_addr_t *) iov->iov_base;
    opt->ip6dma_type = IP6_MHOPT_DST_MN_ADDR;
    opt->ip6dma_len = 16;
    opt->dst_mn_addr = *dst_mn_addr;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_serv_mag_addr(struct iovec *iov, struct in6_addr *Serv_MAG_addr)
{
    ip6_mh_opt_serv_mag_addr_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_serv_mag_addr_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_serv_mag_addr_t *) iov->iov_base;
    opt->ip6sma_type = IP6_MHOPT_SERV_MAG_ADDR;
    opt->ip6sma_len = 16;   //16 bytes
    opt->serv_mag_addr = *Serv_MAG_addr;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_serv_lma_addr(struct iovec *iov, struct in6_addr *serv_lma_addr)
{
    ip6_mh_opt_serv_lma_addr_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_serv_lma_addr_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_serv_lma_addr_t *) iov->iov_base;
    opt->ip6sla_type = IP6_MHOPT_SERV_LMA_ADDR;
    opt->ip6sla_len = 16;   //16 bytes
    opt->serv_lma_addr = *serv_lma_addr;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_src_mn_addr(struct iovec *iov, struct in6_addr *src_mn_addr)
{
    struct ip6_mh_opt_src_mn_addr *opt;
    size_t optlen = sizeof(struct ip6_mh_opt_src_mn_addr);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (struct ip6_mh_opt_src_mn_addr *) iov->iov_base;
    opt->ip6sma_type = IP6_MHOPT_SRC_MN_ADDR;
    opt->ip6sma_len = 16;   //16 bytes
    opt->src_mn_addr = *src_mn_addr;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_create_opt_src_mag_addr(struct iovec *iov, struct in6_addr *src_mag_addr)
{
    ip6_mh_opt_src_mag_addr_t *opt;
    size_t optlen = sizeof(ip6_mh_opt_src_mag_addr_t);
    iov->iov_base = malloc(optlen);
    iov->iov_len = optlen;
    if (iov->iov_base == NULL)
    return -ENOMEM;
    opt = (ip6_mh_opt_src_mag_addr_t *) iov->iov_base;
    opt->ip6sma_type = IP6_MHOPT_SRC_MAG_ADDR;
    opt->ip6sma_len = 16;   //16 bytes
    opt->src_mag_addr = *src_mag_addr;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_pbu_parse(msg_info_t * info, struct ip6_mh_binding_update *pbu, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
    static struct mh_options mh_opts;
    ip6_mh_opt_home_net_prefix_t *home_net_prefix;
    ip6_mh_opt_mn_identifier_t *mh_id_opt;
    ip6_mh_opt_time_stamp_t *time_stamp_opt;
    ip6_mh_link_local_add_t *link_local;
    bzero(&mh_opts, sizeof(mh_opts));
    info->src = *in_addrs->src;
    info->dst = *in_addrs->dst;
    info->iif = iif;
    info->addrs.src = &info->src;
    info->addrs.dst = &info->dst;
    if (len < sizeof(struct ip6_mh_binding_update)
    || mh_opt_parse(&pbu->ip6mhbu_hdr, len, sizeof(struct ip6_mh_binding_update), &mh_opts) < 0)
    return 0;
    info->PBU_flags = ntohs(pbu->ip6mhbu_flags);
    info->lifetime.tv_sec = (ntohs(pbu->ip6mhbu_lifetime) << 2);
    info->seqno = ntohs(pbu->ip6mhbu_seqno);
    dbg("Serving MAG Address: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src));
    dbg("Our Address: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->dst));
    dbg("PBU Lifetime: %d (%d s)\n", pbu->ip6mhbu_lifetime, info->lifetime.tv_sec);
    dbg("PBU Sequence No: %d\n", info->seqno);
    home_net_prefix = mh_opt(&pbu->ip6mhbu_hdr, &mh_opts, IP6_MHOPT_HOM_NET_PREX);
    if (home_net_prefix)    //hip   not handling HN prefix in pbu rx since it is already handled.
    {
//copy
    info->mn_prefix = home_net_prefix->ip6hnp_prefix;
    dbg("MN Home Network Prefix: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_prefix));
    }
    mh_id_opt = mh_opt(&pbu->ip6mhbu_hdr, &mh_opts, IP6_MHOPT_MOB_IDENTIFIER);
    if (mh_id_opt) {
//copy
    info->mn_iid = in6addr_any;
    memcpy(&info->mn_iid.s6_addr32[2], &mh_id_opt->mn_identifier, sizeof(ip6mnid_t));
    dbg("MN IID: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_iid));
    }
    time_stamp_opt = mh_opt(&pbu->ip6mhbu_hdr, &mh_opts, IP6_MHOPT_TIME_STAMP);
    if (time_stamp_opt) {
//copy
//info->timestamp = time_stamp_opt->time_stamp;
    info->timestamp.first = time_stamp_opt->time_stamp.first;
    info->timestamp.second = time_stamp_opt->time_stamp.second;
    }
    link_local = mh_opt(&pbu->ip6mhbu_hdr, &mh_opts, IP6_MHOPT_LINK_ADDR);
    if (link_local) {
//copy
    info->mn_link_local_addr = link_local->ip6link_addr;
    dbg("MN Link Local Address: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_link_local_addr));
    }
    info->msg_event = hasPBU;
    dbg("FSM Message Event: %d\n", info->msg_event);
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_pba_parse(msg_info_t * info, struct ip6_mh_binding_ack *pba, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
    static struct mh_options mh_opts;
    ip6_mh_opt_home_net_prefix_t *home_net_prefix;
    ip6_mh_opt_mn_identifier_t *mh_id_opt;
    ip6_mh_opt_time_stamp_t *time_stamp_opt;
    ip6_mh_link_local_add_t *link_local;
    bzero(&mh_opts, sizeof(mh_opts));
    info->src = *in_addrs->src;
    info->dst = *in_addrs->dst;
    info->iif = iif;
    info->addrs.src = &info->src;
    info->addrs.dst = &info->dst;
    if (len < sizeof(struct ip6_mh_binding_ack)
    || mh_opt_parse(&pba->ip6mhba_hdr, len, sizeof(struct ip6_mh_binding_ack), &mh_opts) < 0)
    return 0;
    home_net_prefix = mh_opt(&pba->ip6mhba_hdr, &mh_opts, IP6_MHOPT_HOM_NET_PREX);
    if (home_net_prefix) {
    info->mn_prefix = home_net_prefix->ip6hnp_prefix;
    dbg("MN Home Network Prefix: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_prefix));
    }
    mh_id_opt = mh_opt(&pba->ip6mhba_hdr, &mh_opts, IP6_MHOPT_MOB_IDENTIFIER);
    if (mh_id_opt) {
//copy
    info->mn_iid = in6addr_any;
    memcpy(&info->mn_iid.s6_addr32[2], &mh_id_opt->mn_identifier, sizeof(ip6mnid_t));
    dbg("MN IID: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_iid));
    }
    time_stamp_opt = mh_opt(&pba->ip6mhba_hdr, &mh_opts, IP6_MHOPT_TIME_STAMP);
    if (time_stamp_opt) {
//copy
    memcpy(&info->timestamp, &time_stamp_opt->time_stamp, sizeof(ip6ts_t));
    }
    link_local = mh_opt(&pba->ip6mhba_hdr, &mh_opts, IP6_MHOPT_LINK_ADDR);
    if (link_local) {
//copy
    info->mn_link_local_addr = link_local->ip6link_addr;
    dbg("MN Link Local Address: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_link_local_addr));
    }
    info->seqno = ntohs(pba->ip6mhba_seqno);
    info->PBA_flags = ntohs(pba->ip6mhba_flags);
    info->lifetime.tv_sec = ntohs(pba->ip6mhba_lifetime) << 2;
    dbg("Proxy Binding Ack Lifetime: %d (%d s)\n", pba->ip6mhba_lifetime, info->lifetime.tv_sec);
    info->msg_event = hasPBA;
    /* AnhKhuong: added */
    if (pba->ip6mhba_status == IP6_MH_BAS_IHR_MSG)
    	info->msg_event = hasIHR;

    dbg("FSM Message Event: %d\n", info->msg_event);
    return 0;
}

//---------------------------------------------------------------------------------------------------------------------
int icmp_rs_parse(msg_info_t * info, struct nd_router_solicit *rs, const struct in6_addr *saddr, const struct in6_addr *daddr, int iif, int hoplimit)
{
    bzero(info, sizeof(msg_info_t));
//info->ns_target = ns->nd_ns_target;
    info->hoplimit = hoplimit;
    info->msg_event = hasRS;
    info->src = *saddr;
    info->dst = *daddr;
    info->iif = iif;
    info->addrs.src = &info->src;
    info->addrs.dst = &info->dst;
//Calculated fields
    info->mn_iid = get_node_id(&info->src);
    dbg("MN IID: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_iid));
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int icmp_na_parse(msg_info_t * info, struct nd_neighbor_advert *na, const struct in6_addr *saddr, const struct in6_addr *daddr, int iif, int hoplimit)
{
    bzero(info, sizeof(msg_info_t));
    info->na_target = na->nd_na_target;
    info->hoplimit = hoplimit;
    info->msg_event = hasNA;
    info->src = *saddr;
    info->dst = *daddr;
    info->iif = iif;
    info->addrs.src = &info->src;
    info->addrs.dst = &info->dst;
//Calculated fields
    info->mn_iid = get_node_id(&info->na_target);
    info->mn_addr = info->na_target;
    info->mn_prefix = get_node_prefix(&info->na_target);
    dbg("NA Target: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&na->nd_na_target));
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int pmip_mh_send(const struct in6_addr_bundle *addrs, const struct iovec *mh_vec, int iovlen, int oif)
{
    struct sockaddr_in6 daddr;
    struct iovec iov[2 * (IP6_MHOPT_MAX + 1)];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int cmsglen;
    struct in6_pktinfo pinfo;
    int ret = 0, on = 1;
    struct ip6_mh *mh;
    int iov_count;
    iov_count = mh_try_pad(mh_vec, iov, iovlen);
    mh = (struct ip6_mh *) iov[0].iov_base;
    mh->ip6mh_hdrlen = (mh_length(iov, iov_count) >> 3) - 1;
    dbg("Sending MH type %d\n" "from %x:%x:%x:%x:%x:%x:%x:%x\n" "to %x:%x:%x:%x:%x:%x:%x:%x\n", mh->ip6mh_type, NIP6ADDR(addrs->src), NIP6ADDR(addrs->dst));
    memset(&daddr, 0, sizeof(struct sockaddr_in6));
    daddr.sin6_family = AF_INET6;
    daddr.sin6_addr = *addrs->dst;
    daddr.sin6_port = htons(IPPROTO_MH);
    memset(&pinfo, 0, sizeof(pinfo));
    pinfo.ipi6_addr = *addrs->src;
    pinfo.ipi6_ifindex = oif;
    cmsglen = CMSG_SPACE(sizeof(pinfo));
    cmsg = malloc(cmsglen);
    if (cmsg == NULL) {
    dbg("malloc failed\n");
    return -ENOMEM;
    }
    memset(cmsg, 0, cmsglen);
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsglen;
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_count;
    msg.msg_name = (void *) &daddr;
    msg.msg_namelen = sizeof(daddr);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(pinfo));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    memcpy(CMSG_DATA(cmsg), &pinfo, sizeof(pinfo));
    pthread_mutex_lock(&mh_sock.send_mutex);
    setsockopt(mh_sock.fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(int));
    ret = sendmsg(mh_sock.fd, &msg, 0);
    if (ret < 0)
    dbg("sendmsg: %s\n", strerror(errno));
    pthread_mutex_unlock(&mh_sock.send_mutex);
    free(msg.msg_control);
    dbg("MH is sent....\n");
    return ret;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_send_pbu(const struct in6_addr_bundle *addrs, pmip_entry_t * bce, struct timespec *lifetime, int oif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] MAG Send PBU \n", getcurrenttime(strtime));
    int iovlen = 1;
    struct ip6_mh_binding_update *pbu;
    static struct iovec mh_vec[7];
    bzero(mh_vec, sizeof(mh_vec));
    pbu = mh_create(&mh_vec[0], IP6_MH_TYPE_BU);
    if (!pbu) {
    dbg("mh_create() failed\n");
    return -ENOMEM;
    }
    pbu->ip6mhbu_seqno = htons(bce->seqno_out);
    pbu->ip6mhbu_flags = htons(bce->PBU_flags);
    pbu->ip6mhbu_lifetime = htons(lifetime->tv_sec >> 2);
    dbg("Create PBU with lifetime = %d (%d s)\n", pbu->ip6mhbu_lifetime, conf.PBULifeTime);
    ip6mnid_t mn_id;
    memcpy(&mn_id, &bce->mn_suffix.s6_addr32[2], sizeof(ip6mnid_t));
/*
* create the options in this order.
* home network prefix.
* mobile Identifier.
* padN with len=0
* timestamp.
* padN with len =4.
* link local address.
*/
    dbg("Create PBU options...\n");
    mh_create_opt_home_net_prefix(&mh_vec[iovlen++], &bce->mn_prefix);  //removed HN prefix from PBU hip
    uint16_t p_flag = htons(IP6_MH_MNID);
    mh_create_opt_mn_identifier(&mh_vec[iovlen++], p_flag, &mn_id);
//create_opt_pad(&mh_vec[iovlen++], 2); //2 byte PadN option header + 0 bytes
    mh_create_opt_time_stamp(&mh_vec[iovlen++], &bce->timestamp);
//create_opt_pad(&mh_vec[iovlen++], 6); //2 byte PadN option header + 4 bytes
    mh_create_opt_link_local_add(&mh_vec[iovlen++], &bce->mn_link_local_addr);
//calculate the length of the message.
    pbu->ip6mhbu_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send PBU....\n");
    pmip_mh_send(addrs, mh_vec, iovlen, oif);
    dbg("Copy PBU message into TEMP PMIP entry iovec....\n");
//copy the PBU message into the mh_vector for the entry for future retransmissions.
    memcpy(bce->mh_vec, mh_vec, sizeof(mh_vec));
    bce->iovlen = iovlen;
//free_iov_data(mh_vec, iovlen); --> Don't free, keep for retransmission of PBU
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mh_send_pba(const struct in6_addr_bundle *addrs, pmip_entry_t * bce, struct timespec *lifetime, int oif)
{
	/* Anh Khuong add */
	char strtime[512];
	printf("********[SIM %s] LMA Send PBA \n", getcurrenttime(strtime));
    int iovlen = 1;
    struct ip6_mh_binding_ack *pba;
    static struct iovec mh_vec[7];
    bzero(mh_vec, sizeof(mh_vec));
    pba = mh_create(&mh_vec[0], IP6_MH_TYPE_BACK);
    if (!pba) {
    dbg("mh_create() failed\n");
    return -ENOMEM;
    }
    pba->ip6mhba_status = bce->status;
    pba->ip6mhba_flags = htons(bce->PBA_flags); //check since it is only one byte!!
    pba->ip6mhba_seqno = htons(bce->seqno_in);
    pba->ip6mhba_lifetime = htons(lifetime->tv_sec >> 2);
/*
* create the options in this order.
* home network prefix.
* mobile Identifier.
* padN with len=0
* timestamp.
* padN with len =4.
* link local address.
*/
    dbg("Create PBA options....\n");
    mh_create_opt_home_net_prefix(&mh_vec[iovlen++], &bce->mn_prefix);
    uint16_t p_flag = htons(IP6_MH_MNID);
    ip6mnid_t mn_id;
    memcpy(&mn_id, &bce->mn_suffix.s6_addr32[2], sizeof(ip6mnid_t));
    mh_create_opt_mn_identifier(&mh_vec[iovlen++], p_flag, &mn_id);
//create_opt_pad(&mh_vec[iovlen++], 2); //2 byte PadN option header + 0 bytes
    mh_create_opt_time_stamp(&mh_vec[iovlen++], &bce->timestamp);
//create_opt_pad(&mh_vec[iovlen++], 6); //2 byte PadN option header + 4 bytes
    mh_create_opt_link_local_add(&mh_vec[iovlen++], &bce->mn_link_local_addr);
//calculate the length of the message.
    pba->ip6mhba_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send PBA...\n");
    pmip_mh_send(addrs, mh_vec, iovlen, oif);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

/*************************************************************************************************
 * Specific functions for new features or papers
 *
 *************************************************************************************************/
int mh_rot_parse(msg_info_t * info, struct ip6_mh_rot *rot, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	static struct mh_options mh_opts;
	ip6_mh_opt_src_mag_addr_t *mag_addr_opt;
	ip6_mh_opt_src_mn_addr_t *mn_saddr_opt;
	ip6_mh_opt_dst_mn_addr_t *mn_daddr_opt;

	bzero(&mh_opts, sizeof(mh_opts));
	info->src = *in_addrs->src;
	info->dst = *in_addrs->dst;
	info->iif = iif;
	info->addrs.src = &info->src;
	info->addrs.dst = &info->dst;

	 if (len < sizeof(struct ip6_mh_rot)
		|| mh_opt_parse(&rot->ip6mh_hdr, len, sizeof(struct ip6_mh_rot), &mh_opts) < 0)
		return 0;
	 mn_saddr_opt = mh_opt(&rot->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MN_ADDR);
	 if (mn_saddr_opt) {
		 info->src_mn_addr = mn_saddr_opt->src_mn_addr;
	 }
	 mn_daddr_opt = mh_opt(&rot->ip6mh_hdr, &mh_opts, IP6_MHOPT_DST_MN_ADDR);
	 if (mn_daddr_opt) {
		 info->mn_addr = mn_daddr_opt->dst_mn_addr;
	 }
	 mag_addr_opt = mh_opt(&rot->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MAG_ADDR);
	 if (mag_addr_opt) {
		 info->src_mag_addr = mag_addr_opt->src_mag_addr;
	 }
	 dbg("*** SMN addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mn_addr));
	 dbg("*** DMN addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_addr));
	 dbg("*** MAG addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mag_addr));
	 info->msg_event = hasROT;
	 return 0;
}

int mh_roi_parse(msg_info_t * info, struct ip6_mh_roi *roi, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	static struct mh_options mh_opts;
	ip6_mh_opt_src_mag_addr_t *mag_addr_opt;
	ip6_mh_opt_src_mn_addr_t *mn_saddr_opt;
	ip6_mh_opt_dst_mn_addr_t *mn_daddr_opt;

	bzero(&mh_opts, sizeof(mh_opts));
	info->src = *in_addrs->src;
	info->dst = *in_addrs->dst;
	info->iif = iif;
	info->addrs.src = &info->src;
	info->addrs.dst = &info->dst;

	 if (len < sizeof(struct ip6_mh_roi)
	    || mh_opt_parse(&roi->ip6mh_hdr, len, sizeof(struct ip6_mh_roi), &mh_opts) < 0)
	    return 0;
	 mn_saddr_opt = mh_opt(&roi->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MN_ADDR);
	 if (mn_saddr_opt) {
		 info->src_mn_addr = mn_saddr_opt->src_mn_addr;
	 }
	 mn_daddr_opt = mh_opt(&roi->ip6mh_hdr, &mh_opts, IP6_MHOPT_DST_MN_ADDR);
	 if (mn_daddr_opt) {
		 info->mn_addr = mn_daddr_opt->dst_mn_addr;
	 }
	 mag_addr_opt = mh_opt(&roi->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MAG_ADDR);
	 if (mag_addr_opt) {
		 info->src_mag_addr = mag_addr_opt->src_mag_addr;
	 }
	 dbg("*** SMN addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mn_addr));
	 dbg("*** DMN addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_addr));
	 dbg("*** MAG addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mag_addr));
	 info->msg_event = hasROI;
	 return 0;
}

int mh_ros_parse(msg_info_t * info, struct ip6_mh_ros *ros, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	static struct mh_options mh_opts;
	ip6_mh_opt_src_mn_addr_t *mn_addr_opt;

	bzero(&mh_opts, sizeof(mh_opts));
	info->src = *in_addrs->src;
	info->dst = *in_addrs->dst;
	info->iif = iif;
	info->addrs.src = &info->src;
	info->addrs.dst = &info->dst;

	 if (len < sizeof(struct ip6_mh_ros)
	    || mh_opt_parse(&ros->ip6mh_hdr, len, sizeof(struct ip6_mh_ros), &mh_opts) < 0)
	    return 0;

	 info->src_mag_addr = info->src;
	 mn_addr_opt = mh_opt(&ros->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MN_ADDR);
	 if (mn_addr_opt) {
		 info->src_mn_addr = mn_addr_opt->src_mn_addr;
	 }

	 dbg("*** SMN addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mn_addr));
	 dbg("*** MAG addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mag_addr));
	 info->msg_event = hasROS;
	 return 0;
}

int mh_etm_parse(msg_info_t * info, struct ip6_mh_etm *etm, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	static struct mh_options mh_opts;
	ip6_mh_opt_src_mag_addr_t *mag_addr_opt;
	ip6_mh_opt_src_mn_addr_t *mn_addr_opt;

	bzero(&mh_opts, sizeof(mh_opts));
	info->src = *in_addrs->src;
	info->dst = *in_addrs->dst;
	info->iif = iif;
	info->addrs.src = &info->src;
	info->addrs.dst = &info->dst;

	 if (len < sizeof(struct ip6_mh_etm)
	    || mh_opt_parse(&etm->ip6mh_hdr, len, sizeof(struct ip6_mh_etm), &mh_opts) < 0)
	    return 0;

	 mn_addr_opt = mh_opt(&etm->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MN_ADDR);
	 if (mn_addr_opt) {
		 info->src_mn_addr = mn_addr_opt->src_mn_addr;
	 }

	 mag_addr_opt = mh_opt(&etm->ip6mh_hdr, &mh_opts, IP6_MHOPT_SRC_MAG_ADDR);
	 if (mag_addr_opt) {
		 info->src_mag_addr = mag_addr_opt->src_mag_addr;
	 }
	 dbg("*** MN addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mn_addr));
	 dbg("*** MAG addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mag_addr));


	 info->msg_event = hasETM;
	 return 0;
}

int mh_hi_parse(msg_info_t * info, struct ip6_mh_hi *hi, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	static struct mh_options mh_opts;
	ip6_mh_opt_dst_mn_addr_t *mn_addr_opt;

	bzero(&mh_opts, sizeof(mh_opts));
	info->src = *in_addrs->src;
	info->dst = *in_addrs->dst;
	info->iif = iif;
	info->addrs.src = &info->src;
	info->addrs.dst = &info->dst;

	 if (len < sizeof(struct ip6_mh_hi)
	    || mh_opt_parse(&hi->ip6mh_hdr, len, sizeof(struct ip6_mh_hi), &mh_opts) < 0)
	    return 0;

	 mn_addr_opt = mh_opt(&hi->ip6mh_hdr, &mh_opts, IP6_MHOPT_DST_MN_ADDR);
	 if (mn_addr_opt) {
		 info->mn_addr = mn_addr_opt->dst_mn_addr;
	 }

	 dbg("*** mn addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_addr));
	 info->msg_event = hasHI;
	 return 0;
}

int mh_ha_parse(msg_info_t * info, struct ip6_mh_ha *ha, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
{
	static struct mh_options mh_opts;
	ip6_mh_opt_dst_mn_addr_t *mn_addr_opt;

	bzero(&mh_opts, sizeof(mh_opts));
	info->src = *in_addrs->src;
	info->dst = *in_addrs->dst;
	info->iif = iif;
	info->addrs.src = &info->src;
	info->addrs.dst = &info->dst;

	 if (len < sizeof(struct ip6_mh_ha)
		|| mh_opt_parse(&ha->ip6mh_hdr, len, sizeof(struct ip6_mh_ha), &mh_opts) < 0)
		return 0;

	 mn_addr_opt = mh_opt(&ha->ip6mh_hdr, &mh_opts, IP6_MHOPT_DST_MN_ADDR);
	 if (mn_addr_opt) {
		 info->mn_addr = mn_addr_opt->dst_mn_addr;
	 }
	 info->mn_iid = info->mn_addr;

	dbg("*** MN addr: %x:%x:%x:%x:%x:%x:%x:%x, status = %d \n", NIP6ADDR(&info->mn_addr), ha->ip6mhha_status);
	info->msg_event = hasHA;

	// pMAG clean up pmip_tunnel and bce if status = 123
	// nMAG replies HA message with status=0 after receiving HI,
	// nMAG sends HA message again with status=123 when receiving PBA from LMA (finish FPMIP scheme)
	if (ha->ip6mhha_status == 123) {
		info->msg_event = hasHAC;
		dbg("Event is hasHAC \n");
	}
	return 0;
}

int mh_send_ihr(pmip_entry_t * bce, int oif)
{
    int iovlen = 1;
    struct in6_addr_bundle addrs;
    struct ip6_mh_binding_ack *pba;
    static struct iovec mh_vec[7];
    bzero(mh_vec, sizeof(mh_vec));
    pba = mh_create(&mh_vec[0], IP6_MH_TYPE_BACK);
    if (!pba) {
    dbg("mh_create() failed\n");
    return -ENOMEM;
    }
    pba->ip6mhba_status = IP6_MH_BAS_IHR_MSG;
    pba->ip6mhba_flags = htons(bce->PBA_flags); //check since it is only one byte!!
    pba->ip6mhba_seqno = htons(bce->seqno_in);
    pba->ip6mhba_lifetime = htons(conf.PBALifeTime.tv_sec >> 2);
/*
* create the options in this order.
* home network prefix.
* mobile Identifier.
* padN with len=0
* timestamp.
* padN with len =4.
* link local address.
*/
    dbg("Create PBA options....\n");
    mh_create_opt_home_net_prefix(&mh_vec[iovlen++], &bce->mn_prefix);
    uint16_t p_flag = htons(IP6_MH_MNID);
    ip6mnid_t mn_id;
    memcpy(&mn_id, &bce->mn_suffix.s6_addr32[2], sizeof(ip6mnid_t));
    mh_create_opt_mn_identifier(&mh_vec[iovlen++], p_flag, &mn_id);
//create_opt_pad(&mh_vec[iovlen++], 2); //2 byte PadN option header + 0 bytes
    mh_create_opt_time_stamp(&mh_vec[iovlen++], &bce->timestamp);
//create_opt_pad(&mh_vec[iovlen++], 6); //2 byte PadN option header + 4 bytes
    mh_create_opt_link_local_add(&mh_vec[iovlen++], &bce->mn_link_local_addr);
//calculate the length of the message.
    pba->ip6mhba_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);

    /* send IHR to nMAGs */
	addrs.src = &conf.OurAddress;
	int i;
	for (i=0; i<mags_info.size; i++) {
		if (mags_info.has_mn[i] == 0) {
			if (!IN6_ARE_ADDR_EQUAL(&mags_info.mags_addr[i], &bce->mn_serv_mag_addr)) {
				addrs.dst = &mags_info.mags_addr[i];
				pmip_mh_send(&addrs, mh_vec, iovlen, oif);
				mags_info.has_mn[i] = 1;
				mags_info.nhas_mn++;
			}
			#ifdef CACHE_RADIUS
			else {
				mags_info.nhas_mn++;
				mags_info.has_mn[i] = 1;
			}
			#endif
		}
	}

    free_iov_data(mh_vec, iovlen);
    return 0;
}

// mn_saddr, mag_saddr belong to lmaself. mn_daddr belong to dst_addr which is other LMA
int mh_send_rot (struct in6_addr *mn_saddr, struct in6_addr *mn_daddr, struct in6_addr *mag_saddr, struct in6_addr * dst_addr)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_rot *rot;
    static struct iovec mh_vec[4];
    bzero(mh_vec, sizeof(mh_vec));
    rot = mh_create(&mh_vec[0], IP6_MH_TYPE_ROT);
    if (!rot) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
    rot->ip6mhrot_seqno = 0;
    rot->ip6mhrot_flags = 0;
    rot->ip6mhrot_lifetime = htons(conf.PBALifeTime.tv_sec >> 2);
/*
* create the options in this order.
* mn addr
* mag addr
*/
    dbg("Create ROT options....\n");
    mh_create_opt_src_mn_addr(&mh_vec[iovlen++], mn_saddr);
    mh_create_opt_dst_mn_addr(&mh_vec[iovlen++], mn_daddr);
    mh_create_opt_src_mag_addr(&mh_vec[iovlen++], mag_saddr);

//calculate the length of the message.
    rot->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send ROT...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

// mn_saddr belong to mag_saddr, mn_daddr belong to dst_addr
int mh_send_roi (struct in6_addr *mn_saddr, struct in6_addr *mn_daddr, struct in6_addr *mag_saddr, struct in6_addr * dst_addr)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_roi *roi;
    static struct iovec mh_vec[4];
    bzero(mh_vec, sizeof(mh_vec));
    roi = mh_create(&mh_vec[0], IP6_MH_TYPE_ROI);
    if (!roi) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
    roi->ip6mhroi_seqno = 0;
    roi->ip6mhroi_flags = 0;
    roi->ip6mhroi_lifetime = htons(conf.PBALifeTime.tv_sec >> 2);
/*
* create the options in this order.
* mn addr
* mag addr
*/
    dbg("Create ROI options....\n");
    mh_create_opt_src_mn_addr(&mh_vec[iovlen++], mn_saddr);
    mh_create_opt_dst_mn_addr(&mh_vec[iovlen++], mn_daddr);
    mh_create_opt_src_mag_addr(&mh_vec[iovlen++], mag_saddr);

//calculate the length of the message.
    roi->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send ROI...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

//mn_addr is belong to our address of MAG, dst_addr is other MAG addr
int mh_send_ros (struct in6_addr *mn_addr, struct in6_addr * dst_addr)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_ros *ros;
    static struct iovec mh_vec[2];
    bzero(mh_vec, sizeof(mh_vec));
    ros = mh_create(&mh_vec[0], IP6_MH_TYPE_ROS);
    if (!ros) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
    ros->ip6mhros_seqno = 0;
    ros->ip6mhros_flags = 0;
    ros->ip6mhros_lifetime = htons(conf.PBALifeTime.tv_sec >> 2);
/*
* create the options in this order.
* mn addr
* mag addr
*/
    dbg("Create ROS options....\n");
    mh_create_opt_src_mn_addr(&mh_vec[iovlen++], mn_addr);

//calculate the length of the message.
    ros->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send ROS...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

int mh_send_rosa (struct in6_addr * dst_addr)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_rosa *rosa;
    static struct iovec mh_vec[1];
    bzero(mh_vec, sizeof(mh_vec));
    rosa = mh_create(&mh_vec[0], IP6_MH_TYPE_ROSA);
    if (!rosa) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
    rosa->ip6mhrosa_seqno = 0;
    rosa->ip6mhrosa_flags = 0;
    rosa->ip6mhrosa_lifetime = htons(conf.PBALifeTime.tv_sec >> 2);

//calculate the length of the message.
    rosa->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send ROSA...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

int mh_send_etm (struct in6_addr *mn_addr, struct in6_addr *nmag_addr, struct in6_addr * dst_addr)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_etm *etm;
    static struct iovec mh_vec[3];
    bzero(mh_vec, sizeof(mh_vec));
    etm = mh_create(&mh_vec[0], IP6_MH_TYPE_ETM);
    if (!etm) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
/*
* create the options in this order.
* mn addr
*/
    mh_create_opt_src_mn_addr(&mh_vec[iovlen++], mn_addr);
    mh_create_opt_src_mag_addr(&mh_vec[iovlen++], nmag_addr);

//calculate the length of the message.
    etm->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send ETM message...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

int mh_send_hi (struct in6_addr *mn_addr, struct in6_addr * dst_addr)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_hi *hi;
    static struct iovec mh_vec[2];
    bzero(mh_vec, sizeof(mh_vec));
    hi = mh_create(&mh_vec[0], IP6_MH_TYPE_HI);
    if (!hi) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
/*
* create the options in this order.
* mn addr
*/
    mh_create_opt_dst_mn_addr(&mh_vec[iovlen++], mn_addr);

//calculate the length of the message.
    hi->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send HI message...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}

int mh_send_ha (struct in6_addr * mn_addr, struct in6_addr * dst_addr, int status)
{
	/* Anh Khuong add */
	struct in6_addr_bundle addrs;
    int iovlen = 1;
    struct ip6_mh_ha *ha;
    static struct iovec mh_vec[2];
    bzero(mh_vec, sizeof(mh_vec));
    ha = mh_create(&mh_vec[0], IP6_MH_TYPE_HA);
    if (!ha) {
    	dbg("mh_create() failed\n");
    	return -ENOMEM;
    }
    ha->ip6mhha_status = status;

    /*
    * create the options in this order.
    * mn addr
    */
    mh_create_opt_dst_mn_addr(&mh_vec[iovlen++], mn_addr);

//calculate the length of the message.
    ha->ip6mh_hdr.ip6mh_hdrlen = mh_length(mh_vec, iovlen);
    dbg("Send HA message...\n");
    addrs.src = &conf.OurAddress;
    addrs.dst = dst_addr;
    pmip_mh_send(&addrs, mh_vec, iovlen, 0);
    free_iov_data(mh_vec, iovlen);
    return 0;
}
