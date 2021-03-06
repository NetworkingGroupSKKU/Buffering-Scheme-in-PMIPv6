/*! \file pmip_msgs.h
* \brief
* \author OpenAir3 Group
* \date 12th of October 2010
* \version 1.0
* \company Eurecom
* \project OpenAirInterface
* \email: openair3@eurecom.fr
*/

/** \defgroup MESSAGES MESSAGES
 * \ingroup PMIP6D
 *  PMIP Messages (MSGs)
 *  @{
 */

#ifndef __PMIP_MSGS_H__
#    define __PMIP_MSGS_H__
//-----------------------------------------------------------------------------
#    ifdef PMIP_MSGS_C
#        define private_pmip_msgs(x) x
#        define protected_pmip_msgs(x) x
#        define public_pmip_msgs(x) x
#    else
#        ifdef PMIP
#            define private_pmip_msgs(x)
#            define protected_pmip_msgs(x) extern x
#            define public_pmip_msgs(x) extern x
#        else
#            define private_pmip_msgs(x)
#            define protected_pmip_msgs(x)
#            define public_pmip_msgs(x) extern x
#        endif
#    endif
//-----------------------------------------------------------------------------
#include <netinet/ip6mh.h>
#include "icmp6.h"
#include "mh.h"
//-----------------------------------------------------------------------------
#include "pmip_cache.h"
//-PROTOTYPES----------------------------------------------------------------------------
/*! \fn struct in6_addr get_node_id(struct in6_addr *)
* \brief Translate a IPv6 address into a mobile interface identifier
* \param[in]  mn_addr The mobile address
* \return   The mobile interface identifier in a struct in6_addr.
*/
private_pmip_msgs(struct in6_addr get_node_id(struct in6_addr *mn_addr);)
/*! \fn struct in6_addr get_node_prefix(struct in6_addr *)
* \brief Retrieve the prefix of a IPv6 address
* \param[in]  mn_addr A mobile IPv6 address
* \return   The prefix.
* \note The prefix len is 64 bits
*/
protected_pmip_msgs(struct in6_addr get_node_prefix(struct in6_addr *mn_addr);)
/*! \fn int mh_create_opt_home_net_prefix(struct iovec *, struct in6_addr *)
* \brief Creates the Home Network Prefix option.
* \param[in,out]  iov Storage
* \param[in]  Home_Network_Prefix Option home network prefix value
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_home_net_prefix(struct iovec *iov, struct in6_addr *Home_Network_Prefix);)

/*! \fn int mh_create_opt_mn_identifier(struct iovec *, int, ip6mnid_t *)
* \brief Creates the mobile interface identifier option.
* \param[in-out]  iov Storage
* \param[in]  flags  Option flags value
* \param[in]  MN_ID  Option mobile node identifier value
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_mn_identifier(struct iovec *iov, int flags, ip6mnid_t * MN_ID);)
/*! \fn int mh_create_opt_time_stamp(struct iovec *iov, ip6ts_t *)
* \brief Creates the timestamp option.
* \param[in-out]  iov Storage
* \param[in]  Timestamp  Option timestamp value
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_time_stamp(struct iovec *iov, ip6ts_t * Timestamp);)
/*! \fn int mh_create_opt_link_local_add(struct iovec *, struct in6_addr *)
* \brief Creates the link local address option.
* \param[in-out]  iov Storage
* \param[in]  LinkLocal  Option link local address value
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_link_local_add(struct iovec *iov, struct in6_addr *LinkLocal);)
/*! \fn int mh_create_opt_dst_mn_addr(struct iovec *, struct in6_addr *)
* \brief Creates the Destination MN address option.
* \param[in-out]  iov Storage
* \param[in]  dst_mn_addr  Destinantion mobile node address option value
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_dst_mn_addr(struct iovec *iov, struct in6_addr *dst_mn_addr);)

/*! \fn int mh_create_opt_serv_mag_addr(struct iovec *, struct in6_addr *)
* \brief Creates the Serving MAG address option.
* \param[in-out]  iov Storage
* \param[in]  serv_MAG_addr  Serving MAG address option value
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_serv_mag_addr(struct iovec *iov, struct in6_addr *serv_MAG_addr);)
/*! \fn int mh_create_opt_serv_lma_addr(struct iovec *iov, struct in6_addr *)
* \brief Creates the Serving LMA address option.
* \param[in-out]  iov Storage
* \param[in]  serv_lma_addr  Serving LMA address option value.
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_serv_lma_addr(struct iovec *iov, struct in6_addr *serv_lma_addr);)
/*! \fn int mh_create_opt_src_mn_addr(struct iovec *, struct in6_addr *)
* \brief Creates the source mobile node address option.
* \param[in-out]  iov Storage
* \param[in]  src_mn_addr  Source mobile node address option value.
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_src_mn_addr(struct iovec *iov, struct in6_addr *src_mn_addr);)
/*! \fn int mh_create_opt_src_mag_addr(struct iovec *, struct in6_addr *)
* \brief Creates the mobile interface identifier option.
* \param[in-out]  iov Storage
* \param[in]  src_mag_addr  Source MAG address option value.
* \return   Zero if success, negative value otherwise.
*/
private_pmip_msgs(int mh_create_opt_src_mag_addr(struct iovec *iov, struct in6_addr *src_mag_addr);)
/*! \fn int mh_pbu_parse(msg_info_t * info, struct ip6_mh_binding_update *pbu, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif)
* \brief Parse PBU message.
* \param[in-out]   info Storage containing all necessary informations about the message received.
* \param[in]  pbu  Mobility header "Binding Update".
* \param[in]  len  Length of pbu.
* \param[in]  in_addrs  Source and Destination address of PBU message.
* \param[in]  iif  Interface identifier.
* \return   Zero.
*/
protected_pmip_msgs(int mh_pbu_parse(msg_info_t * info, struct ip6_mh_binding_update *pbu, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
/*! \fn int mh_pba_parse(msg_info_t * , struct ip6_mh_binding_ack *, ssize_t , const struct in6_addr_bundle *, int)
* \brief Parse PBA message.
* \param[in-out]   info Storage containing all necessary informations about the message received.
* \param[in]  pba  Mobility header "Binding Acknowledgment".
* \param[in]  len  Length of pbu.
* \param[in]  in_addrs  Source and Destination address of PBU message.
* \param[in]  iif  Interface identifier.
* \return   Zero.
*/
protected_pmip_msgs(int mh_pba_parse(msg_info_t * info, struct ip6_mh_binding_ack *pba, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
/*! \fn int icmp_rs_parse(msg_info_t * , struct nd_router_solicit *, const struct in6_addr *, const struct in6_addr *, int , int )
* \brief Parse ICMPv6 RS message.
* \param[in-out]   info Storage containing all necessary informations about the message received.
* \param[in]  rs  Router sollicitation infos.
* \param[in]  saddr  Source address of the message.
* \param[in]  daddr  Destination address of the message.
* \param[in]  iif  Interface identifier.
* \param[in]  hoplimit  Hop limit value found in RS message.
* \return   Zero.
*/
protected_pmip_msgs(int icmp_rs_parse(msg_info_t * info, struct nd_router_solicit *rs, const struct in6_addr *saddr, const struct in6_addr *daddr, int iif, int hoplimit);)
/*! \fn int icmp_na_parse(msg_info_t *, struct nd_neighbor_advert *, const struct in6_addr *, const struct in6_addr *, int , int )
* \brief Parse ICMPv6 NA message.
* \param[in-out]   info Storage containing all necessary informations about the message received.
* \param[in]  na  Neighbour advertisement infos.
* \param[in]  saddr  Source address of the message.
* \param[in]  daddr  Destination address of the message.
* \param[in]  iif  Interface identifier.
* \param[in]  hoplimit  Hop limit value found in NA message.
* \return   Zero.
*/
protected_pmip_msgs(int icmp_na_parse(msg_info_t * info, struct nd_neighbor_advert *na, const struct in6_addr *saddr, const struct in6_addr *daddr, int iif, int hoplimit);)
/*! \fn int pmip_mh_send(const struct in6_addr_bundle *, const struct iovec *, int , int )
* \brief Send MH message.
* \param[in]  addrs  Source and destination address of the message.
* \param[in]  mh_vec  Storage of the message.
* \param[in]  iovlen  Len of the storage.
* \param[in]  oif  Outgoing interface identifier.
* \return   Zero if success, negative value otherwise.
*/
protected_pmip_msgs(int pmip_mh_send(const struct in6_addr_bundle *addrs, const struct iovec *mh_vec, int iovlen, int oif);)
/*! \fn int mh_send_pbu(const struct in6_addr_bundle *, pmip_entry_t *, struct timespec *lifetime, int oif)
* \brief Send PBU message.
* \param[in]  addrs  Source and destination address of the message.
* \param[in]  bce  Binding cache entry corresponding to the binding.
* \param[in]  lifetime  Lifetime of the binding.
* \param[in]  oif  Outgoing interface identifier.
* \return   Zero if success, negative value otherwise.
*/
protected_pmip_msgs(int mh_send_pbu(const struct in6_addr_bundle *addrs, pmip_entry_t * bce, struct timespec *lifetime, int oif);)
/*! \fn int mh_send_pba(const struct in6_addr_bundle *, pmip_entry_t *, struct timespec *, int)
* \brief Send PBA message.
* \param[in]  addrs  Source and destination address of the message.
* \param[in]  bce  Binding cache entry corresponding to the binding.
* \param[in]  lifetime  Lifetime of the binding.
* \param[in]  oif  Outgoing interface identifier.
* \return   Zero if success, negative value otherwise.
*/
protected_pmip_msgs(int mh_send_pba(const struct in6_addr_bundle *addrs, pmip_entry_t * bce, struct timespec *lifetime, int oif);)

// Anh Khuong add
protected_pmip_msgs(int mh_rot_parse(msg_info_t * info, struct ip6_mh_rot *rot, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
protected_pmip_msgs(int mh_roi_parse(msg_info_t * info, struct ip6_mh_roi *roi, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
protected_pmip_msgs(int mh_ros_parse(msg_info_t * info, struct ip6_mh_ros *ros, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
protected_pmip_msgs(int mh_etm_parse(msg_info_t * info, struct ip6_mh_etm *etm, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
protected_pmip_msgs(int mh_hi_parse(msg_info_t * info, struct ip6_mh_hi *hi, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
protected_pmip_msgs(int mh_ha_parse(msg_info_t * info, struct ip6_mh_ha *ha, ssize_t len, const struct in6_addr_bundle *in_addrs, int iif);)
protected_pmip_msgs(int mh_send_ihr(pmip_entry_t * bce, int oif);)
protected_pmip_msgs(int mh_send_ros (struct in6_addr *mn_addr, struct in6_addr * dst_addr);)
protected_pmip_msgs(int mh_send_rosa (struct in6_addr * dst_addr);)
protected_pmip_msgs(int mh_send_roi (struct in6_addr *mn_saddr, struct in6_addr *mn_daddr, struct in6_addr *mag_saddr, struct in6_addr * dst_addr);)
protected_pmip_msgs(int mh_send_rot (struct in6_addr *mn_saddr, struct in6_addr *mn_daddr, struct in6_addr *mag_saddr, struct in6_addr * dst_addr);)
protected_pmip_msgs(int mh_send_etm (struct in6_addr *mn_addr, struct in6_addr *nmag_addr, struct in6_addr * dst_addr);)
protected_pmip_msgs(int mh_send_hi (struct in6_addr *mn_addr, struct in6_addr * dst_addr);)
protected_pmip_msgs(int mh_send_ha (struct in6_addr * mn_addr, struct in6_addr * dst_addr, int status);)
// end
#endif
/** @}*/
