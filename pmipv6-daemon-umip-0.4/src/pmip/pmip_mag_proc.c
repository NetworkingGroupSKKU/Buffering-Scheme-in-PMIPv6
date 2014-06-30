/*! \file pmip_mag_proc.c
* \brief
* \author OpenAir3 Group
* \date 12th of October 2010
* \version 1.0
* \company Eurecom
* \project OpenAirInterface
* \email: openair3@eurecom.fr
*/
#define PMIP
#define PMIP_MAG_PROC_C
#ifdef HAVE_CONFIG_H
#	include <config.h>
#endif
#include <sys/sysctl.h>
//---------------------------------------------------------------------------------------------------------------------
#include "pmip_mag_proc.h"
#include "pmip_handler.h"
#include "pmip_hnp_cache.h"
#include "pmip_tunnel.h"
#include "pmip_ro.h"
//---------------------------------------------------------------------------------------------------------------------
#include "rtnl.h"
#include "tunnelctl.h"
#ifdef ENABLE_VT
#    include "vt.h"
#endif
#include "debug.h"
#include "conf.h"
#include "util.h"
//---------------------------------------------------------------------------------------------------------------------
void pmip_timer_retrans_pbu_handler(struct tq_elem *tqe);
//---------------------------------------------------------------------------------------------------------------------
int mag_setup_route(struct in6_addr *pmip6_addr, int downlink)
{
    int res = 0;
    if (conf.TunnelingEnabled) {
        //add a rule for MN for uplink traffic from MN must query the TABLE for PMIP --> tunneled
        dbg("Uplink: Add new rule for tunneling src=%x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(pmip6_addr));
        res = rule_add(NULL, RT6_TABLE_PMIP, IP6_RULE_PRIO_PMIP6_FWD, RTN_UNICAST, pmip6_addr, 128, &in6addr_any, 0, 0);
        if (res < 0) {
            dbg("ERROR Add new rule for tunneling");
        }

        //add a route for downlink traffic through LMA (any src) ==> MN
        dbg("Downlink: Add new route for %x:%x:%x:%x:%x:%x:%x:%x in table %d\n", NIP6ADDR(pmip6_addr), RT6_TABLE_MIP6);
        res |= route_add(downlink, RT6_TABLE_MIP6, RTPROT_MIP, 0, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, pmip6_addr, 128, NULL);
        if (res < 0) {
            dbg("ERROR Add new rule for tunneling");
        }
    } else {
        dbg("WARNING CANNOT ADD ROUTING RULES SINCE TUNNELING DISABLED IN CONFIG");
    }
    return res;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_remove_route(struct in6_addr *pmip6_addr, int downlink)
{
    int res = 0;
    if (conf.TunnelingEnabled) {
        //Delete existing rule for the deleted MN
        dbg("Uplink: Delete old rule for tunneling src=%x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(pmip6_addr));
        res = rule_del(NULL, RT6_TABLE_PMIP, IP6_RULE_PRIO_PMIP6_FWD, RTN_UNICAST, pmip6_addr, 128, &in6addr_any, 0, 0);
        if (res < 0) {
            dbg("ERROR Del new rule for tunneling ");
        }
        //Delete existing route for the deleted MN
        dbg("Downlink: Delete old routes for: %x:%x:%x:%x:%x:%x:%x:%x from table %d\n", NIP6ADDR(pmip6_addr), RT6_TABLE_MIP6);
        res |= route_del(downlink, RT6_TABLE_MIP6, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, pmip6_addr, 128, NULL);
        if (res < 0) {
            dbg("ERROR Del new rule for tunneling ");
        }
    } else {
        dbg("WARNING CANNOT DELETE ROUTING RULES SINCE TUNNELING DISABLED IN CONFIG");
    }
    return res;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_dereg(pmip_entry_t * bce, int propagate)
{
    //Delete existing route & rule for the deleted MN
    int res = 0;
    bce->type = BCE_NO_ENTRY;
    if (propagate) // Anh Khuong add if condition for FPMIP case
    	res = mag_remove_route(get_mn_addr(bce), bce->link);
    int usercount = tunnel_getusers(bce->tunnel);
    dbg("# of binding entries %d \n", usercount);
    if (usercount == 1) {
        route_del(bce->tunnel, RT6_TABLE_PMIP, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, &in6addr_any, 0, NULL);
    }
    //decrement users of old tunnel.
    pmip_tunnel_del(bce->tunnel);
    if (propagate) {
        dbg("Propagate the deregistration... \n");
        struct in6_addr_bundle addrs;
        addrs.src = &conf.OurAddress;
        addrs.dst = &conf.LmaAddress;
        struct timespec Lifetime = { 0, 0 };
        dbg("Create PBU for LMA for deregistration....\n");
        mh_send_pbu(&addrs, bce, &Lifetime, 0);
    }
    //Delete PBU cache entry
    dbg("Delete PBU entry....\n");
    pmipcache_release_entry(bce);
    pmip_bce_delete(bce);
    return res;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_start_registration(pmip_entry_t * bce)
{
    //Create PBU and send to the LMA
    struct in6_addr_bundle addrs;
    addrs.src = &conf.MagAddressEgress;
    addrs.dst = &conf.LmaAddress;
    mh_send_pbu(&addrs, bce, &conf.PBULifeTime, 0);
    //add a new task for PBU retransmission.
    struct timespec expires;
    clock_gettime(CLOCK_REALTIME, &bce->add_time);
    tsadd(bce->add_time, conf.NRetransmissionTime, expires);
    add_task_abs(&expires, &bce->tqe, pmip_timer_retrans_pbu_handler);
    dbg("PBU Retransmissions Timer is registered....\n");
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_end_registration(pmip_entry_t * bce, int iif)
{
    //Change the BCE type.
    bce->type = BCE_PMIP;
    dbg("New PMIP cache entry type: %d\n", bce->type);
    //Reset the Retransmissions counter.
    bce->n_rets_counter = conf.MaxMessageRetransmissions;
    //Add task for entry expiry.
    dbg("Timer for Expiry is initialized: %d(s)!\n", bce->lifetime.tv_sec);
    pmip_cache_start(bce);
    //create a tunnel between MAG and LMA.
    bce->tunnel = pmip_tunnel_add(&conf.OurAddress, &conf.LmaAddress, iif);
    int usercount = tunnel_getusers(bce->tunnel);
    dbg("# of binding entries %d\n", usercount);
    if (usercount == 1) {
        dbg("Add routing entry for uplink traffic\n");
        route_add(bce->tunnel, RT6_TABLE_PMIP, RTPROT_MIP, 0, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, &in6addr_any, 0, NULL);
    }
    mag_kickoff_ra(bce);
    dbg("Adding route for : %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(get_mn_addr(bce)));
    mag_setup_route(get_mn_addr(bce), bce->link);
    dbg("Out of setup route \n");

    /* calculate period for handover: from link up to send RA */
    struct timeval time_end;
    int i;
    if (time_info.size < 20) {
		gettimeofday(&time_end, NULL);
		time_info.period[time_info.size] = ts2usec(time_end) - ts2usec(time_info.time_start);/* micro seconds */
		time_info.size++;
		/* printf result */
		printf("\n******* HANDOVER TIME INFORMATION %d********\n", time_info.size);
		for (i=0; i<time_info.size; i++)
			printf("%lu     ", time_info.period[i]);
		printf("\n");
    }
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_kickoff_ra(pmip_entry_t * bce)
{
    struct in6_addr *src;
    src = malloc(sizeof(struct in6_addr));
    memset(src, 0, sizeof(struct in6_addr));
    struct iovec iov;
    struct nd_router_advert *radvert;
    adv_prefix_t prefix;
    unsigned char buff[MSG_SIZE];
    size_t len = 0;
    memset(&buff, 0, sizeof(buff));
    radvert = (struct nd_router_advert *) buff;
    radvert->nd_ra_type = ND_ROUTER_ADVERT;
    radvert->nd_ra_code = 0;
    radvert->nd_ra_cksum = 0;
    radvert->nd_ra_curhoplimit = router_ad_iface.AdvCurHopLimit;
    radvert->nd_ra_flags_reserved = (router_ad_iface.AdvManagedFlag) ? ND_RA_FLAG_MANAGED : 0;
    radvert->nd_ra_flags_reserved |= (router_ad_iface.AdvOtherConfigFlag) ? ND_RA_FLAG_OTHER : 0;
    /* Mobile IPv6 ext */
    radvert->nd_ra_flags_reserved |= (router_ad_iface.AdvHomeAgentFlag) ? ND_RA_FLAG_HOME_AGENT : 0;
    /* if forwarding is disabled, send zero router lifetime */
    radvert->nd_ra_router_lifetime = !check_ip6_forwarding()? htons(router_ad_iface.AdvDefaultLifetime) : 0;
    radvert->nd_ra_reachable = htonl(router_ad_iface.AdvReachableTime); //ask giuliana
    radvert->nd_ra_retransmit = htonl(router_ad_iface.AdvRetransTimer); // ask giuliana
    len = sizeof(struct nd_router_advert);
    prefix = router_ad_iface.Adv_Prefix;
    /*
     *  add prefix options
    */
    struct nd_opt_prefix_info *pinfo;
    pinfo = (struct nd_opt_prefix_info *) (buff + len);
    pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
    pinfo->nd_opt_pi_len = 4;
    pinfo->nd_opt_pi_prefix_len = prefix.PrefixLen;
    pinfo->nd_opt_pi_flags_reserved = (prefix.AdvOnLinkFlag) ? ND_OPT_PI_FLAG_ONLINK : 0;
    pinfo->nd_opt_pi_flags_reserved |= (prefix.AdvAutonomousFlag) ? ND_OPT_PI_FLAG_AUTO : 0;
    /* Mobile IPv6 ext */
    pinfo->nd_opt_pi_flags_reserved |= (prefix.AdvRouterAddr) ? ND_OPT_PI_FLAG_RADDR : 0;
    pinfo->nd_opt_pi_valid_time = htonl(prefix.AdvValidLifetime);
    pinfo->nd_opt_pi_preferred_time = htonl(prefix.AdvPreferredLifetime);
    pinfo->nd_opt_pi_reserved2 = 0;
    memcpy(&pinfo->nd_opt_pi_prefix, &bce->mn_prefix, sizeof(struct in6_addr));
    len += sizeof(*pinfo);
    //mobile ip extension
    if (router_ad_iface.AdvHomeAgentInfo
    && (router_ad_iface.AdvMobRtrSupportFlag || router_ad_iface.HomeAgentPreference != 0 || router_ad_iface.HomeAgentLifetime != router_ad_iface.AdvDefaultLifetime)) {
    home_agent_info_t ha_info;
    ha_info.type = ND_OPT_HOME_AGENT_INFO;
    ha_info.length = 1;
    ha_info.flags_reserved = (router_ad_iface.AdvMobRtrSupportFlag) ? ND_OPT_HAI_FLAG_SUPPORT_MR : 0;
    ha_info.preference = htons(router_ad_iface.HomeAgentPreference);
    ha_info.lifetime = htons(router_ad_iface.HomeAgentLifetime);
    memcpy(buff + len, &ha_info, sizeof(ha_info));
    len += sizeof(ha_info);
    }
    iov.iov_len = len;
    iov.iov_base = (caddr_t) buff;
    int err;
    err = icmp6_send(bce->link, 255, src, &bce->mn_link_local_addr, &iov, 1);
    if (err < 0) {
        dbg("Error: couldn't send a RA message ...\n");
    } else {
    	/* Anh Khuong add */
    	char strtime[512];
    	printf("[SIM %s] MAG Send RA \n", getcurrenttime(strtime));
        dbg("RA LL ADDRESS sent\n");
    }
    return err;
}
//---------------------------------------------------------------------------------------------------------------------
int check_ip6_forwarding(void)
{
    int forw_sysctl[] = { SYSCTL_IP6_FORWARDING };
    int value;
    int rc;
    size_t size = sizeof(value);
    FILE *fp = NULL;
#ifdef __linux__
    fp = fopen(PROC_SYS_IP6_FORWARDING, "r");
    if (fp) {
        rc = fscanf(fp, "%d", &value);
        fclose(fp);
        if (rc <= 0) {
             dbg("ERROR reading %s" ,PROC_SYS_IP6_FORWARDING);
        }
    } else
        dbg("Correct IPv6 forwarding procfs entry not found, " "perhaps the procfs is disabled, " "or the kernel interface has changed?");
#endif              /* __linux__ */
    if (!fp && sysctl(forw_sysctl, sizeof(forw_sysctl) / sizeof(forw_sysctl[0]), &value, &size, NULL, 0) < 0) {
        dbg("Correct IPv6 forwarding sysctl branch not found, " "perhaps the kernel interface has changed?");
        return (0);     /* this is of advisory value only */
    }
    if (value != 1) {
        dbg("IPv6 forwarding setting is: %u, should be 1", value);
        return (-1);
    }
    return (0);
}
//---------------------------------------------------------------------------------------------------------------------
int mag_get_ingress_info(int *if_index, char *dev_name_mn_link)
{
    FILE *fp;
    char str_addr[INET6_ADDRSTRLEN];
    unsigned int plen, scope, dad_status, if_idx;
    struct in6_addr addr;
    unsigned int ap;
    int i;

    char devname[32];
    if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
        dbg("you don't have root previleges, please logon as root, can't open %s:", "/proc/net/if_inet6");
        return -1;
    }
    // first find the device name
    while (fscanf(fp, "%32s %x %02x %02x %02x %15s\n", str_addr, &if_idx, &plen, &scope, &dad_status, devname) != EOF) {
        for (i = 0; i < 16; i++) {
            sscanf(str_addr + i * 2, "%02x", &ap);
            addr.s6_addr[i] = (unsigned char) ap;
        }
        if (memcmp(&conf.MagAddressIngress, &addr, sizeof(struct in6_addr)) == 0) {
            strncpy(dev_name_mn_link, devname, 32);
            *if_index = if_idx;
            dbg("The interface name of the device that is used for communicate with MNs is %s, iif is %d\n", dev_name_mn_link, *if_index);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    dbg("No interface name of the device that is used for communicate with MNs found");
    return -1;
}
//---------------------------------------------------------------------------------------------------------------------
// Anh Khuong: add
int mag_get_egress_info(int *if_index, char *dev_name_mn_link)
{
    FILE *fp;
    char str_addr[INET6_ADDRSTRLEN];
    unsigned int plen, scope, dad_status, if_idx;
    struct in6_addr addr;
    unsigned int ap;
    int i;

    char devname[32];
    if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
        dbg("you don't have root previleges, please logon as root, can't open %s:", "/proc/net/if_inet6");
        return -1;
    }
    // first find the device name
    while (fscanf(fp, "%32s %x %02x %02x %02x %15s\n", str_addr, &if_idx, &plen, &scope, &dad_status, devname) != EOF) {
        for (i = 0; i < 16; i++) {
            sscanf(str_addr + i * 2, "%02x", &ap);
            addr.s6_addr[i] = (unsigned char) ap;
        }
        if (memcmp(&conf.MagAddressEgress, &addr, sizeof(struct in6_addr)) == 0) {
            strncpy(dev_name_mn_link, devname, 32);
            *if_index = if_idx;
            dbg("The interface name of the device that is used for communicate with MNs is %s\n", dev_name_mn_link);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    dbg("No interface name of the device that is used for communicate with MNs found");
    return -1;
}
//---------------------------------------------------------------------------------------------------------------------
int setup_linklocal_addr(struct in6_addr *src)
{
    FILE *fp;
    char str_addr[INET6_ADDRSTRLEN];
    unsigned int plen, scope, dad_status, if_idx;
    struct in6_addr addr;
    unsigned int ap;
    int i;
    int flagy = 0;
    char devname[32];
    char dev_name_mn_link[32];
    if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
        dbg("you don't have root previleges, please logon as root, can't open %s:", "/proc/net/if_inet6");
        return -1;
    }
    // first find the device name
    while (fscanf(fp, "%32s %x %02x %02x %02x %15s\n", str_addr, &if_idx, &plen, &scope, &dad_status, devname) != EOF) {
        for (i = 0; i < 16; i++) {
            sscanf(str_addr + i * 2, "%02x", &ap);
            addr.s6_addr[i] = (unsigned char) ap;
        }
        if (memcmp(&conf.MagAddressIngress, &addr, sizeof(struct in6_addr)) == 0) {
            strncpy(dev_name_mn_link, devname, 32);
            flagy = 1;
            dbg("The interface name of the device that is used for communicate with MNs is %s\n", dev_name_mn_link);
            break;
        }
    }
    fclose(fp);
    if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
        dbg("can't open %s:", "/proc/net/if_inet6");
        return -1;
    }
    while (fscanf(fp, "%32s %x %02x %02x %02x %15s\n", str_addr, &if_idx, &plen, &scope, &dad_status, devname) != EOF) {
    if (scope == IPV6_ADDR_LINKLOCAL && strcmp(devname, dev_name_mn_link) == 0) //we have to store the interface name from which we get the router solicitation
    {
        dbg("entered the if to get %s iface ll address ", dev_name_mn_link);
        flagy = 1;
        for (i = 0; i < 16; i++) {
        sscanf(str_addr + i * 2, "%02x", &ap);
        addr.s6_addr[i] = (unsigned char) ap;
        }
        dbg("PMIP cache entry is found for: %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&addr));
        *src = addr;
    }
    }
    if (flagy == 0) {
        dbg("no link local address configured ");
        fclose(fp);
        return -1;
    } else {
        fclose(fp);
        return 1;
    }
}
//---------------------------------------------------------------------------------------------------------------------
int mag_update_binding_entry(pmip_entry_t * bce, msg_info_t * info)
{
    dbg("Store binding entry\n");
    bce->our_addr = conf.OurAddress;
    bce->mn_suffix = info->mn_iid;
    bce->mn_hw_address = eth_address2hw_address(info->mn_iid);
    bce->mn_prefix = info->mn_prefix;
    bce->mn_addr = info->mn_addr;
    bce->mn_link_local_addr = info->mn_link_local_addr;
    bce->mn_serv_mag_addr = info->src;
    bce->lifetime = info->lifetime;
    bce->n_rets_counter = conf.MaxMessageRetransmissions;
    bce->seqno_in = info->seqno;
    bce->link = info->iif;
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_pmip_md(msg_info_t * info, pmip_entry_t * bce)
{
    if (bce != NULL) {
        bce->our_addr = conf.OurAddress;
        bce->mn_suffix = info->mn_iid;
        bce->mn_prefix = info->mn_prefix;
        dbg("Making BCE entry in MAG with HN prefix  %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&bce->mn_prefix));
        bce->mn_serv_mag_addr = conf.OurAddress;
        bce->mn_serv_lma_addr = conf.LmaAddress;
        bce->seqno_out = 0;
        bce->PBU_flags = IP6_MH_BU_ACK | IP6_MH_PBU;
        //AnhKhuong: added
        if (info->flag == 1)
            bce->PBU_flags = bce->PBU_flags | IP6_MH_BU_S_BIT;
        bce->link = info->iif;
        struct in6_addr *link_local = link_local_addr(&bce->mn_suffix);
        bce->mn_link_local_addr = *link_local;  // link local address of MN
        dbg("New attachment detected! Start Location Registration procedure...\n");
        bce->type = BCE_TEMP;
        mag_start_registration(bce);
    }
    return 0;
}

/******************************************************************************
 * Specific functions for new features or papers
 *
 ******************************************************************************/
// Using for RO MN1<->MN2: flag = 0, mn_addr is MN2, mag_addr is mag2
// Using for FPMIP MN <->CN: mag_addr is mag2, flag = 1 - at pMAG, flag=2 - at nMAG.
int mag_create_tunnel(struct in6_addr *mn_addr, struct in6_addr *mag_addr, int flag)
{
	char devname[32];
	int iif;
	int res;
	tnlinfo_list_entry_t *entry;
	mag_get_egress_info(&iif, devname);

	if (mn_addr != NULL && mag_addr != NULL) {
		// create entry for ro information
		entry = (tnlinfo_list_entry_t *)malloc(sizeof(tnlinfo_list_entry_t));
		entry->type = flag;
		entry->mn_addr = *mn_addr;
		entry->mag_addr = *mag_addr;
		dbg("Setup tunnel/route/rule iif: %d our_addr: %x:%x:%x:%x:%x:%x:%x:%x mag_addr2: %x:%x:%x:%x:%x:%x:%x:%x\n", iif, NIP6ADDR(&conf.OurAddress), NIP6ADDR(&entry->mag_addr));
		// add tunnel
		entry->tunnel = pmip_tunnel_add(&conf.OurAddress, mag_addr, iif);
		int usercount = tunnel_getusers(entry->tunnel);
		dbg("tunnel: number of binding entries %d\n", usercount);
		// add route
		if (usercount == 1) {
			dbg("Add routing entry for uplink traffic\n");
			res = route_add(entry->tunnel, RT6_TABLE_PMIP_RO, RTPROT_MIP, 0, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, &in6addr_any, 0, NULL);
			if ((flag == 1) || (flag == 0)) {
				res |= rule_add(NULL, RT6_TABLE_PMIP_RO, IP6_RULE_PRIO_PMIP6_RO, RTN_UNICAST, &in6addr_any, 0, mn_addr, 128, 0);
			}
			else if (flag == 2)
				res |= rule_add(NULL, RT6_TABLE_PMIP_RO, IP6_RULE_PRIO_PMIP6_RO, RTN_UNICAST, mn_addr, 128, &in6addr_any, 0, 0);
			if (res < 0) {
				dbg("Add route or rule failed \n");
				return res;
			}
		}

		// add entry
		pmip_tunnel_add_entry(entry);
	}
	return 0;
}

int mag_delete_tunnel()
{
	pmip_tunnel_clean_list();
	return 0;
}

// do not need send RA and add route because already did. Use in FPMIP
int mag_setup_route_before_send_PBU(struct in6_addr *mn_addr)
{
	char devname[32];
	int iif;
	mag_get_ingress_info(&iif, devname);

	int res = route_add(iif, RT6_TABLE_MIP6, RTPROT_MIP, 0, IP6_RT_PRIO_MIP6_FWD, &in6addr_any, 0, mn_addr, 128, NULL);
	if (res < 0)
		dbg("Add route failed \n");
        return 0;
}

int mag_cleanup_for_fpmip(struct in6_addr *mn_addr)
{
	// remove tunnel
	struct in6_addr _mag_addr;
	if (pmip_tunnel_get_info_fpmip(mn_addr, NULL, &_mag_addr) == 0) {
		dbg("Found mn_addr in tunnel information of FMIP mn_adrr: %x:%x:%x:%x:%x:%x:%x:%x, mag_addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(mn_addr), NIP6ADDR(&_mag_addr));
		mag_delete_tunnel();
		// send to pMAG to remove tunnel;
		mh_send_ha(mn_addr, &_mag_addr, 123);
	}
}
