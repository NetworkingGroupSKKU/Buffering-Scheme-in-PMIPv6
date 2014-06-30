/*! \file pmip_fsm.c
* \brief
* \author OpenAir3 Group
* \date 12th of October 2010
* \version 1.0
* \company Eurecom
* \project OpenAirInterface
* \email: openair3@eurecom.fr
*/
#define PMIP
#define PMIP_FSM_C
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
//---------------------------------------------------------------------------------------------------------------------
#include "pmip_fsm.h"
#include "pmip_hnp_cache.h"
#include "pmip_lma_proc.h"
#include "pmip_mag_proc.h"
//---------------------------------------------------------------------------------------------------------------------
#ifdef ENABLE_VT
#    include "vt.h"
#endif
#include "debug.h"
#include "conf.h"
#include "pmip_buffering.h"
#include "pmip_ro.h"
//---------------------------------------------------------------------------------------------------------------------
int mag_init_fsm(void)
{
    if (pthread_rwlock_init(&pmip_lock, NULL))
      return -1;
    else
      return 0;
}
//---------------------------------------------------------------------------------------------------------------------
int mag_fsm(msg_info_t * info)
{
    int result = 0;
    int aaa_result = 0;
    pmip_entry_t *bce;
    struct in6_addr prefix;
    struct in6_addr hw_address = eth_address2hw_address(info->mn_iid);
    int type = pmip_cache_exists(&conf.OurAddress, &hw_address);
    pthread_rwlock_wrlock(&fsm_lock);
    switch (type) {
//--------------------------------------
    case BCE_NO_ENTRY:
        dbg("BCE_NO_ENTRY\n");
    if (info->msg_event == hasRS) {
        dbg("New MN is found sending RS, start new registration ...\n\n");
        bce = pmip_cache_alloc(BCE_TEMP);
        prefix = mnid_hnp_map(hw_address, &aaa_result);
        if (aaa_result >= 0) {
            bce->mn_prefix = prefix;
            bce->mn_suffix = info->mn_iid;
            bce->mn_hw_address = eth_address2hw_address(info->mn_iid);
            info->mn_prefix = prefix;
            result = mag_pmip_md(info, bce);
            dbg("Movement detection is finished, now going to add an entry into the cache\n\n");
            pmip_cache_add(bce);
            //dbg("pmip_cache_add is done \n\n");
        } else {
            dbg("Authentication failed\n");
        }
    //yet to process
    }
    else if (info->msg_event == hasWLCCP) {
        dbg("Incoming MN is detected by CISCO AP, start new registration ...\n\n");
        bce = pmip_cache_alloc(BCE_TEMP);
        prefix = mnid_hnp_map(hw_address, &aaa_result);
        if (aaa_result >= 0) {
            bce->mn_prefix = prefix;
            bce->mn_suffix = info->mn_iid;
            bce->mn_hw_address = hw_address;
            info->mn_prefix = prefix;
#ifdef USE_FPMIP
			//reinject packet
			struct in6_addr _mn_addr;
			if (pmip_tunnel_get_info_fpmip(&bce->mn_prefix, &_mn_addr, NULL) == 0) {
				dbg("Found mn_addr in tunnel information of FMIP : %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&_mn_addr));
				mag_setup_route_before_send_PBU(&_mn_addr); // setup route to flush buffered packets.
				usleep(500);
				pmip_buffering_reinject(&_mn_addr, 0);
#ifdef ETM_METHOD  // create packet via new path
				pmip_buffering_start(&_mn_addr, 1);
#endif
			}
#endif
#ifdef USE_SMARTBUFF
			// create tunnel with pMAG
			mag_create_tunnel(&info->mn_addr, &info->mn_info_mag_addr, 2);
			// create buffering here
			pmip_add_rule(&info->mn_addr, 2);
			dbg("Initializing the buffering module\n");
			if (pmip_buffering_init() < 0) {
				dbg("Buffering init error. \n");
				pmip_buffering_cleanup();
				return -1;
			}
			pmip_buffering_start(&info->mn_addr, 0);

			// send HI to pMAG
			mh_send_hi(&bce->mn_addr, &info->mn_info_mag_addr);
#endif
            result = mag_pmip_md(info, bce);
            dbg("Movement detection is finished, now going to add an entry into the cache\n\n");
            pmip_cache_add(bce);
            dbg("pmip_cache_add is done \n\n");
        } else {
            dbg("Authentication failed\n");
        }
    //yet to process
	}
    else if (info->msg_event == hasDEREG) {
        dbg("Received DEREG message\n");
		dbg("No action for this event (%d) at current state (%d) !\n", info->msg_event, type);
    }
    /* AnhKhuong: added */
	else if (info->msg_event == hasIHR) {
    	dbg("Received IHR message mnid: %x:%x:%x:%x:%x:%x:%x:%x mn_prefix: %x:%x:%x:%x:%x:%x:%x:%x\n",
    												NIP6ADDR(&hw_address), NIP6ADDR(&info->mn_prefix));
    	pmip_insert_into_hnp_cache(hw_address, info->mn_prefix);
    }
	else if (info->msg_event == hasHI) { // for FPMIP
		dbg("Received HI message mn_saddr: %x:%x:%x:%x:%x:%x:%x:%x from MAG addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->mn_addr), NIP6ADDR(&info->src_mag_addr));
#ifdef USE_FPMIP
		mag_create_tunnel(&info->mn_addr, &info->src, 2);
		// create buffering here
			pmip_add_rule(&info->mn_addr, 0);
			dbg("Initializing the buffering module\n");
			if (pmip_buffering_init() < 0) {
				dbg("Buffering init error. \n");
				pmip_buffering_cleanup();
				return -1;
			}
			pmip_buffering_start(&info->mn_addr, 0);
		mh_send_ha(&info->mn_addr, &info->src, 0);
#endif
#ifdef USE_SMARTBUFF
		// create tunnel with nMAG
		mag_create_tunnel(&info->mn_addr, &info->src, 1);
		// forward packets to pMAG
		pmip_buffering_reinject(&info->mn_addr, 0);
#endif
	}
	else if (info->msg_event == hasETM) {
	    	if (!IN6_ARE_ADDR_EQUAL(&conf.OurAddress, &info->src_mag_addr)) {
	    		dbg("forward ETM message mn_addr: %x:%x:%x:%x:%x:%x:%x:%x  MAG2 addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mn_addr), NIP6ADDR(&info->src_mag_addr));
	    		mh_send_etm (&info->src_mn_addr, &info->src_mag_addr,  &info->src_mag_addr);
	        }
	    	else {
	    		dbg("Received ETM message.\n");
	    	}
		}
    break;
    //--------------------------------------
    case BCE_TEMP:
        dbg("BCE_TEMP\n");
    if (info->msg_event == hasPBA) {
        dbg("Handling PBA. Moving from BCE_TEMP to BCE_PMIP\n");
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
        if (info->seqno == bce->seqno_out) {
			dbg("Finish Location Registration\n");
			//Modify the entry with additional info.
			del_task(&bce->tqe);    //Delete timer retransmission PBU (if any)
			bce->PBA_flags = info->PBA_flags;
			bce->lifetime = info->lifetime;
			dbg("Prefix before ending registration : %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&bce->mn_prefix));
			// LG COMMENT GOT PREFIX BY RADIUS - bce->mn_prefix = info->mn_prefix;   //adding the hn prefix value receive in PBA to MAG cache
			mag_end_registration(bce, info->iif);
        }
        else
        	dbg("Seq# of PBA is Not equal to Seq# of sent PBU!\n");
        pmipcache_release_entry(bce);
    }
    break;
    //--------------------------------------
    case BCE_PMIP:
        dbg("BCE_PMIP\n");
    if (info->msg_event == hasRS) {
        dbg("Router solicitation received for existing MN\n");
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
        dbg("prefix before entering kickoff_ra : %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&bce->mn_prefix));
        mag_kickoff_ra(bce);
        pmipcache_release_entry(bce);
        dbg("RA sent after router solicitation ...\n");
	} else if (info->msg_event == hasPBA) {
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
        if (info->seqno == bce->seqno_out) {
			dbg("Finish Location Registration\n");
			//Modify the entry with additional info.
			del_task(&bce->tqe);    //Delete timer retransmission PBU (if any)
			bce->PBA_flags = info->PBA_flags;
			bce->lifetime = info->lifetime;
			dbg("Prefix before ending registration : %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&bce->mn_prefix));
			// LG COMMENT GOT PREFIX BY RADIUS - bce->mn_prefix = info->mn_prefix;   //adding the hn prefix value receive in PBA to MAG cache
			mag_end_registration(bce, info->iif);
#ifdef USE_SMARTBUFF
			struct in6_addr _mn_addr;
			if (pmip_tunnel_get_info_fpmip(&bce->mn_prefix, &_mn_addr, NULL) == 0) {
				dbg("Found mn_addr in tunnel information of FMIP : %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&_mn_addr));
				pmip_buffering_reinject(&_mn_addr, 0);
			}
#endif
        }
        pmipcache_release_entry(bce); // anh khuong add to fix bug
    } else if (info->msg_event == hasWLCCP) {
        dbg("Incomming MN is detected by CISCO AP, existing MN\n");
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
        dbg("Prefix before entering kickoff_ra : %x:%x:%x:%x:%x:%x:%x:%x \n", NIP6ADDR(&bce->mn_prefix));
        mag_kickoff_ra(bce);
        pmipcache_release_entry(bce);
        dbg("RA sent after MN AP detection ...\n");
	} else if (info->msg_event == hasDEREG) {
        dbg("Deregistration procedure detected by CISCO AP for a registered MN\n");
		dbg("Start Location Deregistration\n");
		bce = pmip_cache_get(&conf.OurAddress, &hw_address);

		if ((info->flag == FPMIP_FLAG) || (info->flag == SMARTBUFF_FLAG)) { //Anh Khuong: add for test FPMIP
			dbg("Remove route for MN detachment in case FPMIP \n");
			mag_remove_route(get_mn_addr(bce), bce->link);
			pmipcache_release_entry(bce);
		}
#ifdef USE_SMART
		else if (info->flag == RSS_FLAG) {
			pmip_add_rule(&info->mn_addr, 1);
			dbg("Initializing the buffering module\n");
			if (pmip_buffering_init() < 0) {
				dbg("Buffering init error. \n");
				pmip_buffering_cleanup();
				return -1;
			}
			pmip_buffering_start(get_mn_addr(bce), 0);
			pmipcache_release_entry(bce);
		}
		else if (info->flag == SMARTBUFF_FLAG) {

			pmipcache_release_entry(bce);
		}
#endif
		else {
			// AnhKhuong: added
			if (info->flag == SBIT_FLAG) {
				bce->PBU_flags = bce->PBU_flags | IP6_MH_BU_S_BIT;
				dbg("Send PBU with SBIT \n");
			}
			else {
				bce->PBU_flags = bce->PBU_flags & (~IP6_MH_BU_S_BIT);
				dbg("Send PBU without SBIT \n");
			}

			mag_dereg(bce, 1);
#ifdef USE_PMIP_RO
			mag_remove_ro();	// temporary
#endif
		}
    } else if (info->msg_event == hasNA) {
        //Reset counter, Delete task for entry deletion  & Add a new task for NS expiry.
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
        bce->n_rets_counter = conf.MaxMessageRetransmissions;    //Reset the Retransmissions Counter.
        dbg("Reset the Reachability Counter = %d for %x:%x:%x:%x:%x:%x:%x:%x\n", bce->n_rets_counter, NIP6ADDR(&info->mn_iid));
        del_task(&bce->tqe);
        pmip_cache_start(bce);
        pmipcache_release_entry(bce);
    }
    // Anh Khuong add for new features
    else if (info->msg_event == hasROI) {
    	dbg("Received ROI message mn_saddr: %x:%x:%x:%x:%x:%x:%x:%x mn_daddr: %x:%x:%x:%x:%x:%x:%x:%x mag_saddr: %x:%x:%x:%x:%x:%x:%x:%x\n",
    	    		    				NIP6ADDR(&info->src_mn_addr), NIP6ADDR(&info->mn_addr), NIP6ADDR(&info->src_mag_addr));
#ifdef NAMYEONG_PAPER
		dbg("Initializing the buffering module\n");
		if (pmip_buffering_init() < 0) {
			pmip_buffering_cleanup();
			return -1;
		}
		pmip_buffering_start(&info->mn_addr, 0);
#endif
    	// send ROS to second MAG
    	mh_send_ros(&info->mn_addr, &info->src_mag_addr);
    	// add tunnel and router here
    	mag_create_tunnel(&info->src_mn_addr, &info->src_mag_addr, 0);
		dbg("Start buffer \n");
    }
    else if (info->msg_event == hasROS) {
		dbg("Received ROS message mn_saddr: %x:%x:%x:%x:%x:%x:%x:%x mag_saddr: %x:%x:%x:%x:%x:%x:%x:%x\n",
											NIP6ADDR(&info->src_mn_addr), NIP6ADDR(&info->src_mag_addr));
		// add tunnel and router here
		mag_create_tunnel(&info->src_mn_addr, &info->src_mag_addr, 0);
		mh_send_rosa(&info->src_mag_addr);
    }
    else if (info->msg_event == hasREPORT) {
		dbg("Received MN report \n");
		bce = pmip_cache_get(&conf.OurAddress, &hw_address);
		dbg("MN addres : %x:%x:%x:%x:%x:%x:%x:%x nMAG address: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&bce->mn_addr), NIP6ADDR(&info->mn_info_mag_addr));
		mh_send_hi(&bce->mn_addr, &info->mn_info_mag_addr);
		pmipcache_release_entry(bce);
	}
    else if (info->msg_event == hasHA) {
    	dbg("Received HA message.\n");
    	bce = pmip_cache_get(&conf.OurAddress, &hw_address);
    	mag_create_tunnel(&bce->mn_addr, &info->src, 1);
    	pmipcache_release_entry(bce);
    }
    else if (info->msg_event == hasHAC) {
		dbg("Received HAC message.\n");
		bce = pmip_cache_get(&conf.OurAddress, &hw_address);
		mag_dereg(bce, 0); // =0, donot send PBU with lifetime = 0 to LMA and delete route for MN
		mag_delete_tunnel(); // delete tunnel MAG1-MAG2
		// don't need pmipcache_release_entry because cal mag_dereg
	}
    else if (info->msg_event == hasETM) {
    	if (!IN6_ARE_ADDR_EQUAL(&conf.OurAddress, &info->src_mag_addr)) {
    		dbg("forward ETM message mn_addr: %x:%x:%x:%x:%x:%x:%x:%x  MAG2 addr: %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&info->src_mn_addr), NIP6ADDR(&info->src_mag_addr));
    		mh_send_etm (&info->src_mn_addr, &info->src_mag_addr,  &info->src_mag_addr);
        }
    	else {
    		dbg("Received ETM message.\n");
    	}
	}

    break;
    default:
    dbg("No action for this event (%d) at current state (%d) !\n", info->msg_event, type);
    }
    pthread_rwlock_unlock(&fsm_lock);
    return result;
}
//---------------------------------------------------------------------------------------------------------------------
int lma_fsm(msg_info_t * info)
{
    int result = 0;
    pmip_entry_t *bce = NULL;

    struct in6_addr hw_address = eth_address2hw_address(info->mn_iid);
    int type = pmip_cache_exists(&conf.OurAddress, &hw_address);

    switch (type) {
    //--------------------------------------
    case BCE_NO_ENTRY:
    dbg("No PMIP entry found for %x:%x:%x:%x:%x:%x:%x:%x ... \n", NIP6ADDR(&info->mn_iid));
    if (info->msg_event == hasPBU && (info->lifetime.tv_sec > 0 || info->lifetime.tv_nsec > 0)) {
        //Create New Proxy Binding Entry storing information
        dbg("PBU for a new MN ... Location Registration starting now...\n");
        bce = pmip_cache_alloc(BCE_PMIP);
        if (bce != NULL) {
            pmip_insert_into_hnp_cache(hw_address, info->mn_prefix);
            lma_update_binding_entry(bce, info);   //Save information into bce
            lma_reg(bce);
            pmip_cache_add(bce);
            // AnhKhuong: added
#ifdef LMA_BUFFERING
			if (info->PBU_flags & IP6_MH_BU_S_BIT) {
				usleep(100000); /* waite 0.1 second for completing contection MAG <-> MN */
				pmip_buffering_reinject(get_mn_addr(bce), 0);
			}
#endif
        }
    } else if (info->msg_event == hasPBU && info->lifetime.tv_sec == 0 && info->lifetime.tv_nsec == 0) {
	 dbg("PBU with Lifetime = 0 for a not-registered MN... \n");
     lma_dereg(bce, info, 0);
	 pmipcache_release_entry(bce);
	}

    break;
    //--------------------------------------
    case BCE_PMIP:
    if (info->msg_event == hasPBU && (info->lifetime.tv_sec > 0 || info->lifetime.tv_nsec > 0)) {
        dbg("PBU for an existing MN ... update serving MAG\n");
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
#ifdef ETM_METHOD
        dbg("send ETM message \n");
    	dbg("mn_addr: %x:%x:%x:%x:%x:%x:%x:%x mag1: %x:%x:%x:%x:%x:%x:%x:%x mag2: %x:%x:%x:%x:%x:%x:%x:%x\n",
           	    NIP6ADDR(&bce->mn_addr), NIP6ADDR(&bce->mn_serv_mag_addr), NIP6ADDR(&info->src));
    	mh_send_etm (&bce->mn_addr, &info->src, &bce->mn_serv_mag_addr);
#endif
        lma_update_binding_entry(bce, info);
        lma_reg(bce);
        pmipcache_release_entry(bce);
    } else if (info->msg_event == hasPBU && info->lifetime.tv_sec == 0 && info->lifetime.tv_nsec == 0) {
        dbg("PBU with Lifetime = 0... start Location Deregistration\n");
        bce = pmip_cache_get(&conf.OurAddress, &hw_address);
        /* AnhKhuong: added */
        if (info->PBU_flags & IP6_MH_BU_S_BIT) {
#ifdef LMA_BUFFERING
        	pmip_buffering_start(get_mn_addr(bce), 0);
#endif
#ifdef IHR_MESSAGE
			if (mags_info.nhas_mn < mags_info.size)
				mh_send_ihr(bce, 0);
#endif
        }

        // Anh Khuong add for RO
#ifdef USE_PMIP_RO
        if (!undefined_RO) {
			dbg("Send MN Infor to remove in kernel\n");
			pmip_ro_send_mn_info(get_mn_addr(bce));
        }
#endif

        if (IN6_ARE_ADDR_EQUAL(&info->src, &bce->mn_serv_mag_addr)) //Received PBU from serving MAG
        {
			dbg("Deregistration case...\n");
			lma_dereg(bce, info, 1);
			pmipcache_release_entry(bce);
			pmip_bce_delete(bce);
        } else { //Received PBU from an already unregistered MAG
			dbg("Deregistration for an already deregistered MAG\n");
			lma_dereg(bce, info, 0);
			pmipcache_release_entry(bce);
		}
    }
    else if (info->msg_event == hasROT) {
       	dbg("Received ROT message mn_saddr: %x:%x:%x:%x:%x:%x:%x:%x mn_daddr: %x:%x:%x:%x:%x:%x:%x:%x mag_saddr: %x:%x:%x:%x:%x:%x:%x:%x\n",
       	    		    				NIP6ADDR(&info->src_mn_addr), NIP6ADDR(&info->mn_addr), NIP6ADDR(&info->src_mag_addr));
       	pmip_entry_t *bce = NULL;
		struct in6_addr hw_address = eth_address2hw_address(info->mn_addr);
       	bce = pmip_cache_get(&conf.OurAddress, &hw_address);
       	if (bce) {
			dbg("Send ROI to mag \n");
			mh_send_roi(&info->src_mn_addr, &info->mn_addr, &info->src_mag_addr, &bce->mn_serv_mag_addr);
       	}
       	pmipcache_release_entry(bce);
    }
    break;
    default:
    dbg("No action for this event (%d) at current state (%d) !\n", info->msg_event, type);
    }
    return result;
}
