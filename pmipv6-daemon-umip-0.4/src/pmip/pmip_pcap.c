/*! \file pmip_pcap.c
* \brief Analyse of captured packets
* \author OpenAir3 Group
* \date 12th of October 2010
* \version 1.0
* \company Eurecom
* \project OpenAirInterface
* \email: openair3@eurecom.fr
*/
#define PMIP
#define PMIP_PCAP_C
#ifdef HAVE_CONFIG_H
#	include <config.h>
#endif
#include <string.h>
#include <ctype.h>
//---------------------------------------------------------------------------------------------------------------------
#include "pmip_fsm.h"
#include "pmip_hnp_cache.h"
#include "pmip_pcap.h"
#include "pmip_msgs.h"
//---------------------------------------------------------------------------------------------------------------------
#ifdef ENABLE_VT
#    include "vt.h"
#endif
#include "debug.h"
#include "conf.h"
//---------------------------------------------------------------------------------------------------------------------
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
pmip_pcap_print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");
}
//---------------------------------------------------------------------------------------------------------------------
/*
 * print packet payload data (avoid printing binary data)
 */
void
pmip_pcap_print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		pmip_pcap_print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		pmip_pcap_print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			pmip_pcap_print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
}
//---------------------------------------------------------------------------------------------------------------------

//Anh Khuong add for MN report message
void pmip_pcap_msg_handler_report(struct in6_addr mn_iidP, int iifP, char* nmag_addr)
{
    dbg("pmip_pcap_msg_handler_report()\n");
    msg_info_t msg;
    memset(&msg, 0, sizeof(msg_info_t));
    msg.mn_iid = hw_address2eth_address(mn_iidP);
    msg.iif = iifP;
    msg.msg_event = hasREPORT;
    inet_pton(AF_INET6, nmag_addr, &(msg.mn_info_mag_addr));
    mag_fsm(&msg);
}

void pmip_pcap_msg_handler_associate_smartbuff(struct in6_addr mn_iidP, int iifP, char* mag_addr)
{
	dbg("pmip_pcap_msg_handler_associate()\n");
	    gettimeofday(&time_info.time_start, NULL); /* calculate handover period for statistic */
	    msg_info_t msg;
	    memset(&msg, 0, sizeof(msg_info_t));
	    msg.mn_iid = hw_address2eth_address(mn_iidP);
	    msg.iif = iifP;
	    msg.msg_event = hasWLCCP;
	    msg.flag = 4;
	    inet_pton(AF_INET6, mag_addr, &(msg.mn_info_mag_addr));
	    mag_fsm(&msg);
}
//Anh Khuong: end

/*!
*  Construct message event and send it to the MAG FSM
* \param
*  AnhKhuong add S bit
*/
void pmip_pcap_msg_handler_associate(struct in6_addr mn_iidP, int iifP, int flag)
{
    dbg("pmip_pcap_msg_handler_associate()\n");

    gettimeofday(&time_info.time_start, NULL); /* calculate handover period for statistic */
    msg_info_t msg;
    memset(&msg, 0, sizeof(msg_info_t));
    msg.mn_iid = hw_address2eth_address(mn_iidP);
    msg.iif = iifP;
    msg.msg_event = hasWLCCP;
    msg.flag = flag;
    mag_fsm(&msg);
}
//---------------------------------------------------------------------------------------------------------------------
void pmip_pcap_msg_handler_deassociate(struct in6_addr mn_iidP, int iifP, int flag)
{
    dbg("pmip_pcap_msg_handler_desassociate() flag = %d\n", flag);
    msg_info_t msg;
    memset(&msg, 0, sizeof(msg_info_t));
    msg.mn_iid = hw_address2eth_address(mn_iidP);
    msg.iif = iifP;
    msg.msg_event = hasDEREG;
    msg.flag = flag;
    mag_fsm(&msg);
}
//---------------------------------------------------------------------------------------------------------------------
void pmip_pcap_loop(char *devname, int iif)
{
    bpf_u_int32 netaddr = 0, mask = 0;  // To store network address and netmask
    struct bpf_program filter;  // Place to store the BPF filter program
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer
    struct pcap_pkthdr pkthdr;  // Packet information (timestamp, size...)
    const unsigned char *packet = NULL; // Received raw data
    struct in6_addr mn_iid;
    char filter_string[] = "udp port 514";
    char addrmac[16];
    char addrmacByte[16];
    char *p;
    int b, j, count;

    dbg("[PCAP] Device is %s and iif is %d\n", devname, iif);

    pcap_descr = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    memset(&mn_iid, 0, sizeof(struct in6_addr));
    pcap_descr = pcap_open_live(devname, PCAPMAXBYTES2CAPTURE, 0, PCAPTIMEDELAYKERNEL2USERSPACE, errbuf);
    if (pcap_descr == NULL)
        dbg("Error %s", errbuf);
    else if (*errbuf)
        dbg("Warning %s\n", errbuf);

// Look up info from the capture device
    if (pcap_lookupnet(devname, &netaddr, &mask, errbuf) == -1) {
        dbg("Can't get netmask for device %s\n", devname);
        netaddr = 0;
        mask = 0;
    }

// Compiles the filter expression into a BPF filter program
    if (pcap_compile(pcap_descr, &filter, filter_string, 0, mask) == -1) {
        dbg("Couldn't parse filter : %s\n", pcap_geterr(pcap_descr));
   }
// Load the filter program into the packet capture device
    if (pcap_setfilter(pcap_descr, &filter) == -1) {
        dbg("Couldn't install filter: %s\n", pcap_geterr(pcap_descr));
    }

    while (1) {
        packet = pcap_next(pcap_descr, &pkthdr);    // Get one packet
        if ( ( pkthdr.len > 0 ) && ( packet != NULL ) ){
             dbg("[PCAP] RECEIVED PACKET SIZE: %d bytes caplen %d bytes\n", pkthdr.len, pkthdr.caplen);
        	// approx 50 bytes for MAC + IP + UDP headers
        	if ((p = strstr((const char *)(&packet[50]), "Station")) != NULL) {
			p = p + strlen("Station");
            		count = 0;
            		j = 0;
	    		while ((count < 12) && (j < 32)) {
					if (isxdigit(p[j])) {
							addrmac[count++] = p[j] ;
					}
					j++;
            	}
				addrmac[count] = '\0';
		//		dbg ("Before conversion : %s \n", addrmac);

				// convert ascii hex string to bin
				for (b = 0 ; b < 6; b++) {
					strncpy(addrmacByte, addrmac+2*b, 2);
					addrmacByte[2] = '\0';
					// we can do (unsigned int*) because x86 processors are little-endian
					// (done for suppressing a warning)
					sscanf ((const char*)addrmacByte, "%02x", (unsigned int*)&mn_iid.s6_addr[10 + b]);
				}

				if (strstr((const char *)&packet[50], "-ASSOC")) {
					if (strstr((const char *)&packet[50], "S_BIT"))
						pmip_pcap_msg_handler_associate(mn_iid, iif, 1);
					else if (strstr((const char *)&packet[50], "SMARTBUFF"))
						pmip_pcap_msg_handler_associate_smartbuff(mn_iid, iif, 4);
					else if (strstr((const char *)&packet[50], "pMAG")) {
						// Get pMAG address
						char* ptmp;
						char stmp[64];
						strncpy(stmp, strstr((const char *)&packet[50], "-ASSOC") + strlen("-ASSOC "), 63);
						ptmp = strstr(stmp, " pMAG");
						ptmp[0] = 0;
						pmip_pcap_msg_handler_associate(mn_iid, iif, stmp);
					}
					else
						pmip_pcap_msg_handler_associate(mn_iid, iif, 0);
				} else if (strstr((const char *)&packet[50], "-DISASSOC")) {
					if (strstr((const char *)&packet[50], "S_BIT"))
						pmip_pcap_msg_handler_deassociate(mn_iid, iif, SBIT_FLAG);
					else if (strstr((const char *)&packet[50], "FPMIP"))
						pmip_pcap_msg_handler_deassociate(mn_iid, iif, FPMIP_FLAG);
					else if (strstr((const char *)&packet[50], "RSS_NOTFIY"))
						pmip_pcap_msg_handler_deassociate(mn_iid, iif, RSS_FLAG);
					else if (strstr((const char *)&packet[50], "SMARTBUFF"))
						pmip_pcap_msg_handler_deassociate(mn_iid, iif, SMARTBUFF_FLAG);
					else
						pmip_pcap_msg_handler_deassociate(mn_iid, iif, 0);
				} else if (strstr((const char *)&packet[50], "-REPORT")) {
					// Get nMAG address
					char* ptmp;
					char stmp[64];
					strncpy(stmp, strstr((const char *)&packet[50], "-REPORT") + strlen("-REPORT "), 63);
					ptmp = strstr(stmp, " nMAG");
					ptmp[0] = 0;
					pmip_pcap_msg_handler_report(mn_iid, iif, stmp);
				}
			}
        }
    }
}

