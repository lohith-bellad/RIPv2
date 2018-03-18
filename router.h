/*-----------------------------------------------------------------------------
Filename:-      router.h
Descritption:-  This is the header file for the software IP router project 
                routing process created as part of CSCI558L lab project.
Date:-          Sept 26th 2014 - Oct 5th 2014
Authors:-       Weichen Zhao, Lohith Bellad
                University of Southern California, Los Angeles, California
Platform:-      FreeBSD, Ubuntu 12.04
Place:-         Los Angeles, California
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/types.h>//get all interface
#include <ifaddrs.h>//NI_MAXHOST
#include <netdb.h>
#include <netinet/if_ether.h>//struct ether_header
#include <netinet/ip.h>//struct ip
#include <ctype.h>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <libnet.h>
#include <time.h>
#include <pthread.h>

#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define TYPE_UDP 0x11

//for FLAG in routingTableLookUp parameters
#define RETURN_VALID 0
#define RETUEN_ALL 1

#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3] 

#define MAC_ADDR(addr) \
  (unsigned char) addr[0], \
  (unsigned char) addr[1], \
  (unsigned char) addr[2], \
  (unsigned char) addr[3], \
  (unsigned char) addr[4], \
  (unsigned char) addr[5] 
	  
// basic element for interface <-> socket table
struct ll_addr {
	struct ifaddrs *if_ad;
	int sock_id;
	u_char lan_mac[6];
	u_char self_mac[6];
};

// basic element for routing table
struct routing_table_elem{
	__be32  ip_addr;                      // dst IP addr, from struct in_addr
	__be32  ip_mask;                      // dst IP mask;
	int mask_len;                         // length of mask '/24'
	char intf_name[IFNAMSIZ];             // eth intf name
	int sock_fd;                          // eth intf sock fd <- get from
                                              // intf_sock_table
	unsigned char next_hop_mac[ETH_ALEN]; // next hop MAC addr
	unsigned char out_intf_mac[ETH_ALEN]; // output intf MAC addr
	time_t last_update;                   // time stamp, res: 1 sec 
	int valid;                            // valid bit
	int hop;                              // hop count
};
 
// RIP payload structure 
struct rippayload {
	__u16	family;
	__u16	res2;
	__u32	address;
	__u32	res3;
	__u32	res4;
	__u32	metric;
}; 
 
// RIP header structure 
struct riphdr {
	__u8	comm;
	__u8	version;
	__u16	res1;
};
 

// some useful functions, pretty much useful!!!
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);
int select_wait( int *fd_list, int fd_num, int timeout_sec, int timeout_usec);
int create_socket(const char *name);
int is_routing_port(const char *if_name,char *control);
unsigned int ones32(register unsigned int x);

// routing table interfaces
int routingTableEntryValid( struct routingTableElem *routingTable, int index, \
							int size );
int routingTableUpdate(struct routingTableElem *routingTable, __be32 ip, \
						__be32 mask, const char* name, int sock, \
						const unsigned char *mac, const unsigned char *outMac, \
						int hop, int *size);
int routingTableAddEntry(struct routingTableElem *routingTable, __be32 ip, \
						 __be32 mask, const char* name, int sock, \
						 const unsigned char *mac, const unsigned char *outMac, \
						 int hop, int *size);
int routingTableDelEntry(struct routingTableElem *routingTable, int index); //not implemented
int routingTableLookUp(struct routingTableElem *routingTable, __be32 ip, \
						int size, unsigned char *mac, unsigned char *outMac, \
						int *sock, int *matchIndex, int FLAG);
int routingTableDump(struct routingTableElem *routingTable, int size);

// find MAC address from kernel ARP table
int find_lan_mac_add(struct arpreq *arpreqq,char *IP, char *intf, int handle);

// function to update the TTL and checksum
int UpdateTTL(struct ip *ipptr);

// function to update source and dest MAC addresses
int UpdateMac(struct ether_header *eth_head, u_char *dst_mac, u_char *src_mac);

// function to look up for sock_id from interface table using dest_mac
int find_sock_dmac(struct ll_addr *intfSockTable, int t_size, u_char *d_host);

// function to look up for sock_id from interface table using source_mac
int find_sock_smac(struct ll_addr *intfSockTable, int t_size, u_char *s_host);

// function to create to the ICMP packet
int create_icmp(u_char *buffer, u_char *icmp_buffer, struct ll_addr *intfSockTable, int t_size);

// function to calculate the checksum
uint16_t checksum(void* vdata,size_t length);

// function to build the ETHER header
int buildEther(const u_char* dmac, const u_char* smac, ushort etherType, u_char* buffer);

// function to build the IP header
int buildIp(const u_char* sip, const u_char* dip, ushort type, int extLen, u_char *buffer);

// function to build the udp header
int buildUdp(ushort srcp, ushort dstp, ushort len, u_char* buffer);

// function to find the intface_name from interface table using dest_mac
int find_intf_name(struct ll_addr *intfSockTable, int t_size, u_char *s_host, char *name, u_char *d_host);

// function to create the ICMP host unreachable message
int create_icmp_hu(u_char *buffer, u_char *icmp_buffer, struct ll_addr *intfSockTable, int t_size);
