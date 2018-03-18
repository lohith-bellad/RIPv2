/*-----------------------------------------------------------------------------
Filename:-      router.c
Descritption:-	This is the C file containing aux functions for the software 
                IP router project routing process created as part of CSCI558L 
                lab project.
Date:-          Sept 26th 2014 - Oct 5th 2014
Authors:-       Weichen Zhao, Lohith Bellad
                University of Southern California, Los Angeles, California
Platform:-      FreeBSD, Ubuntu 12.04
Place:-         Los Angeles, California
-----------------------------------------------------------------------------*/
#include "router.h"

void print_hex_ascii_line(const u_char *payload, int len, int offset) {
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
	return;
}

void print_payload(const u_char *payload, int len){

	int len_rem = len;
	int line_width = 16;/* number of bytes per line */
	int line_len;
	int offset = 0;/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

int selectWait( int *fdList, int fdNum, int timeoutSec, int timeoutUsec){
	fd_set fds;
	struct timeval timeout;
	int rc, iter;
	
	timeout.tv_sec = timeoutSec;
	timeout.tv_usec = timeoutUsec;
	FD_ZERO(&fds);
	for(iter = 0; iter < fdNum; iter++){
		FD_SET(fdList[iter], &fds); // set fdList for select
	}
	rc = select(sizeof(fds)*8, &fds, NULL, NULL, &timeout);
	if (rc==-1) {
		perror("select failed\n");
		return -1;
	}
	if (rc > 0){
		for(iter = 0; iter < fdNum; iter++){
			if(FD_ISSET(fdList[iter], &fds)){ // check which fd is ready
				return fdList[iter];
			}
		}
	}
	return 0; // timed out, no ready fd
}

/*
 * Create a socket, and bind to an interface.
 */
int create_socket(const char *name) {
	int handle = 0;
	if (handle = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) < 0) {
		printf("Socket creation failed for interface %s,
			errno = %d\n", name, errno);
		return -1;
	}
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if (strcmp(name, "allintf")) {
		strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		if (ioctl(handle, SIOCGIFINDEX, &ifr) == -1) {
			printf("No such device %s, errno = %d\n", name, errno);
			close(handle);
			return -1;
		}
	} else
		printf("Listening on all interfaces\n");

	struct sockaddr_ll   sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family       = AF_PACKET;
	sll.sll_ifindex      = ifr.ifr_ifindex;
	sll.sll_protocol     = htons(ETH_P_ALL);
	if (bind(handle, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		printf("Fail to bind for interface %s, errno = %d\n",
			name, errno);
		close(handle);
		return -1;
	}
	return handle;
}

int is_routing_port(const char *ifName,char *control) {

	return (memcmp(ifName,"lo",2) != 0) && 
		(memcmp(ifName,control,4) != 0);
}

unsigned int ones32(register unsigned int x) {
	/* code from: http://aggregate.ee.engr.uky.edu/MAGIC
	 * 32-bit recursive reduction using SWAR...
	 * but first step is mapping 2-bit values
	 * into sum of 2 1-bit values in sneaky way
	 */
	x -= ((x >> 1) & 0x55555555);
	x = (((x >> 2) & 0x33333333) + (x & 0x33333333));
	x = (((x >> 4) + x) & 0x0f0f0f0f);
	x += (x >> 8);
	x += (x >> 16);
	return(x & 0x0000003f);
}

/* 
 *         updating conditions
 * +-------------+-----------+--------+
 * | invalid bit | hop count | action |
 * +-------------+-----------+--------+
 * |   invalid   |  > entry  | update | [X]
 * |   invalid   |  < entry  | update | [X]
 * |    valid    |  > entry  |  nope  | [ ]
 * |    valid    |  < entry  | update | [X]
 * +-------------+-----------+--------+
 * > entry ==> bigger than existing entry
 */
int routing_table_entry_valid(struct routing_table_elem *routing_table,
			      int index, int size) {
	return (index >= 0 &&
		index < size &&
		routing_table[index].valid == 1) ? 1 : 0;
}

int routing_table_update(struct routing_table_elem *routing_table, __be32 ip,
			 __be32 mask, const char* name, int sock,
			 const unsigned char *mac, const unsigned char *out_mac,
			 int hop, int *size) {
	int index;
	routing_table_look_up(routing_table, ip, *size, NULL, NULL, NULL,
			      &index, RETURN_ALL);
	if (index == -1) {
		routing_table_add_entry(routing_table, ip, mask, name, sock, mac,
					outMac, hop, size);
	} else if (!routing_table_entry_valid(routing_table, index, *size) ||
					      routing_table[index].hop > hop) {
		routing_table_add_entry(routing_table, ip, mask, name, sock, mac,
					out_mac, hop, &index);
	} else if (memcmp((const char *)mac,
		   (const char *)routing_table[index].next_hop_mac, 6) == 0 ) {
		routing_table[index].last_update = time(NULL);
	}
	return 0;
}

int routing_table_add_entry(struct routing_table_elem *routing_table, __be32 ip,
			    __be32 mask, const char* name, int sock,
			    const unsigned char *mac, const unsigned char *out_mac,
			    int hop, int *size) {
	
	routing_table[*size].ip_addr = ip & mask;
	routing_table[*size].ip_mask = mask;
	strcpy(routing_table[*size].intf_name, name);
	routing_table[*size].sock_fd = sock;
	memcpy((char*)routing_table[*size].next_hop_mac, (const char*)mac, ETH_ALEN);
	memcpy((char*)routing_table[*size].out_intf_mac, (const char*)out_mac, ETH_ALEN);
	routing_table[*size].mask_len = ones32(mask);
	routing_table[*size].hop = hop;
	routing_table[*size].valid = 1;
	routing_table[*size].last_update = time(NULL);

	*size += 1;

	return 0;
}

int routing_table_look_up(struct routing_table_elem *routing_table, __be32 ip,
			  int size, unsigned char *mac, unsigned char *outMac,
			  int *sock, int *matchIndex, int FLAG) {

	int i, index = -1, indexMaskLen = -1;
	__be32 maskedIp;
	for(i=0; i<size; i++){
		maskedIp = ip & routing_table[i].ipMask;
		//printf("MASKED IP %d: %d.%d.%d.%d\n", i, NIPQUAD(maskedIp));
		if( ( maskedIp == routing_table[i].ipAddr ) && \
			( FLAG || routing_table[i].valid ) ){
			//printf("entry matched, index %d\n", i);
			if(index == -1 && indexMaskLen == -1){
				indexMaskLen = routing_table[i].maskLen;
				index = i;
			} else if(routing_table[i].maskLen > indexMaskLen) {
				indexMaskLen = routing_table[i].maskLen;
				index = i;
			}
		} else {
			//printf("index not matched: %d\n", i);
		}
	}
	if(index == -1){
		//printf("failed to find a match\n");
		if( matchIndex )
			*matchIndex = -1;
		return -1;
	}
	// if have parameter matchIndex, assign match index
	if( matchIndex != NULL)
		*matchIndex = index;
	// if have pointer for output sending information, assign
	if( mac && outMac && sock){
		memcpy((char*)mac, (const char*)routing_table[index].next_hop_mac, ETH_ALEN);
		memcpy((char*)outMac, (const char*)routing_table[index].outIntfMac, ETH_ALEN);
		*sock = routing_table[index].sockFd;
	}

	return 0;
}

// function to dump the routing table
int routing_tableDump(struct routing_tableElem *routing_table, int size){
	int i;
	printf("\n+--------------------------------------------------------------------------------------------------------------------------------------------------------------+\n");
	printf("|                                                                  ROUTING TABLE                                                                               |\n");
	printf("+-----------------+-----------------+------------+------------------+--------+-------------------+-------------------+-----------+-----------+-----------------+\n");
	printf("|        IP       |       MASK      |  MASK LEN  |       NAME       |  SOCK  |    Next Hop MAC   |   Out Port MAC    |    HOP    |   VALID   |   LAST UPDATE   |\n");
	printf("+-----------------+-----------------+------------+------------------+--------+-------------------+-------------------+-----------+-----------+-----------------+\n");
	for(i=0; i<size; i++){
		printf("| %3d.%3d.%3d.%3d | %3d.%3d.%3d.%3d | %10d | %16s | %6d | %02x:%02x:%02x:%02x:%02x:%02x | %02x:%02x:%02x:%02x:%02x:%02x | %9d | %9d | %15d |\n", \
		NIPQUAD(routing_table[i].ipAddr), NIPQUAD(routing_table[i].ipMask), \
		routing_table[i].maskLen, routing_table[i].intfName, \
		routing_table[i].sockFd, MAC_ADDR(routing_table[i].next_hop_mac), \
		MAC_ADDR(routing_table[i].outIntfMac), routing_table[i].hop, \
		routing_table[i].valid, (int)routing_table[i].lastUpdate);
	}
	printf("+--------------------------------------------------------------------------------------------------------------------------------------------------------------+\n");
	return 0;
}

// function to find the MAC addresses from ARP table
int find_lan_mac_add(struct arpreq *arpreqq,char *IP, char *intf,int handle)
{
	struct sockaddr_in *sin;
	
     memset(arpreqq, 0, sizeof(struct arpreq));
     sin = (struct sockaddr_in *)&arpreqq->arp_pa;
     sin->sin_family = AF_INET;
     sin->sin_addr.s_addr = inet_addr(IP);
     memcpy(arpreqq->arp_dev,intf,4);
     if (ioctl(handle, SIOCGARP, arpreqq) < 0) 
     {
     		perror("ioctl");
     		exit(1);
     } 
	return 0;
}    

// function to update the IP checksum for decrementing TTL
// return -1 if TTL becomes zero
// CAUTION!!! need to send ICMP
int UpdateTTL(struct ip *ipptr)
{
     unsigned long sum;
     unsigned short old;
     old = ntohs(*(unsigned short *)&ipptr->ip_ttl);
     ipptr->ip_ttl -= 1; // decrementing by 1 always
     sum = old + (~ntohs(*(unsigned short *)&ipptr->ip_ttl) & 0xffff);
     sum += ntohs(ipptr->ip_sum);
     sum = (sum & 0xffff) + (sum>>16);
     ipptr->ip_sum = htons(sum + (sum>>16));
	if(ipptr->ip_ttl == 0)
		return -1;
	else
		return 0;
}

// function to update the source and destination MAC addresses
int UpdateMac(struct ether_header *eth_head, u_char *dst_mac, u_char *src_mac)
{
	struct ether_header *loc_hdr;
	loc_hdr = eth_head;
	memcpy((char *)loc_hdr->ether_dhost,(const char *)dst_mac,6);
	memcpy((char *)loc_hdr->ether_shost,(const char *)src_mac,6);
	return 0;
}

// function to find the sock_id from interface table using dest_mac
int find_sock_dmac(struct ll_addr *intfSockTable, int t_size, u_char *d_host)
{
	int i;
	for(i = 0; i < t_size; i++)
		if( (memcmp((char *)intfSockTable[i].self_mac,(char *)d_host,6)) == 0)
			return intfSockTable[i].sock_id;
	return -1;
}

// function to find the sock_id from interface table using dest_mac
int find_sock_smac(struct ll_addr *intfSockTable, int t_size, u_char *s_host)
{
	int i;
	for(i = 0; i < t_size; i++)
		if( (memcmp((char *)intfSockTable[i].lan_mac,(char *)s_host,6)) == 0)
			return intfSockTable[i].sock_id;
	return -1;
}

// function to find the intface_name from interface table using dest_mac
int find_intf_name(struct ll_addr *intfSockTable, int t_size, u_char *s_host, char *name, u_char *d_host)
{
	int i;
	for(i = 0; i < t_size; i++)
	{
		if( (memcmp((char *)intfSockTable[i].lan_mac,(char *)s_host,6)) == 0)
		{
			memcpy(name,intfSockTable[i].if_ad->ifa_name,strlen(intfSockTable[i].if_ad->ifa_name));
			memcpy(d_host,intfSockTable[i].self_mac,6);
			return 0;
		}
	}
	return -1;
}

// function to create the ICMP packet
int create_icmp(u_char *buffer, u_char *icmp_buffer, struct ll_addr *intfSockTable, int t_size)
{
	struct icmphdr *icmp_hdr;
	struct sockaddr_in *sock_addr;
	int i,found = 0;
	unsigned short check_sum;
	struct ip *iphdr;
	
	// finding the IP address of the interface on which we are sending the data
	for(i = 0; i < t_size; i++)
	{
		if( (memcmp((char *)intfSockTable[i].self_mac,buffer,6)) == 0)
		{
			sock_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_addr;
			found = 1;
			break;
		}
	}
	if(found == 0){
		printf("no matching interfaces\n");
		return -1;
	}
	
	// swapping the src and dst MAC addresses
	memcpy(icmp_buffer,&buffer[6],6);
	memcpy(&icmp_buffer[6],buffer,6);
	// Add ethernet_type
	memcpy(&icmp_buffer[12],&buffer[12],2);

	// building the IP header
	iphdr = (struct ip*)&icmp_buffer[14];
	memset(iphdr,0,sizeof(struct iphdr));
	iphdr->ip_v 		= 4; 	
	iphdr->ip_hl		= 5; 	
	iphdr->ip_tos		= '\xC0';
	iphdr->ip_len		= htons(88);
	iphdr->ip_id		= htons(0x8ea6);
	iphdr->ip_off		= 0;
	iphdr->ip_ttl       = 64;
	iphdr->ip_p		= 1;	
	iphdr->ip_sum		= 0;	
	memcpy(&icmp_buffer[26],(&sock_addr->sin_addr.s_addr),4);
	memcpy(&icmp_buffer[30],&buffer[26],4);
	check_sum = checksum((void *)&icmp_buffer[14],20);
	memcpy(&icmp_buffer[24],&check_sum,2);


	// building the ICMP header
	icmp_hdr = (struct icmphdr *)&icmp_buffer[34];
	memset(icmp_hdr,0,sizeof(struct icmphdr));
	icmp_hdr->type = 11;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	
	//Adding the payload (IP and UDP data of request packet)
	memcpy(&icmp_buffer[42],&buffer[14],60);
	check_sum = checksum((void *)&icmp_buffer[34],68);
	memcpy(&icmp_buffer[36],&check_sum,2);
	
	return 102; // always return 102 bytes not a problem!!!
}

// function to create ICMP host unreachable message
int create_icmp_hu(u_char *buffer, u_char *icmp_buffer, struct ll_addr *intfSockTable, int t_size)
{
	struct icmphdr *icmp_hdr;
	struct sockaddr_in *sock_addr;
	int i,found = 0;
	unsigned short check_sum;
	struct ip *iphdr;
	
	// finding the IP address of the interface on which we are sending the data
	for(i = 0; i < t_size; i++)
	{
		if( (memcmp((char *)intfSockTable[i].self_mac,buffer,6)) == 0)
		{
			sock_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_addr;
			found = 1;
			break;
		}
	}
	if(found == 0){
		printf("no matching interfaces\n");
		return -1;
	}
	
	// swapping the src and dst MAC addresses
	memcpy(icmp_buffer,&buffer[6],6);
	memcpy(&icmp_buffer[6],buffer,6);
	// Add ethernet_type
	memcpy(&icmp_buffer[12],&buffer[12],2);

	// building the IP header
	iphdr = (struct ip*)&icmp_buffer[14];
	memset(iphdr,0,sizeof(struct iphdr));
	iphdr->ip_v 		= 4; 	
	iphdr->ip_hl		= 5; 	
	iphdr->ip_tos		= 0;
	iphdr->ip_len		= htons(56);
	iphdr->ip_id		= htons(0x8807);
	iphdr->ip_off		= 0;
	iphdr->ip_ttl       = 64;
	iphdr->ip_p		= 1;	
	iphdr->ip_sum		= 0;	
	memcpy(&icmp_buffer[26],(&sock_addr->sin_addr.s_addr),4);
	memcpy(&icmp_buffer[30],&buffer[26],4);
	check_sum = checksum((void *)&icmp_buffer[14],20);
	memcpy(&icmp_buffer[24],&check_sum,2);


	// building the ICMP header
	icmp_hdr = (struct icmphdr *)&icmp_buffer[34];
	memset(icmp_hdr,0,sizeof(struct icmphdr));
	icmp_hdr->type = 3;
	icmp_hdr->code = 1;
	icmp_hdr->checksum = 0;
	
	//Adding the payload (IP and UDP data of request packet)
	memcpy(&icmp_buffer[42],&buffer[14],28);
	check_sum = checksum((void *)&icmp_buffer[34],36);
	memcpy(&icmp_buffer[36],&check_sum,2);
	
	return 70; // always return 102 bytes not a problem!!!
}

// function to create checksum
uint16_t checksum(void* vdata,size_t length) 
{
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

//build ether header
int buildEther(const u_char* dmac, const u_char* smac, ushort etherType, u_char* buffer)
{
	struct ether_header *eth = (struct ether_header*)buffer;
	memcpy(eth->ether_dhost, dmac, 6);
	memcpy(eth->ether_shost, smac, 6);
	eth->ether_type = htons(etherType);
	return 0;
}

//build IP header
int buildIp(const u_char* sip, const u_char* dip, ushort type, int extLen, u_char *buffer)
{
	struct iphdr *ip = (struct iphdr*)buffer;

	ip->ihl = 5;
	ip->version = 4;
	ip->tot_len = htons(sizeof(struct iphdr) + extLen); // udp->8
	ip->frag_off = 0;
	ip->id = htons(54321);
	ip->ttl = 64; // hops
	ip->protocol = type;
	memset(&ip->check, 0, sizeof(ip->check));
	memcpy(&ip->saddr, sip, 4);
	memcpy(&ip->daddr, dip, 4);
	ip->check = checksum(buffer, (ip->ihl)*4 );
	return 0;
}

// build UDP header
int buildUdp(ushort srcp, ushort dstp, ushort len, u_char* buffer){
	struct udphdr *udp = (struct udphdr*)buffer;
	udp->source = htons(srcp);
	udp->dest = htons(dstp);
	udp->len = htons(len);
	memset(&udp->check, 0, sizeof(udp->check));
	return 0;
}


