/*-----------------------------------------------------------------------------
Filename:- 	test.c
Descritption:- This is the main implementation C file for the software IP 
			router project routing process created as part of CSCI558L 
			lab project.
Date:-		Sept 26th 2014 - Oct 5th 2014
Authors:- 	Lohith Bellad,Weichen Zhao
			University of Southern California, Los Angeles, California
Platform:- 	Mac OS X Mountain Lion, Ubuntu 12.04
Place:-		Los Angeles, California
-----------------------------------------------------------------------------*/
#include "router.h"

struct routingTableElem route_table[50];//creating table for large number of networks
struct ll_addr* intfSockTable;//pointer to socket <-> interface table
int t_size;//routing table size
int intfCount = 0;

// function to send RIP response packets
int sendRipResponse(){
    int i, ret = 0, err = 0;
    struct sockaddr_in *sock_addr,*mask_addr;
    struct rippayload *rip_payload;
    u_char rip_res_buffer[1500],rip_rt[500];
    u_char rip_dip[4] = "\xE0\x00\x00\x09";
    u_char rip_req_buffer[100]; 
    struct riphdr *rip_hdr;
    u_char multicast[6] = "\x01\x00\x5e\x00\x00\x09";
    unsigned long masked_addr;
  
    // build RIP request message
    memset(rip_req_buffer,0,sizeof(rip_req_buffer));
    rip_hdr = (struct riphdr *)&rip_req_buffer[42];
    rip_hdr->comm = 1;
    rip_hdr->version = 2;
    rip_hdr->res1 = 0;
	
    for( i=0; i < intfCount; i++)
    {
		mask_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_netmask;
		sock_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_addr;
		masked_addr = (sock_addr->sin_addr.s_addr & mask_addr->sin_addr.s_addr);
		rip_payload = (struct rippayload *)&rip_rt[i*20];
		rip_payload->family = htons(2);
		rip_payload->res2 = 0;
		memcpy((char *)&rip_payload->address,(char *)&masked_addr,4);
		memcpy((char *)&rip_payload->res3,(char *)&mask_addr->sin_addr.s_addr,4);
		//printf("%d.%d.%d.%d\n", NIPQUAD(rip_payload->address));
		rip_payload->address &= rip_payload->res3; // the address must be masked
		//printf("%d.%d.%d.%d\n", NIPQUAD(rip_payload->address));
		rip_payload->res4 = 0;
		rip_payload->metric = htonl(1);		
	}
	
    for( i=0; i < intfCount; i++)
	{
		// create headers
		sock_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_addr;
    		buildEther(multicast, intfSockTable[i].self_mac, 0x0800, rip_req_buffer);
		buildIp((u_char *)&sock_addr->sin_addr.s_addr,rip_dip, 17, 32, rip_req_buffer + ETH_HDR_LEN);
		buildUdp(520, 520, 32, rip_req_buffer + ETH_HDR_LEN + IP_HDR_LEN);

		// build the RIP response packets 
		buildIp((u_char *)&sock_addr->sin_addr.s_addr,rip_dip, 17, (8+4+(intfCount*20)), rip_req_buffer + ETH_HDR_LEN);
		buildUdp(520, 520, (8+4+(intfCount*20)), rip_req_buffer + ETH_HDR_LEN + IP_HDR_LEN);
		
		memcpy(rip_res_buffer,rip_req_buffer,42);
  	        rip_hdr = (struct riphdr *)&rip_res_buffer[42];
    
	 	rip_hdr->comm = 2;
	 	rip_hdr->version = 2;
	 	rip_hdr->res1 = 0;
		memcpy(&rip_res_buffer[46],rip_rt, (intfCount*20));
		ret = 46 + (intfCount*20);
		//print_payload(rip_res_buffer, ret);
		// send the RIP response packet
		if( (err = send(intfSockTable[i].sock_id,rip_res_buffer,ret,0)) != ret)
		{
			printf("Error sending the RIP response packet\n");
			exit(1);
		}
	}
	return 0;
}

// function to send the RIP response packets
int sendRipRequest(){
	int i, ret = 0, err = 0;
    struct sockaddr_in *sock_addr;//,*mask_addr;
    struct rippayload *rip_payload;
    //u_char rip_res_buffer[1500],
	//u_char rip_rt[500];
    u_char rip_dip[4] = "\xE0\x00\x00\x09";
	u_char rip_req_buffer[100]; 
    struct riphdr *rip_hdr;
    u_char multicast[6] = "\x01\x00\x5e\x00\x00\x09";
	
    // build RIP request message
    memset(rip_req_buffer,0,sizeof(rip_req_buffer));
    rip_hdr = (struct riphdr *)&rip_req_buffer[42];
    rip_hdr->comm = 1;
    rip_hdr->version = 2;
    rip_hdr->res1 = 0;
    rip_payload = (struct rippayload *)&rip_req_buffer[46];
    rip_payload->family = 0;// payload
    rip_payload->res2 = 0;
    rip_payload->address = 0;
    rip_payload->res3 = 0;
    rip_payload->res4 = 0;
    rip_payload->metric = htonl(16);
	
    // loop to send RIP request and response messages on all interfaces
    for( i=0; i < intfCount; i++)
    {
	    sock_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_addr;
	    // build ether header
    	    buildEther(multicast, intfSockTable[i].self_mac, 0x0800, rip_req_buffer);
	    // build IP header
	    buildIp((u_char *)&sock_addr->sin_addr.s_addr,rip_dip, 17, 32, rip_req_buffer + ETH_HDR_LEN);
	    // build udp header
	    buildUdp(520, 520, 32, rip_req_buffer + ETH_HDR_LEN + IP_HDR_LEN);
	    ret = 68;
	    // send the request packet!!!
	    if( (err = send(intfSockTable[i].sock_id,rip_req_buffer,ret,0)) != ret)
	    	{
			printf("Error sending the RIP request packet\n");
			exit(1);
		}	
    }
	return 0;
}

// need two parameters, one is routing table, the other one is intf <-> sock table
void *check( ){
	int i;
	printf("RIP thread started\n");
	while(1){
		selectWait(NULL, 0, 30, 0);
		// check all the valid entry, see if anyone should be expired
		for(i = intfCount; i < t_size; i++){
			if(route_table[i].valid)
				if(time(NULL) - route_table[i].lastUpdate > 180)
					route_table[i].valid = 0;
		}
		routingTableDump(route_table, t_size);
		printf("RIP thread sent RIP response\n");
		// send response packets
		sendRipResponse();
		routingTableDump(route_table, t_size);
	}
}
// main function hahahaaaa
int main(int argc, char **argv)
{
   // stack variables  
   int handle = 0,ret=0,s;
   uint8_t* mac;
   u_char dst_mac[4],*ptrr;
   struct ifreq ifr;
   u_char buffer[1500],icmp_buffer[1500];//, rip_req_buffer[100];
   //u_char rip_res_buffer[1500],
   struct ifaddrs *addrs,*tmp;
   char host[NI_MAXHOST], mask[NI_MAXHOST];
   //struct ll_addr* intfSockTable;
   int tableIndex = 0;
   struct sockaddr_ll sll;
   struct sockaddr_in *sock_addr,*mask_addr; 
   struct ether_header *eth_hdr;
   struct ip *ip_hdr;
   int i,err,icmp_check,sending_sock;
   struct arpreq arpreqq;
   //struct routingTableElem route_table[50];//creating table for large number of networks
   __be32 dest_ip;
   u_char *ptr;
   u_char fin_dst_mac[6], fin_src_mac[6];
   

   
#ifdef FUNCTION_DEMO
   u_char *res_ptr;
   int hop_cnt;   
   struct riphdr *rip_hdr;
   struct udphdr *udp_hdr;
   int num_entries_res = 0;
   char int_name[5];
   u_char dd_host[6];
   pthread_t wait;
   struct in_addr *sock_addr_r,*mask_addr_r;
   u_char rip_rt[500];
#endif  	   
   // recieving the DETER control network interface to neglect it in our program		   
   if(argc < 1)
   {
	   printf("Usage: sudo ./route eth#");
	   return 0;
   }
   
   // sending PING to build the kernel ARP table
   //----------------------------------------------Please modify here accordingly, dont neglect the DEMO-------------------------------------------
   if( (err = system("ping 10.1.1.2 -c 1")) < 0)
   {
    		printf("Failed in building ARP table\n");
   	 	exit(0);
   }
   if( (err = system("ping 10.2.1.2 -c 1")) < 0)
   {
    		printf("Failed in building ARP table\n");
    	 	exit(0);
   }
   if( (err = system("ping 10.3.1.2 -c 1")) < 0)
   {
    		printf("Failed in building ARP table\n");
    	 	exit(0);
   }
   if( (err = system("ping 10.4.1.2 -c 1")) < 0)
   {
    		printf("Failed in building ARP table\n");
    	 	exit(0);
   }
   // create raw socket that listens to everything, the father of all...
   handle = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   memset(&ifr, 0, sizeof(ifr));
   memset(&sll, 0, sizeof(sll));
   sll.sll_family    = AF_PACKET;
   sll.sll_protocol  = htons(ETH_P_ALL);//htons(0x3333)
   if ( bind( handle, (struct sockaddr *) &sll, sizeof(sll)) == -1 )
   {
      printf("fail binding\n");
      return 0;
   }
   printf("Binding listening socket to %x\n", sll.sll_protocol);
   getifaddrs(&addrs);
   tmp = addrs;
   //checking the number of interfaces
   while (tmp)
   {
       if (tmp->ifa_addr->sa_family == AF_INET)
			intfCount += 1;
		tmp = tmp->ifa_next;
   }
   intfCount -= 2;
   // print some info of interfaces
   printf("----------------------------------------------------------------------------------------------------------\n");
   printf("Total number of custom routing interfaces is: %d\n",intfCount);
   printf("------------------------------------------------\n");
   printf("Name\t    IP\t\t  SUBNET MASK\t\t    MAC Address\n");
   printf("----\t    --\t\t  -----------\t\t    -----------\n");
   // allocation memory for intf <-> socket table
   intfSockTable = malloc((intfCount) * sizeof(struct ll_addr));
   ptrr = dst_mac;
   tmp = addrs;
   while (tmp)
   {
   		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
		{
       	   printf("%s", tmp->ifa_name);
       	   //family = tmp->ifa_addr->sa_family;

       	   s = getnameinfo(tmp->ifa_addr, sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
             s |= getnameinfo(tmp->ifa_netmask, sizeof(struct sockaddr_in),mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
             if (s != 0) 
	  	   {
          	  printf("getnameinfo() failed: %s\n", gai_strerror(s));
           	  exit(EXIT_FAILURE);
	  	   }
       	   printf("\t<%s>\t <%s>", host, mask);
	  	   strcpy( ifr.ifr_name, tmp->ifa_name );
		   if( ioctl( handle, SIOCGIFHWADDR, &ifr ) != -1 )
		   {
			   if(strncmp(tmp->ifa_name,"lo",2))
		           {
			   	mac = (uint8_t*)ifr.ifr_ifru.ifru_hwaddr.sa_data;
		        	printf( "\t<%02X:%02X:%02X:%02X:%02X:%02X>\n",MAC_ADDR(mac));
			   }
			   else
				   printf("\t\t\t---\n");
			   if( isRoutingPort(tmp->ifa_name,argv[1]) )
			   {
				   intfSockTable[tableIndex].sock_id = createSocket(tmp->ifa_name);
			 	   intfSockTable[tableIndex].if_ad = tmp;
				   memcpy(intfSockTable[tableIndex].self_mac,ifr.ifr_ifru.ifru_hwaddr.sa_data,6);
				   tableIndex += 1;
			  	   sprintf((char *)ptrr,"%c",mac[5]);
				   ptrr = ptrr+1;
			   }
       	   	    }
		}
    	 	tmp = tmp->ifa_next;
    }
    //------------------------------------Please modify here accordingly, dont neglect the DEMO, nah!!!----------------------------------------
    find_lan_mac_add(&arpreqq,"10.1.1.2", "eth0",handle);	
    mac = (uint8_t*)&arpreqq.arp_ha.sa_data;
    memcpy(intfSockTable[0].lan_mac,arpreqq.arp_ha.sa_data,6);
   
    find_lan_mac_add(&arpreqq,"10.2.1.2", "eth1",handle);	
    mac = (uint8_t*)&arpreqq.arp_ha.sa_data;
    memcpy(intfSockTable[1].lan_mac,arpreqq.arp_ha.sa_data,6);
    
    find_lan_mac_add(&arpreqq,"10.3.1.2", "eth5",handle);	
    mac = (uint8_t*)&arpreqq.arp_ha.sa_data;
    memcpy(intfSockTable[2].lan_mac,arpreqq.arp_ha.sa_data,6);
    
    find_lan_mac_add(&arpreqq,"10.4.1.2", "eth5",handle);	
    mac = (uint8_t*)&arpreqq.arp_ha.sa_data;
    memcpy(intfSockTable[3].lan_mac,arpreqq.arp_ha.sa_data,6);
    
   
    // Adding static routing table entries to the table, depending on interfaces used for custom routing 
    for( i=0; i < intfCount ; i++)
    {
	     sock_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_addr;
		mask_addr = (struct sockaddr_in *)intfSockTable[i].if_ad->ifa_netmask;
    		err = routingTableAddEntry(route_table, ((sock_addr->sin_addr.s_addr) & (mask_addr->sin_addr.s_addr)) , mask_addr->sin_addr.s_addr, intfSockTable[i].if_ad->ifa_name,\
    		 	intfSockTable[i].sock_id,intfSockTable[i].lan_mac , intfSockTable[i].self_mac,1,&t_size);
    }   
    err = routingTableDump(route_table, t_size);
#ifdef FUNCTION_DEMO
    	
	// creating threads
	pthread_create(&wait, NULL, check, NULL);
    
	// sending request and response packets
	sendRipRequest();
	sendRipResponse();
#endif    
   // Forever loop!!!, capture packets and forward it, as fast as possible, anyways!!!, go packets gooooo, 
   while(1)
   {
      memset(&buffer, 0, sizeof(buffer));
	 memset(&icmp_buffer,0,sizeof(icmp_buffer));
      ret = recv(handle, buffer, sizeof(buffer), 0);
      if(ret > 0)
	 {
         eth_hdr = (struct ether_header *)buffer;
         if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
	    {
		    if(dst_mac[0] == eth_hdr->ether_dhost[5] || dst_mac[1] == eth_hdr->ether_dhost[5] || eth_hdr->ether_dhost[5] == '\x09' || dst_mac[2] == eth_hdr->ether_dhost[5])
		    {
			    /*-------------------------------the main routing part-------------------------------*/
			    // parsing IP header
				ip_hdr = (struct ip*)&buffer[14];
#ifdef FUNCTION_DEMO				
				// check for UDP packets 
				if(ip_hdr->ip_p == TYPE_UDP)
				{
					udp_hdr = (struct udphdr *)&buffer[34];
					//printf("UDP, %d, %d\n", udp_hdr->dest, htons(520));
					
					// check for RIP_V2 response packets 
					if(udp_hdr->dest == htons(520))
					{
						//printf("%c %c %c %c\n",eth_hdr->ether_shost[5],dst_mac[0],dst_mac[1],dst_mac[2]);
						// neglect self response packets
						if(eth_hdr->ether_shost[5] == dst_mac[0] || eth_hdr->ether_shost[5] == dst_mac[1] || eth_hdr->ether_shost[5] == dst_mac[2])
							continue;
					
						rip_hdr = (struct riphdr *)&buffer[42];
						if(rip_hdr->comm == 2)// we got a response packet here, hurray!!!, time to update our routing table
						{
							//printf("got RIP packet\n");
							memset(rip_rt,0,sizeof(rip_rt));
							memset(int_name,0,sizeof(int_name));
							// get the interface name
							if( (err = find_intf_name(intfSockTable,intfCount,eth_hdr->ether_shost,int_name,dd_host)) < 0)
							{
								printf("Error getting interface name\n");
								continue;//exit(1);
							}
							// get the sending socket id
							if( (sending_sock = find_sock_smac(intfSockTable,intfCount,eth_hdr->ether_shost)) < 0)
							{
								printf("Error looking up the Interface table for sock_id\n");
								continue;//exit(1);
							}
							// So, updating our routing table
							num_entries_res = (ret - 46) / 20;// each entry has 20bytes of info
							memcpy(rip_rt,&buffer[46],ret-46);
							res_ptr = rip_rt;
							// parsing the received entries and updating the table
							for(i = 0; i < num_entries_res; i++)
							{
								hop_cnt = (int)ntohl(*((uint32_t*)(res_ptr + 16)));
								sock_addr_r = (struct in_addr *)(res_ptr + 4);
								mask_addr_r = (struct in_addr *)(res_ptr + 8);
								
								routingTableUpdate(route_table,((sock_addr_r->s_addr) & (mask_addr_r->s_addr)) , mask_addr_r->s_addr, \
									(char *)&int_name, sending_sock,(unsigned char *)eth_hdr->ether_shost, (unsigned char *)dd_host,hop_cnt+1,&t_size);	
								res_ptr += 20; // each entry is 20 bytes
								
							}
							routingTableDump(route_table, t_size);
						}
						continue;
					}
				}
#endif
				//#ifdef FUNCTION_DEMO 
			    	//After recieving packet, update the TTL
				// send the ICMP time-exceeded packet back to host
				if( (icmp_check = UpdateTTL(ip_hdr)) < 0)
				{
					if( (ret = create_icmp(buffer, icmp_buffer,intfSockTable,intfCount)) < 0)
						printf("Error creating the ICMP Time exceeded packet\n");
				
					if( (sending_sock = find_sock_dmac(intfSockTable,intfCount,eth_hdr->ether_dhost)) < 0)
						printf("Error looking up the Interface table\n");
					
					if( (err = send(sending_sock,icmp_buffer,ret,0)) != ret)
						printf("Error sending the ICMP Time exceeded packet\n");
						
					continue;
				}	 
			     else
				{
					//finding destination IP address of the packet 
					dest_ip = ip_hdr->ip_dst.s_addr;
					//Looking up the dest_ip next hop MAC
					if( (err = routingTableLookUp(route_table, dest_ip,t_size, fin_dst_mac, fin_src_mac, &sending_sock, NULL, RETURN_VALID)) < 0)
					{	
						// if error in looking up, send ICMP host unreachable message back to host
						if( (ret = create_icmp_hu(buffer, icmp_buffer,intfSockTable,intfCount)) < 0)
							printf("Error creating the ICMP Time exceeded packet\n");
							
						if( (sending_sock = find_sock_dmac(intfSockTable,intfCount,eth_hdr->ether_dhost)) < 0)
							printf("Error looking up the Interface table\n");
						
						if( (err = send(sending_sock,icmp_buffer,ret,0)) != ret)
							printf("Error sending the ICMP Time exceeded packet\n");
	
						continue;
					}
				
					//#endif
					// update the source and destination mac of outgoing packet
					UpdateMac(eth_hdr, fin_dst_mac, fin_src_mac);
					// Finally....Uhff...send(route) the packet 
					if( (err = send(sending_sock,buffer,ret,0)) != ret)
					{
						printf("Error in sending(routing) the packet\n");
						continue;// if error in sending the packet, drop it and continue with the next packet
					}	
					//#ifdef FUNCTION_DEMO 
				}
				//#endif	
				/*--------------------------------------------------------------------*/
				// Printing the packet recieved info, comment it if not required, thank you	
				/*ptr = eth_hdr->ether_shost;
	    			printf("Source MAC: ");
	     		i = ETHER_ADDR_LEN;
	     		do
				{
	     	    	 	printf("%s%x",(i == ETHER_ADDR_LEN) ? "" : ":",*ptr++);
	     		}while(--i>0);
	    			printf("\tDestination MAC: ");
	    			ptr = eth_hdr->ether_dhost;
	     		i = ETHER_ADDR_LEN;
	     		do
				{
	     	    	 	printf("%s%x",(i == ETHER_ADDR_LEN) ? "" : ":",*ptr++);
	     		}while(--i>0);
     	
				ip_hdr = (struct ip*)&buffer[14];
				printf("\tProto: 0x%04x\tDst IP: %d.%d.%d.%d\tSrc IP: %d.%d.%d.%d\tTTL: %d\n",ntohs(eth_hdr->ether_type), NIPQUAD(ip_hdr->ip_dst), NIPQUAD(ip_hdr->ip_src), ip_hdr->ip_ttl);*/
				
		    }
	    }
      }
   }
   freeifaddrs(addrs);
   free(intfSockTable);
   return 0;
}
