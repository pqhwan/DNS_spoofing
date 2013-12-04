
 /* =====================================================================================
 *
 *       Filename:  node.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/03/2013 02:41:31 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
*/
/*
www.google.com IP address 74.125.226.212
1. We only want to capture the DNS request : meaning that
	we must check if the TCP SYN is set, we do the following steps :
	1. replace the destination address in the paceket with the one
		we wish to redirect to
	2. reconstruct TCP/IP packet with correct headers and checksums
	3. send the new packet to the victim
	4. our response would get to the victim much faster than the 
		actual server. 

*/
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <mcheck.h>
#include <netinet/udp.h>
#include "node.h"
#include "assert.h"

#define REQUEST_SIZE 100
#define MANIS 1
#define PETES 0

/***************** DNS HEADER FOR NOW *******************/
struct dnshdr {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};
/****************** DNS QUERY PART *********************/
struct dnsquery {
  char *qname;
  char qtype[2];
  char qclass[2];
};

/************************* NOT USED YET ***********************/
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

/************************* NOT USED YET ***********************/
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
/************************* NOT USED YET ***********************/
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
/************************* NOT USED YET ***********************/ 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
/************************* NOT USED YET ***********************/
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

/************************ GETS the raw socket *****************
Must be UDP
***************************************************************/
int get_raw_socket() {

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

	if(fd == -1){
		perror("socket()");
		return -1;
	}
	return fd;
}


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

void print_udpheader(struct udphdr *udp) {

	printf("UDP src_port=%d dst_port=%d length=%d checksum=%x\n",
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
	printf("vsion:%hd\t hlen:%hd\t len:%d\t id: %d\t foff %d\t ptcl: %hd\t sum: %x\t source: %s\t destination: %s\n",i->version,i->ihl,i->tot_len,i->id,i->frag_off,i->protocol,i->check,src,dest);
		
}

/************************** TODO here ************************
maskari : at this point, we can get the query name like ex: 3www4google8com
This function tries to fix this to a normal domain name ex : www.google.com
NOT FUNCTIONAL YET
**************************************************************/
void extract_dns_request(struct dnsquery *dns_query, char *request){
  unsigned int i, j, k;
  char *curr = dns_query->qname;
  unsigned int size;
  
  size = curr[0];

  j=0;
  i=1;
  while(size > 0){
    for(k=0; k<size; k++){
      request[j++] = curr[i+k];
    }
    request[j++]='.';
    i+=size;
    size = curr[i++];
  }
  request[--j] = '\0';
}

int main ( int argc, char *argv[] )
{

	//count argument
	if(argc < ARGNUM){
		printf("usage: dnsspoof redirectDomain originalRequestDomain\n");
		exit(1);
	}

	//UDP because DNS uses UDP
	int fd = get_raw_socket();
	assert(fd != -1);
	
	char *buffer = malloc(65535);
	if(buffer == NULL){
		perror("malloc()");
		exit(1);
	}

	char saddrstr[INET_ADDRSTRLEN];
	int bytes_recvd;
	struct sockaddr_in src;
	int srclen = sizeof(src);
	int count = 0;

#ifdef PETE
	printf("going into loop\n");
#endif

	// ip, udp, dns query
	while(1){

		bytes_recvd = recvfrom(fd, buffer, 65535, 0,  &src, &srclen);
		if (bytes_recvd < 0)  {
			fprintf(stderr, "Error : %s\n", -bytes_recvd);
			break;
		}
		else if(bytes_recvd > 0){

			printf("-------------------Received PACKET ---------------------\n");
			int len = bytes_recvd;
			struct udphdr *udp;
			struct iphdr *ip;
			struct dnshdr *dns;
			struct dnsquery *dnsq;

			//get the ip header
			ip = malloc(sizeof(struct iphdr));
			decapsulate_fromip(buffer, &ip);

#ifdef MANI
			print_ipheader(ip);
#endif

			//Skip ip header
			buffer += sizeof(struct iphdr);
			len -= sizeof(struct iphdr);

			udp = malloc(sizeof(struct udphdr));
			memcpy(udp, buffer, sizeof(struct udphdr));

#ifdef MANI
			print_udpheader(udp);
#endif

			//skip udp header
			buffer += sizeof(struct udphdr);
			len -= sizeof(struct udphdr);
			//printf("Buffer -> %s\n", buffer);

			printf("DNS....\n");

			//get DNS part
			dns = malloc(sizeof(struct dnshdr));
			//copy the dnsheader from buffer
			memcpy(dns, buffer, sizeof(struct dnshdr));
			//skip the dns header
			buffer += sizeof(struct dnshdr);

			//get the dns query part
			dnsq = malloc(sizeof(struct dnsquery));
			dnsq->qname = (unsigned char *)buffer;
			
			//get the request
			//char request[REQUEST_SIZE];
			printf("Buffer -> %s\n", buffer);

			//TODO : extract_dns fix
			//extract_dns_request(&dnsq, request);
			//printf("Request for %s\n", request);

			//only the first request : for DEBUGGING
			if (count++ > 10) break;
		}	
	}
	
	return 0;
}
