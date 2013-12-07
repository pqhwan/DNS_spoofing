#include <netinet/in.h>

#define IPV4_ADDR_LEN		0x0004
#define DNS_REPLY_FLAGS		0x8180
#define DNS_REPLY_REFUSED	0x8183
#define DNS_REPLY_NAME		0xC00C
#define DNS_REPLY_TTL		0x0005
#define DNS_CLASS_IN		0x0001
#define DNS_TYPE_A			0x0001
#define DNS_TYPE_NS			0x0002
#define DNS_NUM_ANSWERS		0x0002
#define NS_NAME_ONE			"\x03ns1\xC0\x0C"
#define NS_NAME_TWO			"\x03ns2\xC0\x0C"
#define NS_NAME_LEN			0x0006
#define MAX_DNS_QUESTIONS	1

#define MAX_TTL				64
#define LOCALHOST "127.0.0.1"
#define UDP_RECV_SIZE			65536
#define MAX_CONTENT_LENGTH		1024


#define PERIOD				"."
#define PERIOD_SIZE			1
#define QUESTION_MARK		"?"
#define SPACE_STR			" "
#define SPACE_CHAR			' ' 
#define SPACE_SIZE			1
#define COLON				':'
#define COLON_STR			":"
#define COLON_SIZE			1
#define SHORT_STR_LEN		5
#define DNS_PORT			53

#define UDP 17
#define MAX_UDP				512
#define V4_LOCHOST 0x0100007f
#define ETH_HS sizeof(struct ethhdr) //TODO could be wrong
#define IP_HS sizeof(struct iphdr)
#define UDP_HS sizeof(struct udphdr)
#define DNS_HS sizeof(struct dnshdr)
#define DNS_QS sizeof(struct dns_question_section)
#define IP_UDP_HS sizeof(struct iphdr)+sizeof(struct udphdr)
#define IP_V(ip) (((ip)->tos) >> 4)

struct send_dns {
	int len;
	char *payload;
}__attribute__((__packed__));

struct dnshdr {
	//Flags from RFC
	uint16_t xid;
	uint16_t qr:1,opcode:4,	aa:1,tc:1,rd:1,ra:1,z:3,rcode:4;
	uint16_t num_questions;
	uint16_t num_answers;
	uint16_t num_authority;
	uint16_t num_additional;

}__attribute__((__packed__));

struct dns_question_section {

	char *qname;
	uint16_t type;
	uint16_t cls; 

}__attribute__((__packed__));

struct dns_answer_section
{

	char *name;
	uint16_t type;
	uint16_t clss; 
	uint32_t ttl;
	uint16_t data_len;
	uint32_t rdata;

}__attribute__((__packed__));

struct dnsPacket {

	struct dnshdr dns_hdr;
	struct dns_question_section dns_qus;
	struct dns_answer_section dns_anw;	

}__attribute__((__packed__));





// for checksum calculations (not verified yet) mani
struct pseudo_udp
{
	uint32_t 		sudo_src_ip;
	uint32_t 		sudo_dst_ip;
	uint8_t 		sudo_mbz;
	uint8_t 		sudo_prot;
	uint16_t		sudo_udp_len;
	//uint16_t		udp_src_port;
	//uint16_t		udp_dest_port;
	//uint16_t		udp_len;
	//uint16_t		udp_check;
}__attribute__((__packed__));

char *receive(int lsock, int *rx_bytes,struct sockaddr_in *clientaddr);
char *get_domain_queried(char *dns_packet, int packet_size);
char *print_dns_packet(char *packet, int packet_size, int *nameSize);

int send_dns_reply(char *question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *request_packet, int request_packet_size, char *cpy);
uint32_t decapsulate_fromip (char *packet, struct iphdr **ipheader);
void print_ipheader(struct iphdr *i);
int ip_sum(char* packet, int n);
char *pack_dns(char *question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *request_packet, int request_packet_size, int *dns_len);
char *pack_udp(uint32_t srcip, uint32_t destip, struct udphdr *udppart, char *reply_dns_part, int dns_len);
char *pack_ip(struct iphdr *h, int tot_size);
