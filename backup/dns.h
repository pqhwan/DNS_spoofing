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

struct dns_header
{
	uint16_t xid;
	uint16_t flags;
	uint16_t num_questions;
	uint16_t num_answers;
	uint16_t num_authority;
	uint16_t num_additional;
};

struct dns_question_section
{
	uint16_t type;
	uint16_t class;
};

struct dns_answer_section
{
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint16_t ttl_top;
	uint16_t ttl;
	uint16_t data_len;
};

char *receive(int lsock, int sock_type, int *rx_bytes, int csock, struct sockaddr_in *clientaddr);
char *get_domain_in_question(char *dns_packet, int packet_size);
int send_dns_reply(char *question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *request_packet, int request_packet_size);