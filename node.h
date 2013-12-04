#include	<stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <sys/types.h>
#include <sys/socket.h>

#define ARGNUM 2
#define UDPHDRSIZE sizeof(struct udphdr)
#define IPHDRSIZE sizeof(struct iphdr)
