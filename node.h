
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>		
#include <sys/types.h>
#include <arpa/inet.h>		
#include <sys/stat.h>
#include <unistd.h>
#include <linux/ip.h> //why not netinet/ip.h?
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <inttypes.h>
#include "dns.h"
#include "colordefs.h"

#define ARGNUM 0
