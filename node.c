/*
 * =====================================================================================
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

#include "node.h"

				int
main ( int argc, char *argv[] )
{

	//count argument
	if(argc < ARGNUM){
		printf("usage: dnsspoof redirectDomain originalRequestDomain\n");
		exit(1);
	}

	//UDP because DNS uses UDP
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(fd == -1){
		perror("socket()");
		exit(1);
	}
	
	char *buffer = malloc(65535);
	if(buffer == NULL){
		perror("malloc()");
		exit(1);
	}

	char saddrstr[INET_ADDRSTRLEN];
	int bytes_recvd;
	struct sockaddr_in src;
	int srclen = sizeof(src);

	printf("going into loop\n");
	while(1){
		bytes_recvd = recvfrom(fd, buffer, 65535, 0,  &src, &srclen);
		if(bytes_recvd > 0){
			struct iphdr *ipheader = buffer;
			inet_ntop(AF_INET, &ipheader->saddr, saddrstr, INET_ADDRSTRLEN);
			printf("caught packet: \n");
			printf("ipheader->saddr: %s\n", saddrstr);
			printf("caught UDP packet: %s\n", buffer+IPHDRSIZE+UDPHDRSIZE);
		
	}

	free(buffer);
	return 0;
}
