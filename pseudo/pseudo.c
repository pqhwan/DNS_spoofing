

PSEUDOCODE for CS168 DNS Spoofing -- PETE KIM, MANI ASKARI

PROGRAM OVERVIEW: SINGLE FIBERED

1 READ IN PROGRAM ARGUMENT

2 INITIALIZE RAW SOCKETS

3 EAVESDROP ON ALL INCOMING and OUTGOING PACKETS

4 USE HEADER FORMATS TO MAKE SENSE OF THE PACKETS & IDENTIFY DNS REQUESTS

5 CRAFT MISLEADING FAKE DNS RESPONSES AND FEED IT BACK INTO THE RAW SOCKET

...DONE!

EXTRACREDIT: Sniff DNS requests from another machine and continue from step 4


$DEFINITIONS
	#define ARGNUM 2


$SETUP (in main())
	open raw socket


$LOOP
	while(1)
		check raw socket file descriptor for outgoing packets


code for sniffing outgoing & incoming packets
http://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/


$EXIT
