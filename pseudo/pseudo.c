

PSEUDOCODE for CS168 DNS Spoofing -- PETE KIM, MANI ASKARI

PROGRAM OVERVIEW: SINGLE FIBERED

1 READ IN PROGRAM ARGUMENT

2 INITIALIZE RAW SOCKETS

3 EAVESDROP ON ALL INCOMING and OUTGOING PACKETS

4 USE HEADER FORMATS TO MAKE SENSE OF THE PACKETS & IDENTIFY DNS REQUESTS

5 CRAFT MISLEADING FAKE DNS RESPONSES AND FEED IT BACK INTO THE RAW SOCKET

...DONE!

EXTRACREDIT: Sniff DNS requests from another machine and continue from step 4


