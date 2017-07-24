pcap_restart : pcap_restart.o
	gcc -o pcap_restart pcap_restart.o -lpcap
pcap_restart.o : pcap_restart.c
	gcc -c -o pcap_restart.o pcap_restart.c -lpcap
clean :
	rm pcap_restart.o pcap_restart
