#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

#define INET_ADDRSTRLEN 16
/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

int main(int argc, char *argv[])
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */
    uint16_t size_ip;
    uint16_t size_tcp;
    uint16_t size_of_data;
    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet("dum0", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */

    int i=0;
    while(1){
        /* Print its length */
        printf("Jacked a packet with length of [%d]\n", header.len);
        i = pcap_next_ex(handle, &header, &packet);
        if(i==1){ // is next_ex is successful?
            ethernet = (struct sniff_ethernet*)(packet);
            printf("this is for ethernet header's info \n");
            printf("source MAC : ");
            for(int k=0 ; k < 6 ; k++){
                printf("[%02x]",ethernet->ether_shost[k]);
            }
            printf("\n");
            printf("destination MAC : ");
            for(int k=0 ; k < 6 ; k++){
                printf("[%02x]",ethernet->ether_dhost[k]);
            }
            printf("\n");

            if(ntohs(ethernet->ether_type) == 0x0800){ // is next ip?
                ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
                size_ip = IP_HL(ip)*4;
                if (size_ip < 20) {
                    printf("   * Invalid IP header length: %u bytes\n", size_ip);
                    return(0);
                }
                printf("*\n");
                printf("*\n");
                printf("this is for ip header's info \n");
                char src_ip[1024];
                char dst_ip[1024];
                inet_ntop(AF_INET,&(ip->ip_src),src_ip,INET_ADDRSTRLEN);
                inet_ntop(AF_INET,&(ip->ip_dst),dst_ip,INET_ADDRSTRLEN);
                printf("source ip : %s \n", src_ip);
                printf("destination ip : %s\n", dst_ip);
                printf("*\n");
                printf("*\n");
                if(ip->ip_p==0x6){ // is this one tcp?
                    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                    size_tcp = TH_OFF(tcp)*4;
                    if (size_tcp < 20){
                        printf("   * Invalid TCP header length: %u\n", size_tcp);
                        return(0);
                    }
                    printf("this is for tcp header's info \n");
                    printf("tcp source port : %d \n" , ntohs(tcp->th_sport));
                    printf("tcp destination port : %d \n" , ntohs(tcp->th_dport));
                    printf("*\n");
                    printf("*\n");

                    size_of_data = (ntohs(ip->ip_len)*4-size_ip-size_tcp);
                    uint16_t start_of_data = (SIZE_ETHERNET + size_ip + size_tcp);
                    printf("data size is : %d\n",size_of_data);
                    printf("start of data is : %x \n", start_of_data);
                    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);	// actual data's location
                    for(int i=start_of_data; i <= size_of_data ; i++){
                        printf(" %02x ",packet[i]);
                        if(i%16 == 0){printf("\n");}
                    }
                    printf("\n");
                    printf("this is data :\n %s", payload);
                }//check tcp if statement's end
            }//check ip if statement's end
        }//check catch_ex statement's end
        /* And close the session */
    }
    pcap_close(handle);
    return(0);
}
