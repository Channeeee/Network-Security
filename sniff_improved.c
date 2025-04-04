#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include "myheader.h"

void print_ethernet_header(struct ethheader *eth) {
    printf("Ethernet Header:\n");
    printf("  Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth->ether_shost));
    printf("  Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth->ether_dhost));
}

void print_ip_header(struct ipheader *ip) {
    printf("\nIP Header:\n");
    printf("  Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("  IP Length: %d\n", ntohs(ip->iph_len));
}

void print_tcp_header(struct tcpheader *tcp) {
    printf("\nTCP Header:\n");
    printf("  Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("  Destination Port: %d\n", ntohs(tcp->tcp_dport));
    printf("  TCP Header Length: %d bytes\n", TH_OFF(tcp) * 4);
}

void print_message(const u_char *packet, struct ipheader *ip, struct tcpheader *tcp, int ip_header_len) {
    int tcp_header_len = TH_OFF(tcp) * 4;
    int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int message_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    if (message_len > 0) {
        printf("\nMessage (data): ");
        for (int i = 0; i < message_len; i++) {
            printf("%c", packet[total_header_len + i]);
        }
        printf("\n");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        print_ethernet_header(eth);
        print_ip_header(ip);

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            print_tcp_header(tcp);

            print_message(packet, ip, tcp, ip->iph_ihl * 4);
        } else {
            printf("   Protocol: Not TCP\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 캡처
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);  
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap handle: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); 
    return 0;
}