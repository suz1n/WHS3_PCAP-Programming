#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "myheader.h"

#define MAX_PAYLOAD_LEN 100

void print_mac(const char *label, const u_char *mac) {
    printf(" %s: %02x:%02x:%02x:%02x:%02x:%02x\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;
    if (ip->iph_protocol != IPPROTO_TCP) return;

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    const u_char *payload = (u_char *)tcp + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    printf("====== TCP Packet Captured ======\n");
    print_mac("Source MAC", eth->ether_shost);
    print_mac("Dest MAC", eth->ether_dhost);

    printf("IP Header:\n");
    printf(" Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf(" Dest IP : %s\n", inet_ntoa(ip->iph_destip));

    printf("TCP Header:\n");
    printf(" Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf(" Dest Port  : %d\n", ntohs(tcp->tcp_dport));

    if (payload_len > 0) {
        printf("Message (%d bytes):\n", payload_len > MAX_PAYLOAD_LEN ? MAX_PAYLOAD_LEN : payload_len);
        for (int i = 0; i < payload_len && i < MAX_PAYLOAD_LEN; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("No Payload Data.\n");
    }

    printf("=================================\n\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // 자동으로 인터페이스 탐색
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    printf("[*] Using device: %s\n", dev);

    // 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 필터 설정
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't apply filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("[*] Listening on %s...\n\n", dev);
    pcap_loop(handle, 0, handle_packet, NULL);

    pcap_close(handle);
    return 0;
}
