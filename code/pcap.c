#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

// mac 주소를 출력해주는 함수
void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 이더넷 헤더 파싱
    struct ethheader *eth = (struct ethheader *)packet;
   
    // IP 패킷인지 확인
    if (ntohs(eth->ether_type) != 0x0800)
        return;
    // IP 패킷인지 확인 후 IP 헤더 파싱
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    // IP 헤더 길이 저장
    int ip_header_len = ip->iph_ihl * 4;

    // TCP 패킷인지 확인(다른 건 넘김김)
    if (ip->iph_protocol != IPPROTO_TCP)
        return;
    // TCP 패킷인지 확인 후 TCP 헤더 파싱
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    // TCP 헤더 길이
    int tcp_header_len = TH_OFF(tcp) * 4;

    // 페이로드 시작 위치
    char *payload = (char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
    // 진짜 total_len아니고 IP 패킷까지
    int total_len = ntohs(ip->iph_len);
    // IP 패킷 길이에서 IP 헤더 길이와 TCP 헤더 길이를 빼, payload 길이 구하기기
    int payload_len = total_len - ip_header_len - tcp_header_len;

    // mac, IP, port src -> dst 출력
    printf("\n[+] TCP Packet\n");
    printf("Ethernet: "); print_mac(eth->ether_shost); printf(" → "); print_mac(eth->ether_dhost); printf("\n");
    printf("IP: %s → %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
    printf("TCP: %d → %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

    // payload가 있을 경우 출력
    if (payload_len > 0) {
        printf("Payload (%d bytes):\n", payload_len);
        for (int i = 0; i < payload_len && i < 1000; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    }
}

int main() {
    char *dev = "enp0s3";
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: enp0s3 NIC에서 실시간 pcap 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    // Step 2: filter_exp 필터 표현식을 BPF 의사코드로 컴파일
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // 캡처 시작(무한 루프)
    printf("[*] Starting packet capture... Press Ctrl+C to stop.\n");
    pcap_loop(handle, -1, got_packet, NULL);

    // 캡처 종료
    pcap_close(handle);
    return 0;
}
