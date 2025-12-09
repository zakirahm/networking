#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/socket.h>

#define PACKET_SIZE 64

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    int sockfd;
    struct sockaddr_in addr;
    char packet[PACKET_SIZE];
    struct icmphdr *icmp = (struct icmphdr *)packet;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket error");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    memset(packet, 0, PACKET_SIZE);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = checksum(packet, PACKET_SIZE);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        perror("Send error");
        return 1;
    }

    char recv_buf[PACKET_SIZE];
    socklen_t addr_len = sizeof(addr);
    if (recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&addr, &addr_len) <= 0) {
        perror("Receive error");
        return 1;
    }

    gettimeofday(&end, NULL);
    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    printf("Reply from %s: time=%.2f ms\n", argv[1], rtt);

    close(sockfd);
    return 0;
}

