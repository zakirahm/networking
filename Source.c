
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

int main() {
    int sockfd;
    unsigned char buffer[60];
    struct sockaddr_ll addr;
    struct ifreq ifr;

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket error");
        return 1;
    }

    // Bind to interface (change "enol" to your interface)
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "enol", IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        return 1;
    }
    unsigned char my_mac[6];
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        return 1;
    }
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    unsigned char my_ip[4];
    memcpy(my_ip, &ipaddr->sin_addr, 4);

    printf("Listening for ARP requests...\n");

    while (1) {
        ssize_t len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (len > 0) {
            struct ether_header *eth = (struct ether_header *)buffer;
            if (ntohs(eth->ether_type) == ETH_P_ARP) {
                struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ether_header));
                if (ntohs(arp->opcode) == ARP_REQUEST &&
                    memcmp(arp->target_ip, my_ip, 4) == 0) {
                    printf("Received ARP request for my IP\n");

                    // Build ARP reply
                    memcpy(eth->ether_dhost, arp->sender_mac, 6);
                    memcpy(eth->ether_shost, my_mac, 6);

                    arp->opcode = htons(ARP_REPLY);
                    memcpy(arp->target_mac, arp->sender_mac, 6);
                    memcpy(arp->target_ip, arp->sender_ip, 4);
                    memcpy(arp->sender_mac, my_mac, 6);
                    memcpy(arp->sender_ip, my_ip, 4);

                    memset(&addr, 0, sizeof(addr));
                    addr.sll_ifindex = ifindex;
                    addr.sll_halen = ETH_ALEN;
                    memcpy(addr.sll_addr, arp->target_mac, 6);

                    if (sendto(sockfd, buffer, 42, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                        perror("sendto");
                    } else {
                        printf("Sent ARP reply with MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                               my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
                    }
                }
            }
        }
    }

    close(sockfd);
    return 0;
}
