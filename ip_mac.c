#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    int fd;
    struct ifconf ifc;
    struct ifreq ifr[10];
    char ip[INET_ADDRSTRLEN];

    // Create socket for ioctl
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Socket error");
        return 1;
    }

    // Get list of interfaces
    ifc.ifc_len = sizeof(ifr);
    ifc.ifc_req = ifr;
    if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl SIOCGIFCONF");
        close(fd);
        return 1;
    }

    // Loop through interfaces
    int count = ifc.ifc_len / sizeof(struct ifreq);
    for (int i = 0; i < count; i++) {
        // Skip loopback
        if (strcmp(ifr[i].ifr_name, "lo") == 0) continue;

        // Get IP address
        struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr[i].ifr_addr;
        inet_ntop(AF_INET, &ipaddr->sin_addr, ip, sizeof(ip));

        // Get MAC address
        struct ifreq mac_req;
        strncpy(mac_req.ifr_name, ifr[i].ifr_name, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &mac_req) < 0) {
            perror("ioctl SIOCGIFHWADDR");
            continue;
        }
        unsigned char *mac = (unsigned char *)mac_req.ifr_hwaddr.sa_data;

        printf("Interface: %s\n", ifr[i].ifr_name);
        printf("IP Address: %s\n", ip);
        printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break; // Stop after first active interface
    }

    close(fd);
    return 0;
}
