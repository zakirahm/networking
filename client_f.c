/* 
Purpose of the Code:
To perform ARP resolution and retrieve the source MAC address.

Key Elements and Terms:
AF_INET → Specifies the IPv4 address family.
inet_pton() → Stands for Internet Presentation to Network.
Converts an IP address from human-readable text format into its binary representation in network byte order
*/
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define ARP_REQUEST 1
#define ARP_REPLY 2
unsigned char src_ip[INET_ADDRSTRLEN]={0};
unsigned char src_mac[6]={0};
int get_mac_address(); //For get Mac Address 

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
// Function to get MAC address of a given interface
int get_mac_address() {   
    int fd;
    struct ifconf ifc;
    struct ifreq ifr[10];
    char ip[INET_ADDRSTRLEN];
    unsigned char *mac;
    int ifindex;
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
        
        ifindex=ifr[i].ifr_ifindex;   //Ethernet index;
        mac = (unsigned char *)mac_req.ifr_hwaddr.sa_data;

        printf("Interface: %s\n", ifr[i].ifr_name);
        printf("INterface index: %d\n",ifindex);
        printf("IP Address: %s\n", ip);
        printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break; // Stop after first active interface
    }

    memcpy(src_ip,ip,INET_ADDRSTRLEN);
    memcpy(src_mac, mac, 6); // Copy MAC address
    close(fd);
    return ifindex;
}


int main(int argc, char *argv[]) {          //Take argument and Target IP
   char *target_ip_str = argv[1];
   struct sockaddr_ll dest;         //Used for Ethernet frame for L2  
   int sockfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
   if(sockfd<0){perror("ARP Socket");}
   
   // Prepare for ARP request  means interpret the beginning of a raw packet buffer as an Ethernet header.
    unsigned char buffer[42];
    struct ether_header *eth = (struct ether_header *)buffer;
	struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ether_header));
   /*[ Ethernet Header (14 bytes) ][ ARP Header (28 bytes) ]*/
   // 1. Ethernet header
    memset(eth->ether_dhost, 0xff, 6); //Destination MAC address field with FF FF FF FF FF FF(6 bytes). 
      
     	  /* Get Sorce Mac/IP/Ethernet Index address so we used in Ethernet header*/	
          int ifindex = get_mac_address();
          if (ifindex > 1) {
               printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
			   printf("IP Address of source:%s\n",src_ip);
              }
			  else { printf("Failed to get MAC address\n"); }
	     /* Done Got source Mac */		          
     memset(&dest, 0, sizeof(dest));
     dest.sll_ifindex = ifindex;
     dest.sll_halen = ETH_ALEN;
     memset(dest.sll_addr, 0xff, 6);
     memcpy(eth->ether_shost, src_mac, 6); 
     eth->ether_type = htons(ETH_P_ARP);
		   
     // 2. ARP header 
    arp->hw_type = htons(1);
    arp->proto_type = htons(ETH_P_IP);
    arp->hw_size = 6;
    arp->proto_size = 4;
    arp->opcode = htons(ARP_REQUEST);
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_mac, 0x00, 6);
    inet_pton(AF_INET, target_ip_str, arp->target_ip);	//Converts IP address from text format to network byte order binary format.	  
     // Send ARP request using IPC socket
    if (sendto(sockfd, buffer, 42, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) //Used with connectionless sockets (like UDP) or raw sockets.Used with connectionless sockets (like UDP) or raw sockets.
	{
        perror("sendto");
        return 1;
    }
    //// Listen for ARP reply
    while (1) {
        unsigned char recv_buf[60];
        ssize_t len = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
        if (len > 0) {
            struct ether_header *recv_eth = (struct ether_header *)recv_buf;
            if (ntohs(recv_eth->ether_type) == ETH_P_ARP) {
                struct arp_header *recv_arp = (struct arp_header *)(recv_buf + sizeof(struct ether_header));
                if (ntohs(recv_arp->opcode) == ARP_REPLY &&
                    memcmp(recv_arp->sender_ip, arp->target_ip, 4) == 0) {
                    printf("MAC address for %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           target_ip_str,
                           recv_arp->sender_mac[0], recv_arp->sender_mac[1], recv_arp->sender_mac[2],
                           recv_arp->sender_mac[3], recv_arp->sender_mac[4], recv_arp->sender_mac[5]);
                    break;
                }
            }
        }
    }
	
   close(sockfd);
   return 0;
}
