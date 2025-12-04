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
#define PORT 8082

int get_mac_address(const char *, unsigned char *); //For get Mac Address 

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
int get_mac_address(const char *iface, unsigned char *mac) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("Socket error");  return -1; }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { 
	    perror("ioctl error");
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); // Copy MAC address
    close(fd);
    return 0;
}


int main() {
   int client_fd;
   struct sockaddr_in serv_addr;    //Used IP packet for L3
   struct sockaddr_ll dest;         //Used for Ethernet fream for L2  
   // Set server address
   unsigned char src_ip[4];         //purpose to add in ARP header as source Address  
   memcpy(src_ip, &serv_addr.sin_addr, 4);  //Copied source IP address 
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_port = htons(PORT);
   
   // Destination address for L2
    memset(&dest, 0, sizeof(dest));
    dest.sll_ifindex = ifindex;
    dest.sll_halen = ETH_ALEN;
    memset(dest.sll_addr, 0xff, 6);
   
   // Prepare for ARP request  means interpret the beginning of a raw packet buffer as an Ethernet header.
    unsigned char buffer[42];
    struct ether_header *eth = (struct ether_header *)buffer;
	struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ether_header));
   /*[ Ethernet Header (14 bytes) ][ ARP Header (28 bytes) ]*/
      // 1. Ethernet header
           memset(eth->ether_dhost, 0xff, 6); //Destination MAC address field with FF FF FF FF FF FF(6 bytes). 
      
     	  /* Get Sorce mac address so we used in Ethernet header*/		   
          unsigned char src_mac[6];
          if (get_mac_address("eth0", src_mac) == 0) {
               printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
              }
			  else { printf("Failed to get MAC address\n"); }
	     /* Done Got source Mac */		  

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
/*	
	/*For L3 Ping code*/ 
   char *hello = "Hello from client";
   
   
   char rec_buffer[1024] = {0};
   // Create socket
   if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
       printf("Socket creation error\n");
       return -1;
   }


   if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
       printf("Connection failed\n");
       return -1;
   }
   // Send and receive data
   send(client_fd, hello, strlen(hello), 0);
   printf("Hello message sent\n");
   read(client_fd, rec_buffer, 1024);
   printf("Server: %s\n", rec_buffer);  */
   // Close socket
   close(client_fd);
   return 0;
}
