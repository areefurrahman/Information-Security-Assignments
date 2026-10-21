/*
 * Group Members:
 *   Task 02 (Module 1): Abdullah Maqbool - L1F23BSSE0391 (Group Leader: Capture engine & integration)
 *   Task 03 (Module 2): Ansir Ali        - L1F23BSSE0388 (Ethernet dissection)
 *   Task 04 (Module 3): Muhammad Hafeez  - L1F23BSSE0396 (IPv4 dissection)
 *   Task 05 (Module 4): Aref ur Rahman   - L1F23BSSE0389 (TCP/UDP dissection)
 *
 * gcc sniffer.c -o sniffer -lpcap
 * sudo ./sniffer
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MAXBYTES 2048


int ipv4_count = 0;
int arp_count = 0;
int ipv6_count = 0;
int other_count = 0;


void process_pkt(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int dissect_ethernet(const u_char *packet);
void dissect_ipv4(const u_char *packet);
void dissect_tcp(const u_char *packet, int start);
void dissect_udp(const u_char *packet, int start);
void print_app_name(int port);

//  MODULE 1 (Abdullah Maqbool - L1F23BSSE0391): Capture Engine (Task 2)
//  =========================================================================
int main(int argc, char **argv)
{

    char errbuff[PCAP_ERRBUF_SIZE];
    char *device = NULL;
    pcap_t *descptr = NULL;
    int count = 0;

    //  Get network interface name

    if (argc > 1) {


        device = argv[1];
    } else {


        device = pcap_lookupdev(errbuff);
        if (device == NULL) {

            printf("Error finding device: %s\n", errbuff);
            return 1;
        }
    }
    printf("Capturing on interface: %s\n", device);

    // Open device in promiscuous mode (1) with MAXBYTES snaplen
    descptr = pcap_open_live(device, MAXBYTES, 1, 1000, errbuff);
    if (descptr == NULL) {
      
      
        printf("Error opening device: %s\n", errbuff);
        return 1;
    }

    // Capture 20 packets using pcap_loop and pass &count

    pcap_loop(descptr, 20, process_pkt, (u_char *)&count);

    //Print summary counts at the end and close handle
    printf("\n--- Capture Summary (Total: %d packets) ---\n", count);


    printf("IPv4: %d | ARP: %d | IPv6: %d | Other: %d\n", ipv4_count, arp_count, ipv6_count, other_count);

    pcap_close(descptr);
    return 0;
}

// Callback function called for every captured packet 
void process_pkt(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    //  Increment packet counter passed from main 
    
    
int *counter = (int *)args;

(*counter)++;

    // Print packet number, timestamp, caplen and len

    printf("\nPacket #%d  time: %ld.%06ld  caplen: %u  len: %u\n", *counter, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);

    // Decode Ethernet header and get EtherTypw


    int ether_type = dissect_ethernet(packet);

    //  If EtherType is 0x0800 (IPv4), decode IPv4 header 

    if (ether_type == 0x0800) {
    
        dissect_ipv4(packet);
    }
}
