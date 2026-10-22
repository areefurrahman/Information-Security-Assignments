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

//  Ansir codes here


//  MODULE 3 (Muhammad Hafeez - L1F23BSSE0396): IPv4 Dissection (Task 4)
// ========================================================================= 

void dissect_ipv4(const u_char *packet)
{
    // IPv4 starts at byte 14 (right after 14-byte Ethernet header) 

    int version = (packet[14] >> 4) & 0x0F; /* Top 4 bits of byte 14 */

    int ihl = packet[14] & 0x0F;            /* Bottom 4 bits of byte 14 */
    int ihl_bytes = ihl * 4;                /* Header length in bytes */

   
    int total_len = (packet[16] << 8) | packet[17];

    //  Bytes 18-19: Identification 
    int id = (packet[18] << 8) | packet[19];

    // Bytes 20-21: Flags (3 bits) and Fragment Offset (13 bits)

    int flags_frag = (packet[20] << 8) | packet[21];

    int df = (flags_frag >> 14) & 0x01;       /* Don't Fragment flag */

    int mf = (flags_frag >> 13) & 0x01;       /* More Fragments flag */

    int frag_offset = flags_frag & 0x1FFF;    /* 13-bit Fragment Offset */

    // Byte 22: Time to Live (TTL)
    int ttl = packet[22];

    // Byte 23: Protocol (6=TCP, 17=UDP)
    int protocol = packet[23];

    // Bytes 24-25: Header Checksum

    int checksum = (packet[24] << 8) | packet[25];

    printf("  IPv4 Version: %d | IHL: %d words (%d bytes) | Total Length: %d\n", version, ihl, ihl_bytes, total_len);
    printf("  Identification: 0x%04X | DF: %d | MF: %d | Frag Offset: %d (%d bytes)\n", id, df, mf, frag_offset, frag_offset * 8);

    if (protocol == 6) {
        
        printf("  TTL: %d | Protocol: 6 (TCP) | Checksum: 0x%04X\n", ttl, checksum);

    } else if (protocol == 17) {

        printf("  TTL: %d | Protocol: 17 (UDP) | Checksum: 0x%04X\n", ttl, checksum);
    } else {

        printf("  TTL: %d | Protocol: %d (Other) | Checksum: 0x%04X\n", ttl, protocol, checksum);
    }
