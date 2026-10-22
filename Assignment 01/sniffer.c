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








    //  MODULE 4 (Aref ur Rahman - L1F23BSSE0389): TCP/UDP Dissection (Task 5)
// ========================================================================= 


void dissect_tcp(const u_char *packet, int start)
{
    // Bytes 0-1: Source Port, Bytes 2-3: Destination Port
    int src_port = (packet[start] << 8) | packet[start + 1];
    int dst_port = (packet[start + 2] << 8) | packet[start + 3];

    // Bytes 4-7: 32-bit Sequence Number

    unsigned int seq = (packet[start + 4] << 24) | (packet[start + 5] << 16) | (packet[start + 6] << 8)  | packet[start + 7];

    // Bytes 8-11: 32-bit Acknowledgement Number

    unsigned int ack = (packet[start + 8] << 24) | (packet[start + 9] << 16) | (packet[start + 10] << 8) | packet[start + 11];

    // Byte 12 (top 4 bits): TCP Header Length in words

    int hdr_words = (packet[start + 12] >> 4) & 0x0F;

    int hdr_bytes = hdr_words * 4;

    // Byte 13: TCP Flags
    int flags = packet[start + 13];

    printf("  TCP Src Port: %d | Dst Port: %d | Seq: %u | Ack: %u\n", src_port, dst_port, seq, ack);
    printf("  TCP Header Length: %d words (%d bytes) | Flags:", hdr_words, hdr_bytes);

    if (flags & 0x20) printf(" URG");
    if (flags & 0x10) printf(" ACK");
    if (flags & 0x08) printf(" PSH");
    if (flags & 0x04) printf(" RST");
    if (flags & 0x02) printf(" SYN");
    if (flags & 0x01) printf(" FIN");
    printf("\n");


    print_app_name(src_port);
    print_app_name(dst_port);
}

void dissect_udp(const u_char *packet, int start)
{
    //  Bytes 0-1: Source Port, Bytes 2-3: Destination Port

    int src_port = (packet[start] << 8) | packet[start + 1];
    int dst_port = (packet[start + 2] << 8) | packet[start + 3];

    //  Bytes 4-5: UDP Length, Bytes 6-7: UDP Checksum

    int len = (packet[start + 4] << 8) | packet[start + 5];

    int checksum = (packet[start + 6] << 8) | packet[start + 7];

    printf("  UDP Src Port: %d | Dst Port: %d | Length: %d | Checksum: 0x%04X\n", src_port, dst_port, len, checksum);

    // Check application protocol using ports

    print_app_name(src_port);

    print_app_name(dst_port);
}


void print_app_name(int port)
{
    if (port == 80) {
        printf("  Application: HTTP (Web - Port 80)\n");
    } else if (port == 25) {
        printf("  Application: SMTP (Email - Port 25)\n");
    } else if (port == 20 || port == 21) {
        printf("  Application: FTP (File Transfer - Port %d)\n", port);
    } else if (port == 53) {
        printf("  Application: DNS (Port 53)\n");
    } else if (port == 443) {
        printf("  Application: HTTPS (Secure Web - Port 443)\n");
    } else if (port == 22) {
        printf("  Application: SSH (Secure Shell - Port 22)\n");
    }
}