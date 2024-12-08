#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void print_tcp_flags(u_int8_t flags)
{
    if (flags & TH_SYN) printf("SYN ");
    if (flags & TH_ACK) printf("ACK ");
    if (flags & TH_FIN) printf("FIN ");
    if (flags & TH_RST) printf("RST ");
    if (flags & TH_PUSH) printf("PUSH ");
    if (flags & TH_URG) printf("URG ");
    printf("\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth = (struct ether_header *)packet;
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dest_ip);
        printf("Protocol: %d\n", ip_header->ip_p);

        printf("IP Header Checksum: 0x%04x\n", ntohs(ip_header->ip_sum));

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("TCP Source Port: %u\n", ntohs(tcp_header->th_sport));
            printf("TCP Destination Port: %u\n", ntohs(tcp_header->th_dport));

            printf("TCP Flags: ");
            print_tcp_flags(tcp_header->th_flags);

            printf("TCP Sequence Number: %u\n", ntohl(tcp_header->th_seq));
            printf("TCP Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));

            printf("TCP Header Checksum: 0x%04x\n", ntohs(tcp_header->th_sum));
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("UDP Source Port: %u\n", ntohs(udp_header->uh_sport));
            printf("UDP Destination Port: %u\n", ntohs(udp_header->uh_dport));

            printf("UDP Datagram Size: %u bytes\n", ntohs(udp_header->uh_ulen));

            printf("UDP Header Checksum: 0x%04x\n", ntohs(udp_header->uh_sum));
        }

        printf("Packet Length: %d bytes\n", header->len);
        printf("---------------------------------------\n");
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs, *device;
    char dev_name[256] = {0};

    if (pcap_findalldevs(&all_devs, errbuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    printf("Available devices:\n");
    for (device = all_devs; device != NULL; device = device->next)
    {
        if (device->name)
        {
            printf("- %s", device->name);
            if (device->description)
                printf(" (%s)", device->description);
            printf("\n");
        }
    }

    for (device = all_devs; device != NULL; device = device->next)
    {
        if (device->name != NULL)
        {
            strncpy(dev_name, device->name, sizeof(dev_name) - 1);
            break;
        }
    }

    if (dev_name[0] == '\0')
    {
        fprintf(stderr, "No suitable device found. Exiting.\n");
        pcap_freealldevs(all_devs);
        return 1;
    }

    printf("Using device: %s\n", dev_name);
    pcap_t *handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening device %s: %s\n", dev_name, errbuf);
        pcap_freealldevs(all_devs);
        return 1;
    }

    printf("Capturing TCP/UDP packets... \n");
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    pcap_freealldevs(all_devs);
    return 0;
}
