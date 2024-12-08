#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth = (struct ether_header *)packet;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
        printf("Protocol: %d\n", ip_header->ip_p);
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dest_ip);
        printf("Time-to-Live (TTL): %d\n", ip_header->ip_ttl);
        printf("Header checksum: 0x%04x\n", ntohs(ip_header->ip_sum));

        if (ntohs(ip_header->ip_off) & IP_MF)
            printf("Packet is fragmented. More fragments follow.\n");
        else if (ntohs(ip_header->ip_off) & IP_DF)
            printf("Packet is not fragmented (DF flag set).\n");
        else
            printf("Packet is not fragmented.\n");

        if (ip_header->ip_p == IPPROTO_ICMP)
        {
            struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("ICMP Type: %d\n", icmp_header->icmp_type);
            if (icmp_header->icmp_type == ICMP_ECHO)
                printf("ICMP Message: Echo Request\n");
            else if (icmp_header->icmp_type == ICMP_ECHOREPLY)
                printf("ICMP Message: Echo Reply\n");
            else
                printf("ICMP Message: Other\n");
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

    printf("Capturing IP packets... \n");
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    pcap_freealldevs(all_devs);
    return 0;
}
