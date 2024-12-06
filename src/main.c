#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct ether_header *ether_header = (struct ether_header *) packet;

    if (ntohs(ether_header->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        char *direction = (char *) args;
        printf("%s Packet:\n", direction);

        printf("Source MAC: ");
        for (int i = 0; i < ETH_ALEN; i++)
        {
            printf("%02x", ether_header->ether_shost[i]);
            if (i < ETH_ALEN - 1)
            {
                printf(":");
            }
        }

        printf("\nDestination MAC: ");
        for (int i = 0; i < ETH_ALEN; i++)
        {
            printf("%02x", ether_header->ether_dhost[i]);
            if (i < ETH_ALEN - 1)
            {
                printf(":");
            }
        }

        printf("\nSource IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dest_ip);
        printf("Packet Length: %d bytes\n", header->len);
        printf("--------------------------------------\n");
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *all_devs, *dev;
    char *dev_name = NULL;

    if (pcap_findalldevs(&all_devs, errbuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    dev = all_devs;
    if (dev == NULL)
    {
        fprintf(stderr, "No devices found. Make sure you have permissions.\n");
        return 1;
    }

    dev_name = dev->name;
    printf("Using device: %s\n", dev_name);

    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        pcap_freealldevs(all_devs);
        return 1;
    }

    struct bpf_program filter;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(all_devs);
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(all_devs);
        return 1;
    }

    printf("Listening for packets... Press Ctrl+C to stop.\n");
    pcap_loop(handle, -1, packet_handler, (unsigned char *) "Incoming");

    pcap_close(handle);
    pcap_freealldevs(all_devs);
    return 0;
}
