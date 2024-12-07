#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <string.h>
#include <netdb.h>

void list_interfaces()
{
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, INET_ADDRSTRLEN);
            printf("Interface: %s\nIPv4 Address: %s\n", ifa->ifa_name, ip);
        }
        else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, ip, INET6_ADDRSTRLEN);
            printf("Interface: %s\nIPv6 Address: %s\n", ifa->ifa_name, ip);
        }

        if (ifa->ifa_addr->sa_family == AF_PACKET && ifa->ifa_data != NULL)
        {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
            printf("MAC Address: ");
            for (int i = 0; i < s->sll_halen; i++)
            {
                printf("%02x%s", s->sll_addr[i], (i + 1 != s->sll_halen) ? ":" : "");
            }
            printf("\n");
        }
    }

    freeifaddrs(ifaddr);
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct ether_header *ether_header = (struct ether_header *)packet;

    if (ntohs(ether_header->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        printf("%s Packet:\n", (char *)args);
        printf("Source MAC: ");
        for (int i = 0; i < ETH_ALEN; i++)
        {
            printf("%02x%s", ether_header->ether_shost[i], (i < ETH_ALEN - 1) ? ":" : "");
        }
        printf("\nDestination MAC: ");
        for (int i = 0; i < ETH_ALEN; i++)
        {
            printf("%02x%s", ether_header->ether_dhost[i], (i < ETH_ALEN - 1) ? ":" : "");
        }
        printf("\nSource IP: %s\nDestination IP: %s\nPacket Length: %d bytes\n--------------------------------------\n",
               src_ip, dest_ip, header->len);
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *all_devs, *dev;
    char *dev_name = NULL;

    list_interfaces();

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
    printf("Using device: %s\n\n", dev_name);

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
    pcap_loop(handle, -1, packet_handler, (unsigned char *)"Packet");

    pcap_close(handle);
    pcap_freealldevs(all_devs);
    return 0;
}
