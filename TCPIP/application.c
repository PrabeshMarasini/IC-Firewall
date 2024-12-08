#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void print_http_data(const u_char *data, int len)
{
    if (len >= 4)
    {
        if (strstr((char *)data, "HTTP/") == (char *)data)
        {
            printf("HTTP Response: %.*s\n", len, data);
        }
        else if (strstr((char *)data, "GET") == (char *)data || strstr((char *)data, "POST") == (char *)data)
        {
            printf("HTTP Request: %.*s\n", len, data);
        }
    }
}

void print_ftp_data(const u_char *data, int len)
{
    if (len >= 4)
    {
        if (strstr((char *)data, "USER") == (char *)data)
        {
            printf("FTP Command: USER\n");
        }
        else if (strstr((char *)data, "PASS") == (char *)data)
        {
            printf("FTP Command: PASS\n");
        }
    }
}

void print_dns_data(const u_char *data, int len)
{
    if (len >= 12)
    {
        printf("DNS Query or Response: %.*s\n", len, data);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth = (struct ether_header *)packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    if (ip_header->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        u_char *data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        int data_len = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

        if (data_len > 0)
        {
            printf("Application Layer Data (TCP):\n");

            if (data_len > 0)
            {
                if (strstr((char *)data, "HTTP/") == (char *)data || strstr((char *)data, "GET") == (char *)data || strstr((char *)data, "POST") == (char *)data)
                {
                    printf("Protocol: HTTP\n");
                    print_http_data(data, data_len);
                }
                else if (strstr((char *)data, "USER") == (char *)data || strstr((char *)data, "PASS") == (char *)data)
                {
                    printf("Protocol: FTP\n");
                    print_ftp_data(data, data_len);
                }
                else if (data_len >= 12)
                {
                    printf("Protocol: DNS\n");
                    print_dns_data(data, data_len);
                }
                else
                {
                    printf("Unknown Protocol\n");
                }
            }
        }
    }
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        u_char *data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        int data_len = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

        if (data_len > 0)
        {
            printf("Application Layer Data (UDP):\n");

            if (data_len > 0)
            {
                if (strstr((char *)data, "HTTP/") == (char *)data || strstr((char *)data, "GET") == (char *)data || strstr((char *)data, "POST") == (char *)data)
                {
                    printf("Protocol: HTTP\n");
                    print_http_data(data, data_len);
                }
                else if (strstr((char *)data, "USER") == (char *)data || strstr((char *)data, "PASS") == (char *)data)
                {
                    printf("Protocol: FTP\n");
                    print_ftp_data(data, data_len);
                }
                else if (data_len >= 12)
                {
                    printf("Protocol: DNS\n");
                    print_dns_data(data, data_len);
                }
                else
                {
                    printf("Unknown Protocol\n");
                }
            }
        }
    }

    printf("Packet Length: %d bytes\n", header->len);
    printf("---------------------------------------\n");
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
