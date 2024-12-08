#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

void datalink(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth = (struct ether_header *)packet;
    printf("Frame Type: Ethernet\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("EtherType: 0x%04x\n", ntohs(eth->ether_type));
    printf("Frame Length: %d bytes\n", header->len);

    if (header->len > sizeof(struct ether_header))
    {
        const u_char *fcs = packet + header->len - 4;
        printf("Frame Check Sequence (FCS/CRC): 0x%02x%02x%02x%02x\n",
               fcs[0], fcs[1], fcs[2], fcs[3]);
    }
    else
    {
        printf("FCS/CRC: Not present\n");
    }

    printf("-----------------------------------------\n");
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
    pcap_t *handle = pcap_open_live(dev_name, BUFSIZ, 1, 100, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening device %s: %s\n", dev_name, errbuf);
        pcap_freealldevs(all_devs);
        return 1;
    }

    printf("Capturing Ethernet Packets on %s\n", dev_name);
    pcap_loop(handle, -1, datalink, NULL);
    pcap_close(handle);
    pcap_freealldevs(all_devs);
    return 0;
}
