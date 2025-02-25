#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>
#include "../include/lib.h"
#include "../include/protocols.h"
#include "../include/utils.h"

// get arp entry that matches the destination ip address 
struct arp_table_entry *get_arp_entry(struct arp_table_entry *atable, int atable_len, uint32_t dest_ip)
{
    for (int i = 0; i < atable_len; i++) {
        if (atable[i].ip == dest_ip) {
            return &atable[i];
        }
    }

    return NULL;
}

// check if the packet is for everyone (dest mac is broadcast address) or for the router (dest mac is the same as router interface mac)
int is_packet_for_router(uint8_t *router_interface_mac, struct ether_header *eth_hdr)
{
    int ret_value = 1;

    // check if dest mac is router interface mac
    for (int i = 0; i < 6; i++) {
        if (router_interface_mac[i] != eth_hdr->ether_dhost[i]) {
            ret_value = 0;
            break;
        }
    }

    // check if dest mac is broadcast address
    if (!ret_value) {
        ret_value = 1;
        for (int i = 0; i < 6; i++) {
            if (eth_hdr->ether_dhost[i] != 0xff) {
                ret_value = 0;
                break;
            }
        }
    }

    return ret_value;
}

// create an icmp packet
char *create_icmp_packet(struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t *router_interface_mac, char *router_interface_ip, uint8_t type)
{
    char *packet = malloc(MAX_PACKET_LEN);

    struct ether_header *eth_icmp_hdr = (struct ether_header *) packet;

    eth_icmp_hdr->ether_type = htons(ETHERTYPE_IP);
    memcpy(eth_icmp_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_icmp_hdr->ether_dhost));
    memcpy(eth_icmp_hdr->ether_shost, router_interface_mac, sizeof(eth_icmp_hdr->ether_shost));

    struct iphdr *ip_icmp_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));

    // initialise ipv4 header
    ip_icmp_hdr->tos = 0;
    ip_icmp_hdr->frag_off = 0;
    ip_icmp_hdr->version = 4;
    ip_icmp_hdr->ihl = 5;
    ip_icmp_hdr->id = 1;
    ip_icmp_hdr->ttl = 64;
    ip_icmp_hdr->protocol = 1;
    ip_icmp_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    ip_icmp_hdr->daddr = ip_hdr->saddr;
    ip_icmp_hdr->saddr = inet_addr(router_interface_ip);

    ip_icmp_hdr->check = 0;
    ip_icmp_hdr->check = htons(checksum((uint16_t *) ip_icmp_hdr, sizeof(struct iphdr))); 

    struct icmphdr *icmp_te_hdr = (struct icmphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    icmp_te_hdr->type = type;
    icmp_te_hdr->code = 0;

    icmp_te_hdr->checksum = 0;
    icmp_te_hdr->checksum = htons(checksum((uint16_t *) icmp_te_hdr, sizeof(struct icmphdr)));

    // ipv4 header of dropped packet
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(*ip_hdr));
    
    // copy first 64 bits from orginal packet from original payload
    memcpy(packet + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr + sizeof(struct iphdr), 8);

    return packet;
}

// create an arp request packet
char *create_arp_request_packet(struct route_table_entry *best_route)
{
    char *arp_req_packet = malloc(MAX_PACKET_LEN);

    struct ether_header *eth_req_hdr = (struct ether_header *) arp_req_packet;

    eth_req_hdr->ether_type = htons(ETHERTYPE_ARP);

    get_interface_mac(best_route->interface, eth_req_hdr->ether_shost);
    memset(eth_req_hdr->ether_dhost, 0xff, sizeof(eth_req_hdr->ether_dhost));

    struct arp_header *arp_req_hdr = (struct arp_header *) (arp_req_packet + sizeof(struct ether_header));

    // initialse arp header for arp request
    arp_req_hdr->htype = htons(1);
    arp_req_hdr->ptype = htons(ETHERTYPE_IP);
    arp_req_hdr->hlen = 6;
    arp_req_hdr->plen = 4;
    arp_req_hdr->op = htons(1);
    memcpy(arp_req_hdr->sha, eth_req_hdr->ether_shost, sizeof(arp_req_hdr->sha));
    arp_req_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
    memset(arp_req_hdr->tha, 0, sizeof(arp_req_hdr->tha));

    arp_req_hdr->tpa = best_route->next_hop;

    return arp_req_packet;
}
