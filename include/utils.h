#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>


struct arp_table_entry *get_arp_entry(struct arp_table_entry *atable, int atable_len, uint32_t dest_ip);
int is_packet_for_router(uint8_t *router_interface_mac, struct ether_header *eth_hdr);
char *create_icmp_packet(struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t *router_interface_mac, char *router_interface_ip, uint8_t type);
char *create_arp_request_packet(struct route_table_entry *best_route);

#endif
