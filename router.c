#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>
#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include "include/trie.h"
#include "include/utils.h"

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry atable[50];
int atable_len;

struct queue *q;
int current_queue_len;

struct Trie *root;

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
    uint8_t router_interface_mac[6];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
    DIE(rtable == NULL, "malloc");

    rtable_len = read_rtable(argv[1], rtable);

    root = init_trie();
    q = queue_create();

    populate_trie(root, rtable, rtable_len);

	while (1) {

		int interface;
		size_t len;
        int ret_value;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		 char *router_interface_ip = get_interface_ip(interface);
        get_interface_mac(interface, router_interface_mac);
        ret_value = is_packet_for_router(router_interface_mac, eth_hdr);

        // if the packet isnt for the router or for everyone drop it
        if (!ret_value) {
            continue;
        }

        // ipv4 packet
        if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {

            struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

            // packet has router as it's final destination and it is an icmp packet
            if (ip_hdr->daddr == inet_addr(router_interface_ip) && ip_hdr->protocol == 1) {

                uint8_t mac_aux[6];
                uint32_t ip_aux;

                // swap source and dest mac in ethernet header
                memcpy(mac_aux, eth_hdr->ether_shost, sizeof(mac_aux));
                memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_shost));
                memcpy(eth_hdr->ether_dhost, mac_aux, sizeof(eth_hdr->ether_dhost));

                // swap source and dest ip in ipv4 header
                ip_aux = ip_hdr->saddr;
                ip_hdr->saddr = ip_hdr->daddr;
                ip_hdr->daddr = ip_aux;

                struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));

                // prepare icmp header for echo reply
                icmp_hdr->type = 0;
                icmp_hdr->code = 0;

                icmp_hdr->checksum = 0;
                icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));

                // send echo reply
                send_to_link(interface, buf, len);  
            } else {

                // if checksum isn't 0 drop the packet
                if (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) != 0) {
                    continue;
                }

                // if ttl is 0 or 1 send an icmp packet with time exceeded message
                if (ip_hdr->ttl <= 1) {
                    char *packet = create_icmp_packet(eth_hdr, ip_hdr, router_interface_mac, router_interface_ip, 11);

                    send_to_link(interface, packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
                    free(packet);
                    continue;
                }

                // decrease ttl
                ip_hdr->ttl--;

                // get best route
                struct route_table_entry *best_route = get_best_route(root, ip_hdr->daddr);

                // if no route was found send an icmp packet with destination unreachable
                if (best_route == NULL) {
                    char *packet = create_icmp_packet(eth_hdr, ip_hdr, router_interface_mac, router_interface_ip, 3); 

                    send_to_link(interface, packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
                    free(packet);
                    continue;
                }

                // recalculate checksum
                ip_hdr->check = 0;
                ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

                // check if next hop mac address is in the arp entry table
                struct arp_table_entry *next_hop = get_arp_entry(atable, atable_len, best_route->next_hop);

                // if it isn't put the packet in queue and send an arp request
                if (next_hop == NULL) {
                    char *packet = malloc(len);

                    memcpy(packet, buf, len);
                    queue_enq(q, packet);
                    current_queue_len++;

                    char *arp_req_packet = create_arp_request_packet(best_route);

                    send_to_link(best_route->interface, arp_req_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
                    free(arp_req_packet);
                } else {
                    // if mac is found in arp table entry send the packet to next hop
                    memcpy(eth_hdr->ether_dhost, next_hop->mac, sizeof(eth_hdr->ether_dhost));
                    get_interface_mac(best_route->interface, eth_hdr->ether_shost);
                    send_to_link(best_route->interface, buf, len);
                }
            }
            
        // arp packet
        } else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
            struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

            // arp request
            if (ntohs(arp_hdr->op) == 1) {

                uint32_t ip_aux;
                
                // change mac addreses in the ethernet header for the arp reply
                memcpy(eth_hdr->ether_shost, router_interface_mac, sizeof(eth_hdr->ether_shost));
                memcpy(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(eth_hdr->ether_dhost));

                // swap ip addreses in the arp header
                ip_aux = arp_hdr->spa;
                arp_hdr->spa = arp_hdr->tpa;
                arp_hdr->tpa = ip_aux;

                // change op to indicate arp reply
                arp_hdr->op = htons(2);

                // change hardware addreses in arp packet
                memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(arp_hdr->sha));
                memcpy(arp_hdr->tha, eth_hdr->ether_dhost, sizeof(arp_hdr->tha));

                // send arp reply packet
                send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));

            // arp reply
            } else if (ntohs(arp_hdr->op) == 2) {
                
                // check if the ip ip and mac from the reply already exist in arp table
                struct arp_table_entry *entry = get_arp_entry(atable, atable_len, arp_hdr->spa);

                // if they don't exist add them
                if (entry == NULL) {
                    atable[atable_len].ip = arp_hdr->spa;
                    memcpy(atable[atable_len].mac, arp_hdr->sha, sizeof(atable[atable_len].mac));
                    atable_len++;
                }

                int queue_len = current_queue_len;

                // check all the packets that were added to the queue
                while (queue_len) {
                    char *packet = (char *) queue_deq(q);
                    current_queue_len--;

                    struct ether_header *pkt_hdr = (struct ether_header *) packet;

                    struct iphdr *ip_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));

                    // calculate the best route again for the packet
                    struct route_table_entry *best_route = get_best_route(root, ip_hdr->daddr);

                    // check if mac and ip for next hop exist in arp table
                    struct arp_table_entry *arp_entry = get_arp_entry(atable, atable_len, best_route->next_hop);

                    // if we find the mac address in the arp table we send the packet to next hop
                    if (arp_entry != NULL) {
                        get_interface_mac(best_route->interface, pkt_hdr->ether_shost);
                        memcpy(pkt_hdr->ether_dhost, arp_entry->mac, sizeof(pkt_hdr->ether_dhost));

                        send_to_link(best_route->interface, packet, sizeof(struct ether_header) + sizeof(struct iphdr));
                        free(packet);

                    // if we don't find the mac address we put the packet back in the queue    
                    } else {
                        queue_enq(q, packet);
                        current_queue_len++;
                    }

                    queue_len--;
                }
            }
        } 
	}
	
    free(q);
    free_trie(root);
    free(rtable);
}

