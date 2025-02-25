#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>
#include "../include/lib.h"
#include "../include/protocols.h"
#include "../include/trie.h"

// init trie root
struct Trie *init_trie()
{
    struct Trie *node;
    node = malloc(sizeof(struct Trie));
    node->child[0] = node->child[1] = NULL;
    node->rtable_entry = NULL;

    return node;
}

// populate trie using route table entry
void populate_trie(struct Trie *root, struct route_table_entry *rtable, int rtable_len)
{
    int bit_index;
    uint8_t mask_bit, prefix_bit;
    uint32_t mask, prefix;
    struct Trie *node;

    for (int i = 0; i < rtable_len; i++) {
        mask = rtable[i].mask;
        prefix = rtable[i].prefix;
        bit_index = 31;
        node = root;

        // get bit at index bit_index from mask
        mask_bit = (ntohl(mask) & (1 << bit_index)) >> bit_index; 

        // stop if the bit from mask is zero or bit_index is smaller than 0
        while (mask_bit && (bit_index >= 0)) {
            // get bit at index bit_index from prefix
            prefix_bit = (ntohl(prefix) & (1 << bit_index)) >> bit_index; 

            if (prefix_bit) {
                if (node->child[1] == NULL) {
                    node->child[1] = malloc(sizeof(struct Trie));
                    node->child[1]->rtable_entry = NULL;
                    node->child[1]->child[0] = node->child[1]->child[1] = NULL;
                }

                node = node->child[1];
            } else {
                if (node->child[0] == NULL) {
                    node->child[0] = malloc(sizeof(struct Trie));
                    node->child[0]->rtable_entry = NULL;
                    node->child[0]->child[0] = node->child[0]->child[1] = NULL;
                }

                node = node->child[0];
            }

            // go to next bit index
            bit_index--;
            if (bit_index >= 0) {
                // extract the next bit from mask
                mask_bit = (ntohl(mask) & (1 << bit_index)) >> bit_index;
            }

            /* if the next bit from mask is 0 node will be a leaf node and
             * will retain the rtable entry */
            if (!mask_bit) {
                node->rtable_entry = &rtable[i];
            }
        }   
    }
}

// get_best_route for destination ip address
struct route_table_entry *get_best_route(struct Trie *root, uint32_t dest_ip)
{
    struct route_table_entry *best_route = NULL;
    struct Trie *node = root;
    int bit_index = 31;
    int ip_bit;

    while (bit_index >= 0) {
        
        // get bit at index bit_index from destination ip
        ip_bit = (ntohl(dest_ip) & (1 << bit_index)) >> bit_index;
        
        if (ip_bit) {
            node = node->child[1];
            
            if (node == NULL) {
                break;
            }

            // if the rtable entry from the node is not null we store it as best_route
            if (node->rtable_entry != NULL) {
                best_route = node->rtable_entry;
            }

        } else {
            node = node->child[0];

            if (node == NULL) {
                break;
            }

            best_route = node->rtable_entry;
        }

        // go to next bit index
        bit_index--;
    }

    return best_route;
}

// free trie
void free_trie(struct Trie *root)
{
    if (root != NULL) {
        free_trie(root->child[0]);
        free_trie(root->child[1]);
        free(root);
    }
}

