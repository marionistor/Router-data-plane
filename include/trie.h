#ifndef _TRIE_H_
#define _TRIE_H_

#include <stdint.h>


// trie struct for longest prefix match
struct Trie {
    struct route_table_entry *rtable_entry;
    struct Trie* child[2];
};


struct Trie *init_trie(void);
void populate_trie(struct Trie *root, struct route_table_entry *rtable, int rtable_len);
struct route_table_entry *get_best_route(struct Trie *root, uint32_t dest_ip);
void free_trie(struct Trie *root);

#endif
