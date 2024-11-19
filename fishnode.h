#ifndef FISHNODE_H
#define FISHNODE_H

#include <stdint.h>
#include "fish.h"  // Assuming fish.h contains necessary definitions

#define L2_IMPL

// Signal handler for SIGINT
void sigint_handler(int sig);

// L2 Implementation
#ifdef L2_IMPL

struct L2_hdr {
    fn_l2addr_t dst;
    fn_l2addr_t src;
    uint16_t checksum;
    uint16_t len;
    uint8_t protocol;
} __attribute__((packed));

struct ARP_Packet {
    uint8_t query_type;       // 1 byte: Query Type (1 for request, 2 for response)
    fnaddr_t queried_l3addr;  // 4 bytes: Queried L3 Address (e.g., IP address)
    fn_l2addr_t l2addr;       // 6 bytes: L2 Address for the Queried L3 Address (only valid in responses)
} __attribute__((packed));

void print_l2_frame(void *l2frame);
int my_fish_l2_send(void *l3frame, fnaddr_t next_hop, int len, uint8_t l2_proto);
int my_fishnode_l2_receive(void *l2frame);
void my_arp_received(void *l2frame);
void my_send_arp_request(fnaddr_t l3addr);
void my_add_arp_entry(fn_l2addr_t l2addr, fnaddr_t addr, int timeout);
void my_resolve_fnaddr(fnaddr_t addr, arp_resolution_cb cb, void *param);
#endif

// L3 Implementation
#ifdef L3_IMPL
int my_fishnode_l3_receive(void *l3frame, int len);
int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr, uint8_t proto, uint8_t ttl);
int my_fish_l3_forward(void *l3frame, int len);
void my_timed_event(void *param);
void* my_add_fwtable_entry(fnaddr_t dst, int prefix_length, fnaddr_t next_hop, int metric, char type, void *user_data);
void* my_remove_fwtable_entry(void *route_key);
int my_update_fwtable_metric(void *route_key, int new_metric);
fnaddr_t my_longest_prefix_match(fnaddr_t addr);
#endif

#endif // FISHNODE_H
