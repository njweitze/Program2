#include "fish.h"
#include "fishnode.h"
#include <assert.h>
#include <signal.h>
#include <string.h>

#define DEBUG

static int noprompt = 0;

void sigint_handler(int sig)
{
   if (SIGINT == sig)
	   fish_main_exit();
}

static int print_route(void *callback_data __attribute__((unused)),
      fnaddr_t dest, int prefix_len __attribute((unused)),
      fnaddr_t net_hop __attribute((unused)),
      int metric __attribute((unused)),
      void *entry_data __attribute__((unused))) {
   printf("%s\n", fn_ntoa(dest));
   return 0;
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      fish_print_neighbor_table();
   else if (0 == strcasecmp("show arp", line))
      fish_print_arp_table();
   else if (0 == strcasecmp("show route", line)) {
      fish_print_forwarding_table();
      fish_fwd.iterate_entries(&print_route, NULL, FISH_FWD_TYPE_BROADCAST);
   }
   else if (0 == strcasecmp("show dv", line))
      fish_print_dv_state();
   else if (0 == strcasecmp("quit", line) || 0 == strcasecmp("exit", line))
      fish_main_exit();
   else if (0 == strcasecmp("show topo", line))
      fish_print_lsa_topo();
   else if (0 == strcasecmp("help", line) || 0 == strcasecmp("?", line)) {
      printf("Available commands are:\n"
             "    exit                         Quit the fishnode\n"
             "    help                         Display this message\n"
             "    quit                         Quit the fishnode\n"
             "    show arp                     Display the ARP table\n"
             "    show dv                      Display the dv routing state\n"
             "    show neighbors               Display the neighbor table\n"
             "    show route                   Display the forwarding table\n"
             "    show topo                    Display the link-state routing\n"
             "                                 algorithm's view of the network\n"
             "                                 topology\n"
             "    ?                            Display this message\n"
            );
   }
   else if (line[0] != 0)
      printf("Type 'help' or '?' for a list of available commands.  "
             "Unknown command: %s\n", line);

   if (!noprompt)
      printf("> ");

   fflush(stdout);
}

// Prototypes for program 2.  Taken directly from fish.h header file
#ifdef L2_IMPL

// Define arp_callback as a separate function
void arp_callback(fn_l2addr_t addr, void *param) {
   // printf("In tha callback fn\n");
   struct L2_hdr *L2_fish = (struct L2_hdr *)param;  // Cast param to L2_hdr pointer

   if (!FNL2_VALID(addr)) {
      printf("Failed to resolve L3 address to L2\n");
      free(param);  // Free the allocated memory for the L2 frame
      return;
   }

   // Set the destination (resolved L2 address)
   L2_fish->dst = addr;

   L2_fish->checksum = in_cksum(param, ntohs(L2_fish->len));
   memcpy(param, L2_fish, sizeof(struct L2_hdr));

   // Call L1 send to transmit the frame
   fish_l1_send(L2_fish);

   // print_l2_frame(L2_fish);

   // Free the allocated memory for the L2 frame
   free(param);
}

int my_fish_l2_send(void *l3frame, fnaddr_t next_hop, int len, uint8_t l2_proto) {
   // Allocate memory for the L2 frame (L2 header + L3 frame)
   struct L2_hdr *L2_fish = malloc(sizeof(struct L2_hdr));
   memset(L2_fish, 0, sizeof(struct L2_hdr));
   int total_len = sizeof(struct L2_hdr) + len;  // Total length of L2 frame
   void *l2frame = malloc(total_len);
   memset(l2frame, 0, total_len);

   if (!l2frame) {
      printf("Memory allocation for L2 frame failed\n");
      return -1;
   }

   L2_fish->src = fish_getl2address();    // Set source address (L2)
   L2_fish->len = htons(total_len);                  // Set length
   L2_fish->protocol = l2_proto;        // Set L2 protocol
   memcpy(l2frame, L2_fish, sizeof(struct L2_hdr));
   // L2_fish = (struct L2_hdr *)l2frame;  // Point to the L2 header

   // Copy L3 frame into the L2 frame, right after the L2 header
   memcpy(l2frame + sizeof(struct L2_hdr), l3frame, len);

   arp_resolution_cb cb = arp_callback;

   // Resolve the L3 address (next_hop) to the L2 address and pass the L2 frame as param
   fish_arp.resolve_fnaddr(next_hop, cb, l2frame);
   
   // printf("Made it to the end\n");
   return 0;  // The return value is ignored
}

int my_fishnode_l2_receive(void *l2frame)
{
   // Access the received L2 frame directly from l2frame
   struct L2_hdr *L2_fish = (struct L2_hdr *)l2frame;

   // Step 1: Validate the checksum
   uint16_t original_checksum = L2_fish->checksum;
   L2_fish->checksum = 0;  // Set the checksum field to zero in l2frame for calculation
   uint16_t calculated_checksum = in_cksum(l2frame, ntohs(L2_fish->len));

   if (original_checksum != calculated_checksum) {
      // Drop the frame if the checksum is invalid
      printf("Invalid checksum. Dropping the frame.\n");
      return 1; // Frame dropped
   }

   // Step 2: Check if the frame is destined for this node
   fn_l2addr_t my_address = fish_getl2address(); // Get this node's L2 address
   if (memcmp(&L2_fish->dst, &my_address, sizeof(fn_l2addr_t)) != 0) {
      // Drop the frame if it is not destined for this node
      printf("Frame not destined for this node. Dropping the frame.\n");
      return 1; // Frame dropped
   }

   // Step 3: Decapsulate the frame and pass it up to Layer 3
   void *l3frame = (void *)((char *)l2frame + sizeof(struct L2_hdr));
   int l3_length = ntohs(L2_fish->len) - sizeof(struct L2_hdr); // Length of the L3 frame

   // Call the Layer 3 receive function
   fish_l3.fishnode_l3_receive(l3frame, l3_length);

   return 0; // Successfully processed the frame
}

void my_arp_received(void *l2frame) 
{
}



void my_send_arp_request(fnaddr_t l3addr)
{
   
}

void my_add_arp_entry(fn_l2addr_t l2addr, fnaddr_t addr, int timeout)
{
}

void my_resolve_fnaddr(fnaddr_t addr, arp_resolution_cb cb, void *param)
{
}
#endif

#ifdef L3_IMPL
int my_fishnode_l3_receive(void *l3frame, int len)
{
   return 0;
}

int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr, uint8_t proto, uint8_t ttl)
{
   return 0;
}

int my_fish_l3_forward(void *l3frame, int len)
{
   return 0;
}

// Callback to broadcast DV advertisement
void my_timed_event(void*)
{
}

// Full functionality
void* my_add_fwtable_entry(fnaddr_t dst, int prefix_length, fnaddr_t next_hop,
                   int metric, char type, void *user_data)
{
   return NULL;
}

void* my_remove_fwtable_entry(void *route_key)
{
   return NULL;
}

int my_update_fwtable_metric(void *route_key, int new_metric)
{
   return 0;
}

fnaddr_t my_longest_prefix_match(fnaddr_t addr)
{
   return 0;
}
#endif

int main(int argc, char **argv)
{
	struct sigaction sa;
   int arg_offset = 1;

   /* Verify and parse the command line parameters */
	if (argc != 2 && argc != 3 && argc != 4)
	{
		printf("Usage: %s [-noprompt] <fishhead address> [<fn address>]\n", argv[0]);
		return 1;
	}

   if (0 == strcasecmp(argv[arg_offset], "-noprompt")) {
      noprompt = 1;
      arg_offset++;
   }

   /* Install the signal handler */
	sa.sa_handler = sigint_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (-1 == sigaction(SIGINT, &sa, NULL))
	{
		perror("Couldn't set signal handler for SIGINT");
		return 2;
	}

   fish_enable_neighbor_builtin(1);

   /* Set up debugging output */
#ifdef DEBUG
	fish_setdebuglevel(FISH_DEBUG_INTERNAL);
	// fish_setdebuglevel(FISH_DEBUG_ALL);
#else
	fish_setdebuglevel(FISH_DEBUG_NONE);
#endif
	fish_setdebugfile(stdout);

   /* Join the fishnet */
	if (argc-arg_offset == 1)
		fish_joinnetwork(argv[arg_offset]);
	else
		fish_joinnetwork_addr(argv[arg_offset], fn_aton(argv[arg_offset+1]));

   /* Install the command line parsing callback */
   fish_keybhook(keyboard_callback);
   if (!noprompt)
      printf("> ");
   fflush(stdout);

#ifdef L2_IMPL
   // Examples of overriding function pointers for program 2 base functionality
   // fish_l2.fishnode_l2_receive = &my_fishnode_l2_receive;
   fish_l2.fish_l2_send = &my_fish_l2_send;
   // fish_arp.arp_received = &my_arp_received;
   // fish_arp.send_arp_request = &my_send_arp_request;
   // Full functionality functions
   // fish_arp.add_arp_entry = &my_add_arp_entry;
   // fish_arp.resolve_fnaddr = &my_resolve_fnaddr;
#endif

#ifdef L3_IMPL
   fish_l3.fishnode_l3_receive = &my_fishnode_l3_receive;
   fish_l3.fish_l3_send = &my_fish_l3_send;
   fish_l3.fish_l3_forward = &my_fish_l3_forward;
   // Set up a callback to broadcast DV advertisement
   fish_scheduleevent(0, &my_timed_event, NULL);
   // Full functionality
   fish_fwd.add_fwtable_entry = &my_add_fwtable_entry;
   fish_fwd.remove_fwtable_entry = &my_remove_fwtable_entry;
   fish_fwd.update_fwtable_metric = &my_update_fwtable_metric;
   fish_fwd.longest_prefix_match = &my_longest_prefix_match;
#endif

#if 0
   /* Enable the built-in neighbor protocol implementation.  This will discover
    * one-hop routes in your fishnet.  The link-state routing protocol requires
    * the neighbor protocol to be working, whereas it is redundant with DV.
    * Running them both doesn't break the fishnode, but will cause extra routing
    * overhead */
   fish_enable_neighbor_builtin( 0
         | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
      );
#endif

   /* Enable the link-state routing protocol.  This requires the neighbor
    * protocol to be enabled. */
   // fish_enable_lsarouting_builtin(0);

#if 0
   /* Full-featured DV routing.  I suggest NOT using this until you have some
    * reasonable expectation that your code works.  This generates a lot of
    * routing traffic in fishnet */

   fish_enable_dvrouting_builtin( 0
         | DVROUTING_WITHDRAW_ROUTES
         | DVROUTING_TRIGGERED_UPDATES
         | RVROUTING_USE_LIBFISH_NEIGHBOR_DOWN
         | DVROUTING_SPLIT_HOR_POISON_REV
         | DVROUTING_KEEP_ROUTE_HISTORY
    );
#endif

   /* Execute the libfish event loop */
	fish_main();

   /* Clean up and exit */
   if (!noprompt)
      printf("\n");
   fish_keybhook(NULL);

	printf("Fishnode exiting cleanly.\n");

   fishnet_cleanup();

   // Cleanup your data structures here

	return 0;
}
