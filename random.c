void my_arp_received(void *l2frame) {
   // Cast the L2 frame to access the ARP packet
   struct L2_hdr *l2_hdr = (struct L2_hdr *)l2frame;
   struct ARP_Packet *arp_packet = (struct ARP_Packet *)((char *)l2frame + sizeof(struct L2_hdr));

   // Check if the ARP packet is a request or response
   if (arp_packet->query_type == 1) { // ARP request
      printf("ARP request received for IP: %s\n", fn_ntoa(arp_packet->queried_l3addr));

      // Check if this node is the intended recipient
      if (arp_packet->queried_l3addr == fish_getl3address()) {
         // Prepare an ARP response
         struct L2_hdr response_l2_hdr;
         struct ARP_Packet response_arp;

         // Set up the response L2 header
         response_l2_hdr.src = fish_getl2address();
         response_l2_hdr.dst = l2_hdr->src; // Send back to the requester
         response_l2_hdr.protocol = l2_hdr->protocol; // Use the same protocol

         // Set up the response ARP packet
         response_arp.query_type = 2; // Response type
         response_arp.queried_l3addr = arp_packet->queried_l3addr; // Echo the requested IP
         response_arp.l2addr = fish_getl2address(); // Set the current node's L2 address

         // Construct the response frame (L2 header + ARP packet)
         void *response_frame = malloc(sizeof(struct L2_hdr) + sizeof(struct ARP_Packet));
         memcpy(response_frame, &response_l2_hdr, sizeof(struct L2_hdr));
         memcpy((char *)response_frame + sizeof(struct L2_hdr), &response_arp, sizeof(struct ARP_Packet));

         // Send the ARP response
         fish_l1_send(response_frame);
         free(response_frame);

         printf("Sent ARP response to %s\n", fn_ntoa(arp_packet->queried_l3addr));
      }
   } else if (arp_packet->query_type == 2) { // ARP response
      printf("ARP response received from %s\n", fn_ntoa(arp_packet->queried_l3addr));

      // Add the ARP entry to the table
      fish_arp.add_arp_entry(arp_packet->l2addr, arp_packet->queried_l3addr);
   }
}