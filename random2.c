void my_arp_received(void *l2frame) {
   // Extract L2 header and ARP packet
   //  struct L2_hdr *l2hdr = (struct L2_hdr *)l2frame;
   struct L2_hdr *l2hdr = malloc(sizeof(struct L2_hdr));
   memset(l2hdr, 0, sizeof(struct L2_hdr));
   memcpy(l2hdr, l2frame, sizeof(struct L2_hdr));

   struct ARP_Packet *arp_pkt = malloc(sizeof(struct ARP_Packet));
   memset(arp_pkt, 0, sizeof(struct ARP_Packet));
   memcpy(arp_pkt, l2frame + sizeof(l2hdr), sizeof(struct ARP_Packet));

   // Handle ARP Request
   if (ntohl(arp_pkt->query_type) == 1) { // ARP Request
      // Ignore if not the target
      if(!FNL2_EQ(l2hdr->dst, ALL_L2_NEIGHBORS) && !FNL2_VALID(l2hdr->dst)) {
         return;
      }

      if (arp_pkt->queried_l3addr != fish_getaddress()) {
         return;
      }

      // Create ARP response packet
      struct ARP_Packet *response_pkt = malloc(sizeof(struct ARP_Packet));
      memset(response_pkt, 0, sizeof(struct ARP_Packet));
      response_pkt->query_type = htonl((uint8_t)2); // ARP Response
      response_pkt->queried_l3addr = fish_getaddress();
      response_pkt->l2addr = fish_getl2address();

      // Create L2 header for the ARP response
      struct L2_hdr *response_l2hdr = malloc(sizeof(struct L2_hdr));
      memset(response_l2hdr, 0, sizeof(struct L2_hdr));
      response_l2hdr->dst = l2hdr->src;
      response_l2hdr->src = fish_getl2address();
      response_l2hdr->protocol = (uint8_t)2;
      response_l2hdr->len = htons(sizeof(struct L2_hdr) + sizeof(struct ARP_Packet));

      // Allocate memory for the complete ARP response frame
      uint16_t response_size = sizeof(struct L2_hdr) + sizeof(struct ARP_Packet);
      void *response_frame = malloc(response_size);
      memset(response_frame, 0, response_size);
      if (!response_frame) {
         return;
      }

      // Copy L2 header and ARP response packet into the response frame
      memcpy(response_frame, response_l2hdr, sizeof(struct L2_hdr));
      memcpy(response_frame + sizeof(struct L2_hdr), response_pkt, sizeof(struct ARP_Packet));

      // Calculate and set the checksum
      response_l2hdr->checksum = in_cksum(response_frame, response_size);
      memcpy(response_frame, response_l2hdr, sizeof(struct L2_hdr));

      // Send the ARP response
      fish_l1_send(response_frame);

      // Free allocated memory
      free(response_frame);
   } 
   // Handle ARP Response
   else if (ntohl(arp_pkt->query_type) == 2) { // ARP Response
      fish_arp.add_arp_entry(arp_pkt->l2addr, arp_pkt->queried_l3addr, 180);
   }

   free(l2hdr);
   free(arp_pkt);
}