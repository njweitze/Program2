int my_fishnode_l2_receive(void *l2frame) {
   // Access the received L2 frame directly from l2frame
   struct L2_hdr *L2_fish = malloc(sizeof(struct L2_hdr));
   memset(L2_fish, 0, sizeof(struct L2_hdr));
   memcpy(L2_fish, l2frame, sizeof(struct L2_hdr));

   // Step 1: Validate the checksum
   // uint16_t original_checksum = L2_fish->checksum; // Save the original checksum
   // L2_fish->checksum = 0; // Temporarily set the checksum field to zero for calculation
   // uint16_t calculated_checksum = in_cksum(l2frame, ntohs(L2_fish->len));

   if (in_cksum(l2frame, ntohs(L2_fish->len)) != 0) {
      // Drop the frame if the checksum is invalid
      printf("Invalid checksum. Dropping the frame.\n");
      free(L2_fish);
      return 1; // Frame dropped
   }

   // Step 2: Check if the frame is destined for this node or broadcast
   fn_l2addr_t my_address = fish_getl2address(); // Get this node's L2 address
   
   if (L2_fish->protocol == 2) {
      fish_arp.arp_received(l2frame);
   } else if (FNL2_EQ(L2_fish->dst, ALL_L2_NEIGHBORS) || FNL2_EQ(L2_fish->dst, my_address)) {
       // Extract the L3 frame from the L2 frame
      //  void *l3frame = (void *)((char *)l2frame + sizeof(struct L2_hdr));
      //  uint16_t l3_length = ntohs(L2_fish->len) - sizeof(struct L2_hdr);

      //  // Pass the extracted L3 frame to the L3 layer
      //  fish_l3.fishnode_l3_receive(l3frame, l3_length);
      uint16_t l3_len = htons(L2_fish->len) - sizeof(struct L2_hdr);
      fish_l3.fish_l3_receive(L2_fish + sizeof(struct L2_hdr), l3_len);

   } else {
       // Frame is not for this node or a broadcast
      //  printf("Frame not destined for this node. Ignoring.\n");
      free(L2_fish);
      return 0;
   }
   free(L2_fish);

   return 0; // Successfully processed the frame
}