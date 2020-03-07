UCLA CS118 Project (Simple Router)
====================================

Khoi Nguyen, 804993073
Elwyn Cruz, 104977892


Implementation:

simple_router.cpp is the main functions for handling packets in the router.

The function works by first parsing the ethernet header of the received packet. It checks the destination
MAC address to see if it is destined to the router. After that it checks the Ethernet type. If it is ARP or
IP, then it does the following
	For received ARP Requests:
		The router builds a packet to respond, parsing throught the request packet to populate the new 
		ethernet frame & arp packet fields. After creation, the function sends the packet.
	For received ARP Replies:
		The router stores the IP/MAC information into the ARP cache. After Inserting, a list of pending packets
		is returned. The function then creates new packets from the list and sends it from the router. At 
		sending out all the packets, the function then removes the ARP request from the cache.
	For IP Packets:
		The function first checks if the lengths and the checksum is correct for the IP Packet. If it is correct 
		then it proceeds to find the Interface based on the IP destination.
		If the IP is found:
			Then the packet is meant for the router. The function then checks if it carries ICMP.
				If the packet carries ICMP:
					The function then checks if the icmp type is echo.
					If the type is echo:
						The function builds a packet for an ICMP echo reply and sends it out.
					Otherwise:
						The funciton builds a packet for a ICMP3 unreachable and sends it out.
				If the packet does not carry ICMP:
					Then the function also builds a packet for a ICMP3 port unreachable and sends it out.
		If the IP is not found:
			Then the packet is not destined for the router and needs to be forwarded. Because of this,
			the TTL for the packet is decreased by one. The function checks if the TTL is less than or equal to 
			zero and if it is then a ICMP Time Exceeded packet is constructed and sent out.

			If the TTL is valid, then checksum is recalculated. After that, the ARP Cache then looks up the next 
			hop the packet should be forwarded to. If an ARP entry is found then the function creates a IP packet
			and sends it out.

			If the ARP entry is not found, then the function queues the request. Then the function sends out an ARP 
			request.

Other functions that are important to our project include:
	Routing Table lookup() which sorts the routing table by longest mask. After that, it iterates through the sorted
	table and returns the entry with the longest mask and mathes the search parameter. 

	ArpCache periodicCheckArpRequestsandCacheEntries() handles a request by sending an ARP request about once a second.
	If 5 ARP requests have been sent, then it removes the requests. 

Difficulties Faced:
	Difficulties we faced included matching the Ethernet Broadcast Address to the packet MAC address. Making sure that
	the two were case sensitive and in the correct variable was something we overlooked at the beginning. For the ARP
	Cache, erasing the request was difficult because we did not know that we should mark it for deletion rather than 
	delete immediately. Finding out this error helped our program run. Furthermore creating the function for Routing 
	Table lookup was difficult because we did not know where to start. We first thought that we should match the mask 
	based on bits, however that was inefficient and the function would require much more work. Then we realized that 
	because it was a vector we could have a custom sort function and sort it based on longest mask. Then iterate through
	the sorted vector to see which matched and we could return .


