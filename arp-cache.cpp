/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  //check valid

/*
	for each request in queued requests :
		handleRequest(request)
		
	for each cache entry in entries :
		if not entry->isValid
			record entry for removal
	remove all entries marked for removal
*/
    const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	std::list<std::shared_ptr<ArpEntry>> removeArpEntries;
    std::list<std::shared_ptr<ArpRequest>> removeArpRequests;
    for (auto req = m_arpRequests.begin(); req != m_arpRequests.end(); req++) {
		
		// handle request, by sending an arp request about once/second

		//check if we've sent the request 5 times
		if ((*req)->nTimesSent < MAX_SENT_TIME) {
            // build ARP request
			Buffer request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
			uint8_t* req_buf = (uint8_t*) request.data();

			// create ethernet header
			ethernet_hdr* req_ehdr = (ethernet_hdr*)req_buf;
			// get name of iface of first packet
			std::string name = (*req)->packets.front().iface;
			const Interface* iface = m_router.findIfaceByName(name);
			
			memcpy(req_ehdr->ether_dhost, BroadcastEtherAddr , ETHER_ADDR_LEN);
			memcpy(req_ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
			req_ehdr->ether_type = htons(ethertype_arp);

			// create ARP req header
            arp_hdr* req_ahdr = (arp_hdr*)(req_buf + sizeof(ethernet_hdr));
            req_ahdr->arp_hrd = htons(arp_hrd_ethernet);
            req_ahdr->arp_pro = htons(ethertype_ip);
            req_ahdr->arp_hln = 0x06;
            req_ahdr->arp_pln = 0x04;
            req_ahdr->arp_op = htons(arp_op_request);
            memcpy(req_ahdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
            req_ahdr->arp_sip = iface->ip;
            memcpy(req_ahdr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
            req_ahdr->arp_tip = (*req)->ip;


            // send request 
            m_router.sendPacket(request, name);

            // update time since last send
            (*req)->timeSent = steady_clock::now();
            (*req)->nTimesSent++;

            // move to next request
		}

        else { // remove the request 
            // first remove all the packets
            for (auto pack = (*req)->packets.begin(); pack != (*req)->packets.end();) {
                pack = (*req)->packets.erase(pack);
            }
            // remove pending request from queue mark for deletion
            removeArpRequests.push_back(*req);
            
            
            
        }



    }

    //remove pending requests marked for deletion
    for (auto removeMe = removeArpRequests.begin(); removeMe != removeArpRequests.end(); removeMe++)
        removeRequest(*removeMe);
        


    // record any invalid cache entries
    for (auto cacheEntry : m_cacheEntries) {
        if (!cacheEntry->isValid) {
            removeArpEntries.push_back(cacheEntry); // record for removal
        }
    }

	// remove entries marked for removal
    for (auto removeMe = removeArpEntries.begin(); removeMe != removeArpEntries.end(); ) {
        removeMe = m_cacheEntries.erase(removeMe);
	}
	/*
  for(auto it = m_cacheEntries.begin(); it != m_cacheEntries.end();)
  {
    if((*it)->isValid == false)
    {
      it = m_cacheEntries.erase(it)
      break;
    }
    it++;
  }
  */
  
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
