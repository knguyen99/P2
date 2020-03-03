/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
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

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  uint8_t* data = packet.data();
  uint32_t len = packet.size();

  uint16_t ethtype = ethertype(data);
  ethernet_hdr* ehdr = (ethernet_hdr*)data;

  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    fprintf(stderr, "ETHERNET header, insufficient length\n");
    return;
  }

  // if MAC address equals destination address (destination is router) or destination is broadcast address
  if (strcmp(ehdr->ether_dhost, iface->addr.data()) == 0 || strcmp(ehdr->ether_dhost, "FF:FF:FF:FF:FF:FF") == 0) { 
      if ( ehdr->ether_type == htons(ethertype_arp) ) //ARP
      {
        minlength += sizeof(arp_hdr);
        if (length < minlength)
          fprintf(stderr, "ARP header, insufficient length\n");
        else
        {
          const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
          const Interface* arp_iface = findIfaceByIp(hdr->tip);
          if(hdr->op == htons(arp_op_request) && arp_iface) //if request correct, respond
          {
            //build response packet
            Buffer response_packet(sizeof(ethernet_hdr)+ sizeof(arp_hdr));

            uint8_t* rp_buf = response_packet.data();
            
            //fill in ethernet header
            ethernet_hdr* rep_ehdr = (ethernet_hdr*)rp_buf;
            memcpy(rep_ehdr->ether_dhost, hdr->arp_sha, sizeof(hdr->arp_sha));
            memcpy(rep_ehdr->ether_shost,arp_iface->addr,sizeof(arp_iface->addr));
            rep_ehdr->ether_type = htons(ethertype_arp);

            //fill in arp header
            arp_hdr* rep_ahdr = (arp_hdr*)(rp_buf+sizeof(ethernet_hdr));
            rep_ahdr->arp_hrd = htons(arp_hrd_ethernet);
            rep_ahdr->arp_pro = htons(ethertype_ip);
            rep_ahdr->arp_hln = 0x06;
            rep_ahdr->arp_pln = 0x04;
            rep_ahdr->arp_op = htons(arp_op_reply);
            memcpy(rep_ahdr->arp_sha, arp_iface->addr, sizeof(arp_iface->addr));
            rep_ahdr->arp_sip = arp_iface->ip;
            memcpy(rep_ahdr->arp_tha, hdr->sha, sizeof(hdr->sha));
            rep_ahdr->arp_tip = hdr->arp_sip;

            //full send bAYYbEEEE
            sendPacket(response_packet, arp_iface->name);
          }
          else if(hdr->op == htons(arp_op_reply)) //if receive reply
          {
            Buffer reply_madr(sizeof(hdr->sha));
            uint8_t* rp_data = reply_madr.data();
            memcpy(rp_data, hdr->sha, sizeof(hdr->sha));

            std::shared_ptr<ArpRequest> arp_insert = m_arp.insertArpEntry(reply_madr,hdr->sip);
            if(arp_insert) //proceed with handling
            {
              list<PendingPacket> packets = arp_insert->packets;
              for(auto it = packets.begin(); it != packets.end(); it++){
                std::shared_ptr<ArpEntry> arp_lookup = m_arp.lookup(it->ip);
                if(arp_lookup) //if found in cache
                {
                  Buffer lookup_packet(sizeof(ethernet_hdr));
                  uint8_t* l_buf = lookup_packet.data();
                  ethernet_hdr* lookup_ehdr = (ethernet_hdr*)l_buf;
                  //memcpy(lookup_ehdr->dhost,arp_lookup->,sizeof());
                  //memcpy(lookup_ehdr->shost,,sizeof());

                }
                else //queue
                {
                  //h
                }
              }

            }
            else //queue received packet and start sending arp request to disover
            {

            }
          }
        }
      } 
      else if ( ehdr->ether_type == htons(ethertype_ip)) { //IP
          
      }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
