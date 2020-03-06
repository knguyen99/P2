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
  const uint8_t ETHER_BROADCAST_ADDRESS = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  // if MAC address equals destination address (destination is router) or destination is broadcast address
  if (strcmp(ehdr->ether_dhost, iface->addr.data()) == 0 || strcmp(ehdr->ether_dhost, ETHER_BROADCAST_ADDRESS) == 0) { 
      if ( ehdr->ether_type == htons(ethertype_arp) ) //ARP
      {
        minlength += sizeof(arp_hdr);
        if (length < minlength){
          fprintf(stderr, "ARP header, insufficient length\n");
          return
        }
        else
        {
          const arp_hdr *hdr = (arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
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
                uint8_t* pending_buff = it->packet.data();
                ethernet_hdr* pending_ehdr = (ethernet_hdr*)pending_buff;
                memcpy(pending_ehdr->ether_dhost, iface->addr.data() ,sizeof(iface->addr.data()));
                memcpy(pending_ehdr->ether_shost, hdr->arp_sha,sizeof(hdr->arp_sha));

                sendPacket(it->packet, it->iface);
              }
              m_arp.removeRequest(arp_insert);         
            }   
          }
        }
      } 
      else if ( ehdr->ether_type == htons(ethertype_ip)) { //IP
        minlength += sizeof(ip_hdr);
        if (length < minlength)
        {
          fprintf(stderr, "IP header, insufficient length\n");
          return;
        }
        else
        {
          const ip_hdr *hdr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
          uint16_t isum = hdr->ip_sum; // expected chksum
          hdr->ip_sum = 0;
          uint16_t csum = cksum(hdr, sizeof(ip_hdr)); // new calculated chksum
          if(isum != csum) // chksums not equal
          {
            fprintf(stderr, "IP header, checksum length error");
            return;
          }

          Interface* ip_iface = findIfaceByIp(hdr->ip_dst); // was (hdr->ip_src); shouldnt we be checking destination
          if(ip_iface) //destined for router, check if ICMP
          {
            if(hdr->ip_protocol == ip_protocol_icmp) //if it carries ICMP, properly dispatch it 
            {
                icmp_hdr* icmp_msg = (icmp_hdr*)(hdr + sizeof(ip_hdr)); // icmp is payload of ip
                // get type of icmp message
                uint8_t type = icmp_msg->icmp_type;

                //check if echo, otherwise send unreachable
                if (type == 8) { // echo
                    // send echo reply
                    Buffer icmp_reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
                    uint8_t* icmp_reply_buf = (uint8_t*) icmp_reply.data();
                    
                    // construct ethernet frame (is this needed) ???????
                    ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                    icmp_ether_hdr->ether_shost = ehdr->ether_dhost;
                    icmp_ether_hdr->ether_dhost = ehdr->ether_shost;
                    icmp_ether_hdr->ether_type = ehdr->ether_type;

                    // construct IP header
                    ip_hdr* icmp_ip_hdr = (ip_hdr*) (icmp_reply_buf + sizeof(ethernet_hdr));
                    icmp_ip_hdr->ip_src = ip_iface->ip;
                    icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                    icmp_ip_hdr->ip_p = ip_protocol_icmp;
                    icmp_ip_hdr->ip_ttl = 64; // maybe ???
                    icmp_ip_hdr->ip_sum = 0;
                    icmp_ip_hdr->ip_sum = cksum((uint8_t*)icmp_ip_hdr, sizeof(ip_hdr));

                    // construct ICMP 
                    icmp_hdr* icmp_head = (icmp_hdr*)(icmp_ip_hdr + sizeof(ip_hdr));
                    icmp_head->icmp_type = 0;
                    icmp_head->icmp_code = 0;
                    icmp_head->icmp_sum = 0;
                    icmp_head->icmp_sum = cksum((uint8_t*)icmp_head, sizeof(icmp_hdr));

                    // send ICMP packet

                    sendPacket(icmp_reply, iface->name);
                }
                else { // send icmp3 unreachable
                    // send echo reply
                    Buffer icmp_reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
                    uint8_t* icmp_reply_buf = (uint8_t*)icmp_reply.data();

                    // construct ethernet frame (is this needed) ???????
                    ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                    icmp_ether_hdr->ether_shost = ehdr->ether_dhost;
                    icmp_ether_hdr->ether_dhost = ehdr->ether_shost;
                    icmp_ether_hdr->ether_type = ehdr->ether_type;

                    // construct IP header
                    ip_hdr* icmp_ip_hdr = (ip_hdr*)(icmp_reply_buf + sizeof(ethernet_hdr));
                    icmp_ip_hdr->ip_src = ip_iface->ip;
                    icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                    icmp_ip_hdr->ip_p = ip_protocol_icmp;
                    icmp_ip_hdr->ip_ttl = 64; // maybe ???
                    icmp_ip_hdr->ip_sum = 0;
                    icmp_ip_hdr->ip_sum = cksum((uint8_t*)icmp_ip_hdr, sizeof(ip_hdr));


                    // construct ICMP 
                    icmp_t3_hdr* icmp_head = (icmp_t3_hdr*)(icmp_ip_hdr + sizeof(ip_t3_hdr));
                    icmp_head->icmp_type = 3;
                    icmp_head->icmp_code = 3;
                    icmp_head->unused = 0;
                    icmp_head->next_mtu = 0;
                    memcpy(icmp_head->data, hdr, sizeof(ip_hdr) + 8 * sizeof(uint8_t)); // data is ip hdr + first 8 bytes of payload
                    icmp_head->icmp_sum = 0;
                    icmp_head->icmp_sum = cksum((uint8_t*)icmp_head, sizeof(icmp_hdr));
                    

                    // send ICMP packet

                    sendPacket(icmp_reply, iface->name);

                }
                
                
            }
            else //if not return, drop packet
            {
              return;
            }
          }
          else //not destined for router, forward
          {
            hdr->ttl -= 1;
            if(hdr->ttl <= 0) //ttl exceeded, send ICMP Time Exceeded 
            {
                // TODO: generate ICMP time exceeded message
                Buffer icmp_time_exceed(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
                uint8_t* icmp_reply_buf = (uint8_t*)icmp_time_exceed.data();

                // construct ethernet frame 
                ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                icmp_ether_hdr->ether_shost = iface->addr; 
                icmp_ether_hdr->ether_dhost = ehdr->ether_shost;// send back
                icmp_ether_hdr->ether_type = ehdr->ether_type;

                // construct IP header
                ip_hdr* icmp_ip_hdr = (ip_hdr*)(icmp_reply_buf + sizeof(ethernet_hdr));
                icmp_ip_hdr->ip_src = ip_iface->ip;
                icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                icmp_ip_hdr->ip_p = ip_protocol_icmp;
                icmp_ip_hdr->ip_ttl = 64; // maybe ???
                icmp_ip_hdr->ip_sum = 0;
                icmp_ip_hdr->ip_sum = cksum((uint8_t*)icmp_ip_hdr, sizeof(ip_hdr));

                // construct ICMP 
                icmp_t3_hdr* icmp_head = (icmp_t3_hdr*)(icmp_ip_hdr + sizeof(ip_hdr));
                icmp_head->icmp_type = 11;
                icmp_head->icmp_code = 0;
            
                icmp_head->unused = 0;
                icmp_head->next_mtu = 0;
                memcpy(icmp_head->data, hdr, sizeof(ip_hdr) + 8 * sizeof(uint8_t)); // data is ip hdr + first 8 bytes of payload
                icmp_head->icmp_sum = 0;
                icmp_head->icmp_sum = cksum((uint8_t*)icmp_head, sizeof(icmp_hdr));

                // send ICMP packet

                sendPacket(icmp_time_exceed, iface->name);
              return; 
            }

            //recompute checksum for datagram
            hdr->ip_sum = 0;
            hdr->ip_sum = cksum(hdr, sizeof(ip_hdr));

            RoutingTableEntry rt_entry = m_routingTable.lookup(hdr->ip_dst);
            if(!rt_entry)
            {
              return; //next hop not found
            }
            const Interface* next_iface = findIfaceByName(rt_entry.ifName);
            if(!next_iface)
            {
              return; //next iface not found
            }
            std::shared_ptr<ArpEntry> next_arp = m_arp.lookup(rt_entry.gw);
            if(next_arp) //forward packet
            {
              
            }
            else //cache packet adn send arp request
            {

            }
          }

        }
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
