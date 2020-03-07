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
    const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN
    uint8_t* data = (uint8_t*)packet.data();
    uint32_t len = packet.size();

    uint16_t ethtype = ethertype(data);
    ethernet_hdr* ehdr = (ethernet_hdr*)data;

    size_t minlength = sizeof(ethernet_hdr);
    if (len < minlength) {
        fprintf(stderr, "ETHERNET header, insufficient length\n");
        return;
    }
    std::string packetMACaddr = macToString(packet); // get dest MAC address
    static const uint8_t ETHER_BROADCAST_ADDRESS[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // if MAC address equals destination address (destination is router) or destination is broadcast address
    if (packetMACaddr == macToString(iface->addr) || (packetMACaddr == ETHER_BROADCAST_ADDRESS)) {
        if (ethtype == ethertype_arp) //ARP
        {
            minlength += sizeof(arp_hdr);
            if (len < minlength) {
                fprintf(stderr, "ARP header, insufficient length\n");
                return;
            }
            else
            {
                const arp_hdr* hdr = (arp_hdr*)(data + sizeof(ethernet_hdr));
                const Interface* arp_iface = findIfaceByIp(hdr->arp_tip);
                if (hdr->arp_op == htons(arp_op_request) && arp_iface->ip == hdr->arp_tip) //if request correct, respond
                {
                    //build response packet
                    Buffer response_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));

                    uint8_t* rp_buf = (uint8_t*)response_packet.data();

                    //fill in ethernet header
                    ethernet_hdr* rep_ehdr = (ethernet_hdr*)rp_buf;
                    memcpy(rep_ehdr->ether_dhost, &(hdr->arp_sha), ETHER_ADDR_LEN);
                    memcpy(rep_ehdr->ether_shost, arp_iface->addr.data(), ETHER_ADDR_LEN);
                    rep_ehdr->ether_type = htons(ethertype_arp);

                    //fill in arp header
                    arp_hdr* rep_ahdr = (arp_hdr*)(rp_buf + sizeof(ethernet_hdr));
                    rep_ahdr->arp_hrd = htons(arp_hrd_ethernet);
                    rep_ahdr->arp_pro = htons(ethertype_ip);
                    rep_ahdr->arp_hln = 0x06;
                    rep_ahdr->arp_pln = 0x04;
                    rep_ahdr->arp_op = htons(arp_op_reply);
                    memcpy(rep_ahdr->arp_sha, arp_iface->addr.data(), ETHER_ADDR_LEN);
                    rep_ahdr->arp_sip = arp_iface->ip;
                    memcpy(rep_ahdr->arp_tha, &(hdr->arp_sha), ETHER_ADDR_LEN);
                    rep_ahdr->arp_tip = hdr->arp_sip;

                    //full send bAYYbEEEE
                    sendPacket(response_packet, arp_iface->name);
                }
                else if (hdr->arp_op == htons(arp_op_reply)) //if receive reply
                {
                    Buffer reply_madr(sizeof(hdr->arp_sha));
                    uint8_t* rp_data = (uint8_t*)reply_madr.data();
                    memcpy(rp_data, hdr->arp_sha, ETHER_ADDR_LEN);

                    std::shared_ptr<ArpRequest> arp_insert = m_arp.insertArpEntry(reply_madr, hdr->arp_sip);
                    if (arp_insert != nullptr) //proceed with handling
                    {
                        std::list<PendingPacket> packets = arp_insert->packets;
                        for (auto it = packets.begin(); it != packets.end(); it++) {
                            uint8_t* pending_buff = it->packet.data();
                            ethernet_hdr* pending_ehdr = (ethernet_hdr*)pending_buff;
                            memcpy(pending_ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
                            memcpy(pending_ehdr->ether_dhost, hdr->arp_sha, ETHER_ADDR_LEN);

                            sendPacket(it->packet, it->iface);
                        }
                        m_arp.removeRequest(arp_insert);
                    }
                }
            }
        }
        else if (ethtype == ethertype_ip) //ip
        {
            minlength += sizeof(ip_hdr);
            if (len < minlength)
            {
                fprintf(stderr, "IP header, insufficient length\n");
                return;
            }
            else
            {
                ip_hdr* hdr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
                uint16_t isum = hdr->ip_sum; // expected chksum
                hdr->ip_sum = 0;
                uint16_t csum = cksum(hdr, sizeof(ip_hdr)); // new calculated chksum
                if (isum != csum) // chksums not equal
                {
                    fprintf(stderr, "IP header, checksum length error");
                    return;
                }

                const Interface* ip_iface = findIfaceByIp(hdr->ip_dst); // was (hdr->ip_src); shouldnt we be checking destination
                if (ip_iface != nullptr) //destined for router, check if ICMP
                {
                    if (hdr->ip_p == ip_protocol_icmp) //if it carries ICMP, properly dispatch it 
                    {
                        icmp_hdr* icmp_msg = (icmp_hdr*)(hdr + sizeof(ip_hdr)); // icmp is payload of ip
                        // get type of icmp message
                        uint8_t type = ntohs(icmp_msg->icmp_type);

                        //check if echo, otherwise send unreachable
                        if (type == 8) { // echo
                            // send echo reply
                            Buffer icmp_reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
                            uint8_t* icmp_reply_buf = (uint8_t*)icmp_reply.data();

                            // construct ethernet frame
                            ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                            memcpy(icmp_ether_hdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
                            memcpy(icmp_ether_hdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
                            icmp_ether_hdr->ether_type = ehdr->ether_type;

                            // construct IP header
                            ip_hdr* icmp_ip_hdr = (ip_hdr*)(icmp_reply_buf + sizeof(ethernet_hdr));
                            icmp_ip_hdr->ip_src = ip_iface->ip;
                            icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                            icmp_ip_hdr->ip_p = ip_protocol_icmp;
                            icmp_ip_hdr->ip_len = 36; // 20 from ip hdr, 8 from icmp
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

                            Buffer icmp_reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
                            uint8_t* icmp_reply_buf = (uint8_t*)icmp_reply.data();

                            // construct ethernet frame
                            ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                            memcpy(icmp_ether_hdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
                            memcpy(icmp_ether_hdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
                            icmp_ether_hdr->ether_type = ehdr->ether_type;

                            // construct IP header
                            ip_hdr* icmp_ip_hdr = (ip_hdr*)(icmp_reply_buf + sizeof(ethernet_hdr));
                            icmp_ip_hdr->ip_src = ip_iface->ip;
                            icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                            icmp_ip_hdr->ip_p = ip_protocol_icmp;
                            icmp_ip_hdr->ip_ttl = 64; // maybe ??? 
                            icmp_ip_hdr->ip_len = 56; // 2o from ip hdr, 8 from icmp, 28 from icmp data

                            icmp_ip_hdr->ip_sum = 0;
                            icmp_ip_hdr->ip_sum = cksum((uint8_t*)icmp_ip_hdr, sizeof(ip_hdr));


                            // construct ICMP 
                            icmp_t3_hdr* icmp_head = (icmp_t3_hdr*)(icmp_ip_hdr + sizeof(icmp_t3_hdr));
                            icmp_head->icmp_type = 3;
                            icmp_head->icmp_code = 3;
                            icmp_head->unused = 0;
                            icmp_head->next_mtu = 0;
                            memcpy(icmp_head->data, hdr, ICMP_DATA_SIZE); // data is ip hdr + first 8 bytes of payload
                            icmp_head->icmp_sum = 0;
                            icmp_head->icmp_sum = cksum((uint8_t*)icmp_head, sizeof(icmp_t3_hdr));


                            // send ICMP packet

                            sendPacket(icmp_reply, iface->name);

                        }


                    }
                    else //if not return, drop packet, send ICMP Port Unreachable
                    {
                        Buffer icmp_reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
                        uint8_t* icmp_reply_buf = (uint8_t*)icmp_reply.data();

                        // construct ethernet frame
                        ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                        memcpy(icmp_ether_hdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
                        memcpy(icmp_ether_hdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
                        icmp_ether_hdr->ether_type = ehdr->ether_type;

                        // construct IP header
                        ip_hdr* icmp_ip_hdr = (ip_hdr*)(icmp_reply_buf + sizeof(ethernet_hdr));
                        icmp_ip_hdr->ip_src = ip_iface->ip;
                        icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                        icmp_ip_hdr->ip_p = ip_protocol_icmp;
                        icmp_ip_hdr->ip_ttl = 64; // maybe ??? 
                        icmp_ip_hdr->ip_len = 56; // 2o from ip hdr, 8 from icmp, 28 from icmp data

                        icmp_ip_hdr->ip_sum = 0;
                        icmp_ip_hdr->ip_sum = cksum((uint8_t*)icmp_ip_hdr, sizeof(ip_hdr));


                        // construct ICMP 
                        icmp_t3_hdr* icmp_head = (icmp_t3_hdr*)(icmp_ip_hdr + sizeof(icmp_t3_hdr));
                        icmp_head->icmp_type = 3;
                        icmp_head->icmp_code = 3;
                        icmp_head->unused = 0;
                        icmp_head->next_mtu = 0;
                        memcpy(icmp_head->data, hdr, ICMP_DATA_SIZE); // data is ip hdr + first 8 bytes of payload
                        icmp_head->icmp_sum = 0;
                        icmp_head->icmp_sum = cksum((uint8_t*)icmp_head, sizeof(icmp_t3_hdr));


                        // send ICMP unreachable

                        sendPacket(icmp_reply, iface->name);
                    }
                }
                else //not destined for router, forward
                {
                    hdr->ip_ttl -= 1;
                    if (hdr->ip_ttl <= 0) //ttl exceeded, send ICMP Time Exceeded 
                    {
                        Buffer icmp_time_exceed(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
                        uint8_t* icmp_reply_buf = (uint8_t*)icmp_time_exceed.data();

                        // construct ethernet frame 
                        ethernet_hdr* icmp_ether_hdr = (ethernet_hdr*)icmp_reply_buf;
                        memcpy(icmp_ether_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
                        memcpy(icmp_ether_hdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
                        icmp_ether_hdr->ether_type = ehdr->ether_type;

                        // construct IP header
                        ip_hdr* icmp_ip_hdr = (ip_hdr*)(icmp_reply_buf + sizeof(ethernet_hdr));
                        icmp_ip_hdr->ip_src = ip_iface->ip;
                        icmp_ip_hdr->ip_dst = hdr->ip_src; // return to sender
                        icmp_ip_hdr->ip_p = ip_protocol_icmp;
                        icmp_ip_hdr->ip_ttl = 64; // maybe ???
                        icmp_ip_hdr->ip_len = 56; // 2o from ip hdr, 8 from icmp, 28 from icmp data
                        icmp_ip_hdr->ip_sum = 0;
                        icmp_ip_hdr->ip_sum = cksum((uint8_t*)icmp_ip_hdr, sizeof(ip_hdr));

                        // construct ICMP 
                        icmp_t3_hdr* icmp_head = (icmp_t3_hdr*)(icmp_ip_hdr + sizeof(ip_hdr));
                        icmp_head->icmp_type = 11;
                        icmp_head->icmp_code = 0;

                        icmp_head->unused = 0;
                        icmp_head->next_mtu = 0;
                        memcpy(icmp_head->data, hdr, ICMP_DATA_SIZE); // data is ip hdr + first 8 bytes of payload
                        icmp_head->icmp_sum = 0;
                        icmp_head->icmp_sum = cksum((uint8_t*)icmp_head, sizeof(icmp_t3_hdr));

                        // send ICMP packet

                        sendPacket(icmp_time_exceed, iface->name);
                        return;
                    }

                    //recompute checksum for datagram
                    hdr->ip_sum = 0;
                    hdr->ip_sum = cksum(hdr, sizeof(ip_hdr));

                    RoutingTableEntry rt_entry = m_routingTable.lookup(hdr->ip_dst);
                    const Interface* next_iface = findIfaceByName(rt_entry.ifName);
                    //lookup arp cache
                    std::shared_ptr<ArpEntry> next_arp = m_arp.lookup(rt_entry.gw);
                    if (next_arp) //forward packet
                    {
                        ethernet_hdr* hdr = (ethernet_hdr*)(packet.data());
                        memcpy(hdr->ether_dhost, next_arp->mac.data(), ETHER_ADDR_LEN);
                        memcpy(hdr->ether_shost, next_iface->addr.data(), ETHER_ADDR_LEN);
                        hdr->ether_type = htons(ethertype_ip);
                        sendPacket(packet, next_iface->name);
                    }
                    else //cache packet adn send arp request
                    {
                        std::shared_ptr<ArpRequest> queue = m_arp.queueRequest(hdr->ip_dst, packet, next_iface->name);
                        //send arp req
                        Buffer request_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
                        uint8_t* rq_buf = request_packet.data();

                        //fill in ethernet header
                        ethernet_hdr* req_ehdr = (ethernet_hdr*)rq_buf;
                        memcpy(req_ehdr->ether_shost, next_iface->addr.data(), ETHER_ADDR_LEN);
                        memcpy(req_ehdr->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
                        req_ehdr->ether_type = htons(ethertype_arp);

                        //fill in arp headaer
                        arp_hdr* req_ahdr = (arp_hdr*)(rq_buf + sizeof(ethernet_hdr));
                        req_ahdr->arp_hrd = htons(arp_hrd_ethernet);
                        req_ahdr->arp_pro = htons(ethertype_ip);
                        req_ahdr->arp_hln = 0x06;
                        req_ahdr->arp_pln = 0x04;
                        req_ahdr->arp_op = htons(arp_op_request);
                        memcpy(req_ahdr->arp_sha, next_iface->addr.data(), ETHER_ADDR_LEN);
                        req_ahdr->arp_sip = next_iface->ip;
                        memcpy(req_ahdr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
                        req_ahdr->arp_tip = hdr->ip_dst;

                        sendPacket(request_packet, next_iface->name);
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
