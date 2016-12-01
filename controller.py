# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types




import logging
import struct
import array
import socket

from ryu import utils
from ryu.controller import handler
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import *
from ryu.lib import mac
from ryu.ofproto import ether


class MplsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MplsController, self).__init__(*args, **kwargs)
        # self.mac_to_port = {}

   # Packets decoder
    def packet_print(self, pkt):
        # Mac information
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if pkt_ethernet:
            dst_mac = pkt_ethernet.dst
            src_mac = pkt_ethernet.src
            mac_type = pkt_ethernet.ethertype

            self.logger.info("########ethernet information########")
            self.logger.info("dst_mac:%s src_mac:%s mac_type:%s" % (dst_mac, src_mac, hex(mac_type)))


        # IPv4 information
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            ip_version = pkt_ipv4.version
            ip_header_length = pkt_ipv4.header_length
            ip_tos = pkt_ipv4.tos
            ip_total_length = pkt_ipv4.total_length
            ip_identification = pkt_ipv4.identification
            ip_flags = pkt_ipv4.flags
            ip_offset = pkt_ipv4.offset
            ip_ttl = pkt_ipv4.ttl
            ip_proto = pkt_ipv4.proto
            ip_csum = pkt_ipv4.csum
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            ip_length = pkt_ipv4.total_length
            ip_option = pkt_ipv4.option
            self.logger.info("########IPv4 information########")
            self.logger.info("ip_version:%s ip_header_length:%s tos:%s ip_total_length:%s",ip_version,ip_header_length,ip_tos,ip_total_length)
            self.logger.info("ip_identification:%s ip_flags:%s ip_offset:%s ip_ttl:%s",ip_identification,ip_flags,ip_offset,ip_ttl)
            self.logger.info("ip_proto:%s ip_csum:%s ip_src:%s ip_dst:%s ip_length:%s",ip_proto,ip_csum,ip_src,ip_dst,ip_length)
            self.logger.info("ip_option:%s\n",ip_option)

        # Arp information
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            arp_hwtype = pkt_arp.hwtype
            arp_proto = pkt_arp.proto
            arp_hlen = pkt_arp.hlen
            arp_plen = pkt_arp.plen
            arp_opcode = pkt_arp.opcode
            arp_src_mac = pkt_arp.src_mac
            arp_dst_mac = pkt_arp.dst_mac
            arp_src_ip = pkt_arp.src_ip
            arp_dst_ip = pkt_arp.dst_ip
            self.logger.info("########Arp information########")
            self.logger.info("arp_hwtype:%s arp_proto:%s arp_hlen:%s arp_plen:%s",arp_hwtype,arp_proto,arp_hlen,arp_plen)
            self.logger.info("arp_opcode:%s arp_src_mac:%s arp_dst_mac:%s",arp_opcode,arp_src_mac,arp_dst_mac)
            self.logger.info("arp_dst_ip:%s arp_src_ip:%s\n",arp_dst_ip,arp_src_ip)

        # Tcp information
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            tcp_src_port = pkt_tcp.src_port
            tcp_dst_port = pkt_tcp.dst_port
            tcp_seq = pkt_tcp.seq
            tcp_ack = pkt_tcp.ack
            tcp_offset = pkt_tcp.offset
            tcp_bits = pkt_tcp.bits
            tcp_window_size = pkt_tcp.window_size
            tcp_csum = pkt_tcp.csum
            tcp_urgent = pkt_tcp.urgent
            tcp_option = pkt_tcp.option
            self.logger.info("########Tcp information########")
            self.logger.info("tcp_src_port:%s tcp_dst_port:%s tcp_seq:%s tcp_ack:%s",tcp_src_port,tcp_dst_port,tcp_seq,tcp_ack)
            self.logger.info("tcp_offset:%s tcp_bits:%s tcp_window_size:%s tcp_csum:%s",tcp_offset,tcp_bits,tcp_window_size,tcp_csum)
            self.logger.info("tcp_urgent:%s tcp_option:%s\n",tcp_urgent,tcp_option)

        # Udp information
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp:
            udp_src_port = pkt_udp.src_port
            udp_dst_port = pkt_udp.dst_port
            udp_total_length = pkt_udp.total_length
            udp_csum = pkt_udp.csum
            self.logger.info("########Udp information########")
            self.logger.info("udp_src_port:%s udp_dst_port:%s udp_total_length:%s",udp_src_port,udp_dst_port,udp_total_length)
            self.logger.info("udp_csum:%s\n",udp_csum)

        # icmp information
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            icmp_type = pkt_icmp.type
            icmp_code = pkt_icmp.code
            icmp_csum = pkt_icmp.csum
            icmp_data = pkt_icmp.data
            self.logger.info("########Icmp information########")
            self.logger.info("icmp_type:%s icmp_code:%s icmp_csum:%s icmp_data:%s\n",icmp_type,icmp_code,icmp_csum,icmp_data)



    # Push mpls flow
    def push_mpls_flow(self, datapath, priority, match, mpls_label, mpls_tc, mpls_ttl, out_port):

        actions = []

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth_MPLS = ether.ETH_TYPE_MPLS
        f_label = datapath.ofproto_parser.OFPMatchField.make(datapath.ofproto.OXM_OF_MPLS_LABEL, mpls_label)
        f_tc = datapath.ofproto_parser.OFPMatchField.make(datapath.ofproto.OXM_OF_MPLS_TC, mpls_tc)

        actions = [datapath.ofproto_parser.OFPActionPushMpls(eth_MPLS),
                   datapath.ofproto_parser.OFPActionSetField(f_label),
                   datapath.ofproto_parser.OFPActionSetField(f_tc),
                   datapath.ofproto_parser.OFPActionSetMplsTtl(mpls_ttl),
                   datapath.ofproto_parser.OFPActionOutput(out_port, 0)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(table_id=0,datapath=datapath, priority=priority,out_port=0,out_group=0,match=match, flags=1, instructions=inst)

        datapath.send_msg(mod)

    # Pop mpls flow
    def pop_mpls_flow(self, datapath, priority, match, out_port):

        actions = []

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth_IP = ether.ETH_TYPE_IP
        actions = [datapath.ofproto_parser.OFPActionPopMpls(eth_IP),
                   datapath.ofproto_parser.OFPActionOutput(out_port, 0)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(table_id=0,datapath=datapath, priority=priority,out_port=0,out_group=0,match=match, flags=1, instructions=inst)

        datapath.send_msg(mod)
    """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    """

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        self.packet_print(pkt)

        dpid = datapath.id
        # self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        return

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
