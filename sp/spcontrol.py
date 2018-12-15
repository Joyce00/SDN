# Copyright (C) 2018 Joyce_BY at SYSU
# Yagnes126@gmail.com

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, 
# software distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

#########env##########
# encode -- UTF-8 -- #
# Ubuntu 18.04.1 LTS #
# mininet 2.2.2      #
# ryu 4.30           #
# ovs 2.9.0          #
# python 2.7.15rc1   #
######################

import logging
import struct
import copy
import networkx as nx
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet,ethernet,ipv4,arp
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
# import needed module
import topofinder

class ShortestPath(app_manager.RyuApp):
    """
        spxcontrol is a Ryu app for forwarding packets in shortest path.
        The shortest path computation is done by module TopoFinder
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # given OFP version this app supports
    _CONTEXTS = {"topofinder": topofinder.TopoFinder} # register apps

    def __init__(self, *args, **kwargs):
        super(ShortestPath, self).__init__(*args, **kwargs)
        self.topofinder = kwargs["topofinder"]
        self.datapaths = {} # {dpdi:datapath}

#################################state change#########################################
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            When state changes, collect datapath information
        """
        datapath = ev.datapath
        # if handshake is done, and this dp is not registered, we add it to datapaths
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        # if connection interrupts, we delete this datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

######################################################################################

################################packet in handler#####################################

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            The first packet from an unknown packet must be an ARP, 
            so learn access_table by ARP.
        '''
        msg = ev.msg # get message
        pkt = packet.Packet(msg.data) # decode packet
        arp_pkt = pkt.get_protocol(arp.arp) # get apr header
        ip_pkt = pkt.get_protocol(ipv4.ipv4) # get ipv4 header
        
        # if we have an ARP, then use apr forwarding
        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)
        # if we have an ipv4 packet, then use shortest path forwarding
        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)

#-------------------------------------APR--------------------------------------------#
    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flood it.
        """
        datapath = msg.datapath # get datapath
        ofproto = datapath.ofproto # get openflow protocol
        parser = datapath.ofproto_parser # get ofp parser

        # get host destination mac by using the method in module topofinder
        result = self.topofinder.get_host_location(dst_ip)
        if result:  # if destination host is recorded in access table
            datapath_dst, out_port = result[0], result[1] # get (dpip,port) that connects the dst host
            datapath = self.datapaths[datapath_dst] # get dst datapath
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                    ofproto.OFPP_CONTROLLER,out_port, msg.data) # build out packet
            datapath.send_msg(out) # send out the packet
            self.logger.debug("Reply ARP to knew host")
        else: # if dst host unknown, then flood the packet
            self.flood(msg)

    def flood(self, msg):
        """
            Flood ARP packet to the access port which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.topofinder.access_ports:
            for port in self.topofinder.access_ports[dpid]:
                if (dpid, port) not in self.topofinder.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding msg")

#---------------------------------------ipv4------------------------------------------#
    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            calculate shortest forwarding path and install them into datapaths.
        """
        datapath = msg.datapath # get datapath
        in_port = msg.match['in_port'] # get in port

        # get first switch and last switch dpid in the interval switch net
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result: # if both src and dst switches exist
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # get shortest path
                path = self.get_path(src_sw, dst_sw)
                self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                # install flow entries to all datapaths along the path.
                self.install_flow(  self.datapaths,self.topofinder.link_to_port,
                                    self.topofinder.access_table, path,flow_info, 
                                    msg.buffer_id, msg.data)
        return

    def get_sw(self, dpid, in_port, src, dst):
        """
            return the source and destination switch dpids.
        """
        src_sw = dpid
        dst_sw = None

        src_location = self.topofinder.get_host_location(src) # get (dpid_src,port_src)
        if in_port in self.topofinder.access_ports[dpid]: # make sure this dp connects to a host at this port
            if (dpid, in_port) == src_location: # make sure this src is the src we expect
                src_sw = src_location[0] # return src dpid
            else:
                return None

        dst_location = self.topofinder.get_host_location(dst) # get (dpid_dst,port_dst)
        if dst_location: # if we have an response, that means dst is in topology
            dst_sw = dst_location[0] # return dst dpid

        return src_sw, dst_sw

    def get_path(self, src, dst):
        """
            Get shortest path from topofinder module.
        """
        shortest_paths = self.topofinder.shortest_paths
        return shortest_paths.get(src).get(dst)[0]

#------------------------------------install flow-------------------------------------#
    def install_flow(self, datapaths, link_to_port, access_table, path,flow_info, buffer_id, data=None):
        ''' 
            Install flow entires along the path for roundtrip
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if path is None or len(path) == 0: # no path
            self.logger.info("Path error!")
            return
        in_port = flow_info[3] # get in port
        first_dp = datapaths[path[0]] # get first dp
        out_port = first_dp.ofproto.OFPP_LOCAL # The local OpenFlow virtual port used for in-band control traffic
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # send flow entries to inner dps:
        if len(path) > 2:
            for i in range(1, len(path)-1): # extract a middle A->B->C model
                # get A(port)->B(port)
                port = self.get_port_pair_from_link(link_to_port,path[i-1], path[i])
                # get B(port)->C(port)
                port_next = self.get_port_pair_from_link(link_to_port,path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0] # B(port in), B(port out)
                    datapath = datapaths[path[i]] # get dp B
                    # establish roundtrip flow entry
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    self.logger.debug("inter_link flow install")
        if len(path) > 1: # add flow entry to last node
            # get ports in N-1(port)->N(port)
            port_pair = self.get_port_pair_from_link(link_to_port,path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1] # for last node, get in port
            dst_port = self.get_port(flow_info[2], access_table) # get N(port)->dst host
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return
            last_dp = datapaths[path[-1]] # get dp N
            # add roundtrip flow entry to dp N
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # add flow entries to first node:
            # get port pairs in linke dp1(port)->dp2(port)
            port_pair = self.get_port_pair_from_link(link_to_port,path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0] # get sw1(port)
            # add roundtrip flow entries to the first dp 
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)

            # send packet out to first dp, tell immediate actions of this packet
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        # src and dst on the same datapath: src-DP-dst
        else:
            # get out port directly from access table
            out_port = self.get_port(flow_info[2], access_table)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            # add roundtrip flow entries
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            # send out packet tell the immediate actions of the packet
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(dst_port)]
        match = parser.OFPMatch(in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
        self.add_flow(datapath, 1, match, actions,idle_timeout=15, hard_timeout=60)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,match=match, instructions=inst)
        dp.send_msg(mod)

#---------------------------------send out packet-------------------------------------#
    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        if dst_port:
            actions = [datapath.ofproto_parser.OFPActionOutput(dst_port)]

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                            data=msg_data, in_port=src_port, actions=actions)
        return out

#--------------------------------get port information---------------------------------#
    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of a link
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (src_dpid, dst_dpid))
            return None

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None
