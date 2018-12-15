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

class TopoFinder(app_manager.RyuApp):
    """
        TopoFinder is a Ryu app for discover topology information.
        This App can provide many data services for other App, such as
        link_to_port, access_table, switch_port_table,access_ports,
        interior_ports,topology graph and shorteest paths.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ################################init#####################################
    def __init__(self, *args, **kwargs):
        super(TopoFinder, self).__init__(*args, **kwargs)
        self.topology_api_app = self # enable using of api.py module in topology directory built in ryu
        self.link_to_port = {}       # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.access_table = {}       # {(sw,port) :[host_ip]}
        self.switch_port_table = {}  # dpip->port_num, switch and its ports
        self.access_ports = {}       # dpid->port_num, switch and its ports that connect a host
        self.interior_ports = {}     # dpid->port_num, switch and its ports that connect another switch

        self.graph = nx.DiGraph()     # a graph to store the whole network topology
        self.pre_graph = nx.DiGraph()
        self.pre_access_table = {}
        self.pre_link_to_port = {}
        self.shortest_paths = None    # store shortest paths of every pair of nodes

        self.discover_thread = hub.spawn(self._discover) # Start a green thread to discover network resource.

    def _discover(self):
        i = 0
        while True:
            self.show_topology()
            if i == 5:
                self.get_topology(None)
                i = 0
            hub.sleep(10)
            i = i + 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            Initial operation, send miss-table flow entry to datapaths.
        """
        msg = ev.msg
        datapath = ev.msg.datapath # get datapath from the event
        ofproto = datapath.ofproto # get openflow protocol
        parser = datapath.ofproto_parser # get ofp parser
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch() # set empty match so that this entry matches every packet
        # set actions that match this entry as send to controller and no buffer
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,match=match, instructions=inst)
        dp.send_msg(mod)
    
    ##########################################################################
    

    #############################topology discovery###########################
    # List the event list should be listened.
    events=[event.EventSwitchEnter,event.EventSwitchLeave,
            event.EventPortAdd,event.EventPortDelete,event.EventPortModify,
            event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(events)
    def get_topology(self, ev):
        """
            Get topology info and calculate shortest paths.
        """
        switch_list = get_switch(self.topology_api_app, None) # get a list of switches by ryu api
        self.create_port_map(switch_list) # Create switch_port_table, interior_ports, access_ports 
        self.switches = self.switch_port_table.keys() # get switch dpid list

        links = get_link(self.topology_api_app, None) # get a list of links by ryu api, only sw-sw links
        self.create_interior_links(links) # create the sw-sw links from links we get
        self.create_access_ports() # get ports that is used for sw-host

        self.get_graph(self.link_to_port.keys()) # figure out the network graph from info got above
        self.shortest_paths = self.all_shortest_paths(self.graph, weight='weight') # calculate sp between all pairs

    def create_port_map(self, switch_list):
        """
            Create switch_port_table, interior_ports, access_ports. 
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_interior_links(self, link_list):
        """
            Get links`srouce port to dst port  from link_list,
            link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        """
            Get ports without link into access_ports
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def get_graph(self, link_list):
        """
            Get Adjacency matrix from link_to_port
        """
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    self.graph.add_edge(src, dst, weight=1)
        return self.graph

    def all_shortest_paths(self, graph, weight='weight'):
        """
            Creat all K shortest paths between datapaths.
        """
        _graph = copy.deepcopy(graph)
        paths = {}

        # Find ksp in graph.
        for src in _graph.nodes():
            paths.setdefault(src, {src: [[src]]})
            for dst in _graph.nodes():
                if src == dst:
                    continue
                paths[src].setdefault(dst, [])
                paths[src][dst] = self.shortest_path(_graph, src, dst,weight=weight)
        return paths
    
    # for all_shortest_paths
    def shortest_path(self, graph, src, dst, weight='weight'):
        """
            Great K shortest paths of src to dst.
        """
        generator = nx.shortest_simple_paths(graph, source=src,target=dst, weight=weight)
        shortest_paths = []
        try:
            shortest_paths.append(list(generator)[0])
            return shortest_paths
        except:
            self.logger.debug("No path between %s and %s" % (src, dst))

    # print topology
    def show_topology(self):
        if self.pre_graph != self.graph:
            print ("---------------------Topo Link---------------------")
            print ('%10s' % ("switch"),)
            for i in self.graph.nodes():
                print ('%10d' % i,)
            print ("")
            for i in self.graph.nodes():
                print ('%10d' % i,)
                for j in self.graph[i].values():
                    print ('%10.0f' % j['weight'],)
                print( "")
            self.pre_graph = copy.deepcopy(self.graph)

        if self.pre_link_to_port != self.link_to_port:
            print ("---------------------Link Port---------------------")
            print ('%10s' % ("switch"),)
            for i in self.graph.nodes():
                print ('%10d' % i,)
            print ()
            for i in self.graph.nodes():
                print ('%10d' % i,)
                for j in self.graph.nodes():
                    if (i, j) in self.link_to_port.keys():
                        print ('%10s' % str(self.link_to_port[(i, j)]),)
                    else:
                        print ('%10s' % "No-link",)
                print ("")
            self.pre_link_to_port = copy.deepcopy(self.link_to_port)

        if self.pre_access_table != self.access_table:
            print ("----------------Access Host-------------------")
            print ('%10s' % ("switch"), '%12s' % "Host")
            if not self.access_table.keys():
                print ("    NO found host")
            else:
                for tup in self.access_table:
                    print ('%10d:    ' % tup[0], self.access_table[tup])
            self.pre_access_table = copy.deepcopy(self.access_table)

    ##########################################################################

    #############################packet in handling###########################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
            Hanle the packet in packet, and register the access info.
        """
        msg = ev.msg
        datapath = msg.datapath # get datapath
        in_port = msg.match['in_port'] # get inport
        
        pkt = packet.Packet(msg.data) # decode packet of OFP
        arp_pkt = pkt.get_protocol(arp.arp) 

        if arp_pkt: # if this is an arp packet
            arp_src_ip = arp_pkt.src_ip # get source ip
            #arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac # get source mac
            # learn the comming ip-mac reflection
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)

    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    #########################return final (dpid,port)##########################
    def get_host_location(self, host_ip):
        """
            return a datapath and the port which connects this host_ip
            (dpid, port) 
        """
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

                
