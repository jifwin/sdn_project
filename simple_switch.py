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

"""
An OpenFlow 1.3 L2 learning switch implementation.
"""

import os
import math
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
from ryu.lib import hub
from operator import attrgetter
import networkx as nx


# todo: move to speerate file
class NetworkStats(object):
    def __init__(self):
        self.current_load = {}
        self.prev_load = {}


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.port_to_dst = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.network_stats = NetworkStats()
        self.net = nx.DiGraph()
        self.sleep_time = 2

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, idle_timeout=10, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        
        # avoid broadcast from LLDP
        if eth_pkt.ethertype == 35020 or eth_pkt.ethertype == 34525:
            return
        
        dst = eth_pkt.dst
        src = eth_pkt.src

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # add new node if doesn't exist
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, {'port': in_port})
            self.net.add_edge(src, dpid)

        # compute shortest path
        if dst in self.net:
            path = nx.shortest_path(self.net, src, dst, 'weight')
            #print "New path on s{} from {} to {}: {}".format(dpid, src, dst, path)
            #print "Cost: {}".format(nx.shortest_path_length(self.net, src, dst, 'weight'))
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            if ipv4_pkt != None:
                if tcp_pkt != None:
                    match = parser.OFPMatch(ipv4_src=ipv4_pkt.src,
                                            ipv4_dst=ipv4_pkt.dst,
                                            ip_proto=ipv4_pkt.proto,
                                            eth_type=eth_pkt.ethertype,
                                            tcp_src=tcp_pkt.src_port,
                                            tcp_dst=tcp_pkt.dst_port)
                elif udp_pkt != None:
                    match = parser.OFPMatch(ipv4_src=ipv4_pkt.src,
                                            ipv4_dst=ipv4_pkt.dst,
                                            ip_proto=ipv4_pkt.proto,
                                            eth_type=eth_pkt.ethertype,
                                            udp_src=udp_pkt.src_port,
                                            udp_dst=udp_pkt.dst_port)
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=eth_pkt.ethertype, ip_proto=ipv4_pkt.proto)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=eth_pkt.ethertype)

            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switches = get_switch(self, None)
        switches = [switch.dp.id for switch in switches]
        links = get_link(self, None)

        for link in links:
            self.port_to_dst[(link.src.dpid, link.src.port_no)] = link.dst.dpid

        links = [(link.src.dpid, link.dst.dpid, {'weight': 1, 'port': link.src.port_no}) for link in links]

        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)

        print "**********List of links**********"
        print self.net.edges(data=True)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
        print self.datapaths

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        switch_no = []
        rx_tx_load = []

        '''self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')'''
        switch_no.append(ev.msg.datapath.id)
        for stat in sorted(body, key=attrgetter('port_no')):
             '''self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)'''
             if stat.port_no!= 0xfffffffe:
                rx_tx_load.append(stat.rx_bytes + stat.tx_bytes)


        for i in range(len(switch_no)):
            self.network_stats.current_load[switch_no[i]] = rx_tx_load

    def calculate_load(self):
        os.system("clear")
        load = []
        load_dict = {}
        print "Current rx+tx bytes:"
        print self.network_stats.current_load
        print "Previously measured rx+tx bytes:"
        print self.network_stats.prev_load
        if self.network_stats.prev_load != {}:
            for i in self.network_stats.current_load.keys():  # po switchach
                for j in range(0, len(self.network_stats.current_load[i])):  # po liczbie portow dla kazdego switcha
                    load_avg = math.fabs((self.network_stats.prev_load[i][j] - self.network_stats.current_load[i][j])) / self.sleep_time / (1024*1024)
                    load.append(load_avg)

                    if (i, j+1) in self.port_to_dst:
                        src = i
                        dst = self.port_to_dst[(i, j+1)]

                        if load_avg > 80:
                            self.net[src][dst]['weight'] = 100
                        else:
                            self.net[src][dst]['weight'] = 1

                load_dict[i] = load
                load = []

        self.network_stats.prev_load = self.network_stats.current_load
        self.network_stats.current_load = {}
        print "Calculated load:"
        print load_dict
        print self.net.edges(data=True)
        return load_dict



    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep_time)
            self.calculate_load()


    # https://sdn-lab.com/2014/12/25/shortest-path-forwarding-with-openflow-on-ryu/
    # todo: get stats of links -> costs
    # map link -> cost
    # do self.net ustawic koszty laczy
    # napisac generator ktory to przetestuje, sprawdzic czy przeplywy sie kasuja po jakims czasie
