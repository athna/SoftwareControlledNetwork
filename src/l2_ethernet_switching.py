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
from ryu.lib.packet import vlan
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY

import random
import time

"""
TBD:
    Instead of printing, use a logging file 
    
"""

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.virtual_switches   = [1,3,4,6]
        self.physical_switches  = [2,5]
        self.switch_host_ports  = [1,2]
        self.switch_last_port   = {}
        self._initialize_load_balancing()
    
    def _initialize_load_balancing(self):
        """ Setting the initial outbound port of all the switches to port-3"""
        for s in self.virtual_switches:
            self.switch_last_port[s] = 3

    def balance(self, dpid):
        """ Balancing the load on port-3 and 4 of virtual switches """
        out_port = 3
        if self.switch_last_port[dpid] == 3:
            self.switch_last_port[dpid] = 4
            out_port = 4
        elif self.switch_last_port[dpid] == 4:
            self.switch_last_port[dpid] = 3
            out_port = 3
        return out_port

    def selective_flooding(self, in_port):
        """ Prevents flooding on all output ports, to avoid ARP query loop """
        out_port = []
        if in_port==1:
            out_port = [2,3]
        elif in_port==2:
            out_port = [1,3]
        else:
            out_port = self.switch_host_ports    # [1,2]
        
        return out_port
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # To remove previous flow rules from datapath
        print("Removing the existing rules in DP-switches: {}".format(datapath.id))
        [self.remove_legacy_flows(datapath, n) for n in range(0, 10)]
        
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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
        out_port = None
        flood = False
        actions = []

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            # ignore lldp & IPv6 packets
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        self.logger.info("Packet received from dpid='%s' src='%s' dst='%s' in_port='%s'", dpid, src, dst, in_port)
        
        # Record destination's MAC against switch port, to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        # Check if the switch has learnt the port at which the destination is reachable.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print("No flooding case for dst:{} dpid:{}, out_port:{}".format(dst, dpid, out_port))
            
            #Load balancing logic
            if dpid in self.virtual_switches and (out_port in [3,4]):
                print("load-balancing phase for switch: ", dpid)
                out_port = self.balance(dpid)
            print("Output port:", out_port)

        else:
            print("Switch '{}' must flood for the destination:{} ".format(dpid, dst))
            flood = True
            if dpid in self.physical_switches:          #2,5
                out_port = ofproto.OFPP_FLOOD
            else:
                out_port = self.selective_flooding(in_port)

        if type(out_port)==type(list()):
            for p in out_port:
                actions.append(parser.OFPActionOutput(p))
        else:
            actions = [parser.OFPActionOutput(out_port)]
            
        #"""        
        if not flood:
            # Adding source-to-destination rule
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
            
            # Adding destination-to-sender rule
            match2      = parser.OFPMatch(in_port=out_port, eth_src=dst, eth_dst=src)
            actions2    = [parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, match2, actions2)
        #"""
            
        # One time instruction from RYU controller to forward packet ... Its not a permanent rule in switch.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

        
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

    def remove_legacy_flows(self, datapath, table_id):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        datapath.send_msg(flow_mod)
    

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod
