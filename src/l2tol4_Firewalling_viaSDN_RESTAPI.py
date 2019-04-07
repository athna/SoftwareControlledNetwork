#!/usr/bin/python2.7

# Copyright 2017 Mael Kimmerlin
# Modified by Hammad Kabir, Dec 2018 - as a part of my solution
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from ryu.base import app_manager
from ryu.ofproto import ether, inet, ofproto_v1_0, ofproto_v1_3
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event, dpset
import ryu.app.ofctl.api as ofctl_api

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import json
import uuid

#The supported version are ofproto_v1_0 and ofproto_v1_3
OPENFLOW_PROTOCOL = ofproto_v1_3

# How to run:
    # run with ryu-manager <filenameWithout.py> --wsapi-port 8880

# TBD: 
# Firewall support with match criteria spread along the TCP/IP layers is yet to be tested.
# Moreover, the rules shall be enforced via OpenvSwitch not via python, I gotta check/test on this.
    
#########################################################
# SDN application                                       #
# This contains the SDN logic that runs your controller #
#########################################################
class SDNapp(app_manager.RyuApp):
    OFP_VERSIONS = [OPENFLOW_PROTOCOL.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SDNapp, self).__init__(*args, **kwargs)
        self.mac_to_port        = {}            # Dictionary storing the MAC addresses learnt
        self.datapaths          = {}            # Contains the OpenFlowSwitch object for each connected switch
        self.data               = {}            # The data object passed to the REST API
        #For example, passing a dictionnary of names and the dictionnary of switches
        #self.data["rules"]      = []
        self.data["names"]      = {}
        self.data["switches"]   = self.datapaths

        self.virtual_switches   = [1,3,4,6]
        self.physical_switches  = [2,5]
        self.switch_host_ports  = [1,2]
        wsgi                    = kwargs['wsgi']
        self._initialize_load_balancing()
        self._initialize_host_fw_rules()
        # self.data object is given to the RESTControlAPI, and within it we can store all the parameters upon parsing the REST query.
        # Beware! a copy of data is given to the app, not data itself, so any structural modifications made in the copy of data would be lost
        # So it has to be done here before registering to the app.
        wsgi.register(RESTControlAPI, self.data)

    def _initialize_load_balancing(self):
        """ Setting the initial outbound port of all the switches to port-3"""
        self.logger.info("Setting the default port to 3, for all the outbound connections")
        self.switch_last_port = {}
        for s in self.virtual_switches:
            self.switch_last_port[s] = 3

    def _initialize_host_fw_rules(self):
        # Initialize VLANs to empty values
        self.logger.info("A dictionary to register all FW rules applicable to each VM")
        self.data["rules"]  = {}
        host_ids            = ["1A", "1B", "3A", "3B", "4A", "4B", "6A", "6B"]
        for host_id in host_ids:
            self.data["rules"][host_id] = []
    
    def run_load_balancing(self, dpid):
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

    #This handles the packet in events (reactive)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id                          # dpid = hex(ev.dp.id)
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        dst = eth_pkt.dst
        src = eth_pkt.src
        
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        self.logger.info("packet in dpid=%s src=%s dst=%s in_port=%s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        flood       = False
        fw_rule     = None

        # If the destination MAC address is already learned, Find corresponding output port. Else, Flood.
        if dst in self.mac_to_port[dpid]:
            output_port = self.mac_to_port[dpid][dst]
            out_port    = [output_port]
            #print("No flooding case for dst:{} dpid:{}, out_port:{}".format(dst, dpid, output_port))
            
            #Load balancing logic
            if dpid in self.virtual_switches and (out_port in [3,4]):
                out_port = [self.run_load_balancing(dpid)]
        
        else:
            # Running the selective broadcasting on virtual switches (on hosts with VMs)
            flood = True
            if dpid in self.physical_switches:          #2,5
                out_port = [ ofproto.OFPP_FLOOD ]
            else:
                out_port = self.selective_flooding(in_port)

        # Implementing firewall rules            --- # TBD: sort rules by priority before using them.
        # There are two options to implement FW rules: (1) Do the rule matching to packet in Python code, and apply action. 
        # (2) OR insert match & actions as rule in the switches (associated to hosts). We ll use option-1 here.
        
        # Find the firewall rules based on packet's sender.        [What about destination-specific enforcement?]
        host_id = ""
        if dpid in self.virtual_switches:
            if in_port == 1:    host_id = str(dpid) + "A"
            else:               host_id = str(dpid) + "B"
            fw_rules = self.data["rules"][host_id]      # A list of FW rule objects is returned.
            #print("Firewall rules exist for the sender '{}'".format(host_id))
            
            for fw_rule in fw_rules:
                if fw_rule.do_match(pkt):
                    if fw_rule.is_allowed() is False:
                        self.logger.info("FW rule forbids packet from sender: '{}'".format(host_id))
                        return
        
        # construct action list.
        actions=[]
        for port in out_port:
            actions.append(parser.OFPActionOutput(port))
        
        # Install a flow rule to avoid packet_in() method next time.
        if not flood:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # Option: set the Firewall rule in switch as match & Action field, to prevent all future flows that meet this rule's match criteria 
            #if fw_rule is not None:    fw_rule.set_match_fields(match)
            self.add_flow(datapath, 1, match, actions)
    
        # Forward the received packet using the PacketOut method.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)


    #This handles the switch interaction at the startup, or on termination
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def switch_features_handler(self, ev):
        dpid = hex(ev.dp.id)
        datapath = ev.dp
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        #The switch connects
        if ev.enter:
            # Creates the object to handle the switch and add it to the dict
            self.datapaths[dpid] = OpenFlowSwitch(ev.dp, dpid)
            self.logger.info(str(dpid)+": Switch connected")

            #Delete existing flows to start with a clean state
            delete_flows(self.datapaths[dpid])

            # install the table-miss flow entry.
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)

        #The switch disconnects
        else:
            if dpid in self.datapaths:
                del self.datapaths[dpid]
            print(str(dpid)+": Switch disconnected")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

#####################################################################
# This class contains the Firewal rules inserted via REST interface #
#####################################################################

class FWRule(object):
    def __init__(self, json_req, name=None, description=None, priority=None, in_port=None, action=None):
        self.json_req       = json_req
        self.name           = name
        self.description    = description
        self.priority       = priority
        self.in_port        = in_port
        self.action         = action
        self.eth_src        = None
        self.eth_dst        = None
        self.eth_type       = None
        self.ipv4_src       = None
        self.ipv4_dst       = None
        self.ip_proto       = None
        self.tp_sport       = None
        self.tp_dport       = None
        self.match_criteria = {}
        self.filter_keys    = ["eth_src", "eth_dst", "ipv4_src", "ipv4_dst", "ip_proto", "tp_sport", "tp_dport"]
        self._initialize_layers_filtering()
        self.parse_fw_rule()
        
    def parse_fw_rule(self):
        self.host_id      = self.json_req["name"]
        self.priority     = self.json_req["priority"]
        self.in_port      = self.json_req["in_port"]
        self.action       = self.json_req["action"]
        self.create_match()

        if "eth_src" in self.json_req:      self.eth_src = self.json_req["eth_src"]
        if "eth_dst" in self.json_req:      self.eth_dst = self.json_req["eth_dst"]
        if "ipv4_src" in self.json_req:     self.ipv4_src = self.json_req["ipv4_src"]
        if "ipv4_dst" in self.json_req:     self.ipv4_dst = self.json_req["ipv4_dst"]
        if "ip_proto" in self.json_req:     self.ip_proto = self.json_req["ip_proto"]
        if "tp_sport" in self.json_req:     self.tp_sport = self.json_req["tp_sport"]
        if "tp_dport" in self.json_req:     self.tp_dport = self.json_req["tp_dport"]
        if "description" in self.json_req:  self.description = self.json_req["description"]

    def create_match(self):
        for f in self.filter_keys:
            if f in self.json_req:          self.match_criteria[f] = self.json_req[f]            
    
    def _initialize_layers_filtering(self):
        pass
    
    def get_rule_matching_criteria(self):
        return self.match_criteria

    def is_allowed(self):
        # Informs if the rule Allows/Drops the packet
        return self.action == "accept"
    
    def __cmp__(self, other):
        # Used to sort rules of 1 host/switch-port
        return cmp(self.priority, other.priority)

    def do_match(self, pkt):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        print("In do match")
        
        if eth_pkt is not None:
            possible_ETH_match_fields = {"eth_src": eth_pkt.src, "eth_dst": eth_pkt.dst}
            
            for key, pkt_value in possible_ETH_match_fields.items():
                if key in self.match_criteria:
                    rule_value = self.match_criteria[key]
                    if self.do_field_match(key, pkt_value, rule_value) is False:
                        return False
                    
        if ip4_pkt is not None:
            print("In IPv4 packet")
            possible_IPV4_match_fields = {"ipv4_src": ip4_pkt.src, "ipv4_dst": ip4_pkt.dst, "ip_proto": ip4_pkt.proto}
            for key, pkt_value in possible_IPV4_match_fields.items():
                print("key, pkt_value", key, pkt_value)
                print("key in self.match_criteria: ", key in self.match_criteria)
                if key in self.match_criteria:
                    rule_value = self.match_criteria[key]
                    print(pkt_value, rule_value, "Result of match", self.do_field_match(key, pkt_value, rule_value))
                    if self.do_field_match(key, pkt_value, rule_value) is False:
                        return False
            
        if tcp_pkt is not None:
            possible_TCP_match_fields = {"tp_sport": tcp_pkt.tp_sport, "tp_dport": tcp_pkt.tp_dport}
            for key, pkt_value in possible_TCP_match_fields.items():
                if key in self.match_criteria:
                    rule_value = self.match_criteria[key]
                    if self.do_field_match(key, pkt_value, rule_value) is False:
                        return False
                    
        if udp_pkt is not None:
            possible_UDP_match_fields = {"tp_sport": udp_pkt.tp_sport, "tp_dport": udp_pkt.tp_dport}
            for key, pkt_value in possible_UDP_match_fields.items():
                if key in self.match_criteria:
                    rule_value = self.match_criteria[key]
                    if self.do_field_match(key, pkt_value, rule_value) is False:
                        return False
        
        print("Successful match observed with the packet")
        return True
    
    def do_field_match(self, key, pkt_value, rule_value):
        """ Match the value in packet with value in rule """
        if pkt_value != rule_value:
            return False
        return True
    
    def set_fields(self, match):
        # Used to initialize OpenFlow match object to have the match fields
        if self.eth_src != None:
            match.set_dl_src(str(self.eth_src))
        if self.eth_dst != None:
            match.set_dl_dst(str(self.eth_dst))
        if self.eth_type != None:
            match.set_dl_type(self.eth_type)
        if self.ip_proto != None:
            match.set_ip_proto(self.ip_proto)
        if self.ipv4_src != None:
            match.set_ipv4_src(str(self.ipv4_src))
        if self.ipv4_dst != None:
            match.set_ipv4_dst(str(self.ipv4_dst))
        if self.tp_sport != None:
            if self.ipv4_dst == 6:
                match.set_tcp_src(self.tp_sport)
            elif self.ipv4_dst == 17:
                match.set_udp_src(self.tp_sport)
        if self.tp_dport != None:
            if self.ipv4_dst == 6:
                match.set_tcp_dst(self.tp_dport)
            elif self.ipv4_dst == 17:
                match.set_udp_dst(self.tp_dport)
            



###################################################
# REST application                                #
# This contains the REST logic that runs your API #
###################################################

class RESTControlAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RESTControlAPI, self).__init__(req, link, data, **config)
        self.data = data
        self.mandatory_rule_params = ["name", "priority", "in_port", "action"]
        self.traffic_match_params  = ["eth_src", "eth_dst", "ipv4_src", "ipv4_dst", "ip_proto ", "tp_sport", "tp_dport"]

    @route('Rules', '/task3/rules', methods=['GET','POST'])
    def rulesList(self, req, **kwargs):
        if req.method == "GET":
            # Get list of rules
            return json.dumps(self.data["rules"])+"\n\n"
        
        elif req.method == "POST":
            match_criteria_exists = False
            # Add a new rule
            if not req.body or not req.json:
                return Response(status=400, body="\nMissing parameters"+"\n")
            for m in self.mandatory_rule_params:
                if m not in req.json:
                    return Response(status=400, body="\nMissing parameter: '{}'".format(m)+"\n\n")

            for t in self.traffic_match_params:
                if t in req.json:
                    match_criteria_exists = True
                    break
            
            if match_criteria_exists is False:
                return Response(status=400, body="\nRequest doesn't contain any traffic match criteria, i.e. eth_src/eth_dst, ipv4_src/ipv4_dst, tp_sport/tp_dport, ip_proto"+"\n\n")
            
            host_id = req.json["name"]
            if host_id not in self.data["rules"]:
                return Response(status=400, body="\nHost-ID '{}' does not exist.".format(m)+"\n\n")
                
            rule = FWRule(req.json)
            self.data["rules"][host_id].append(rule)
            return Response(status=200, body="\nRule successfully inserted"+"\n\n")

            
    @route('Rule', '/task3/rule/{ruleid}', methods=['GET','DELETE'])
    def ruleNonList(self, req, **kwargs):
        print("REST request for /task3/rule/{ruleid} '{}'".format(kwargs["ruleid"]))
        if req.method == "GET":
            # Get a single rule
            if "ruleid" in kwargs:
                ruleid = int(kwargs["ruleid"])
                if ruleid >= 0 and ruleid < len(self.data["rules"]):
                    return json.dumps(self.data["rules"][ruleid])+"\n"
                else:
                    print("Uh-oh %d" % (len(self.data["rules"]),))
                    return Response(status=404, body="Not found")
            else:
                return Response(status=404, body="Not found")
            
        elif req.method == "DELETE":
            # Delete a single rule
            if "ruleid" in kwargs:
                ruleid = int(kwargs["ruleid"])
                if ruleid >= 0 and ruleid < len(self.data["rules"]):
                    del self.data["rules"][ruleid]
                    return "\n"
                else:
                    return Response(status=404, body="Not found")
            else:
                return Response(status=404, body="Not found")
        

################################################################
# SDN Interface                                                #
# This contains the functions you can call to act on the rules #
################################################################

def install_flows(switch, flows_list):
    _process_flows(switch, switch.ofp.OFPFC_ADD, flows_list)

def delete_flows(switch, flows_list=[]):
    _process_flows(switch, switch.ofp.OFPFC_DELETE, flows_list)

def delete_strict_flows(switch, flows_list):
    _process_flows(switch, switch.ofp.OFPFC_DELETE_STRICT, flows_list)

def modify_flows(switch, flows_list):
    _process_flows(switch, switch.ofp.OFPFC_MODIFY, flows_list)

def modify_strict_flows(switch, flows_list):
    _process_flows(switch, switch.ofp.OFPFC_MODIFY_STRICT, flows_list)



######################################################################
# Behind the scene                                                   #
# No need to modify anything here except if you want to add features #
######################################################################

# The rest of the file should not be modified, except if you know what you are doing

#This class represents a bridge and contains the method to interact with it  
class OpenFlowSwitch(object):

    def __init__(self, dp, dpid):
        self.dp = dp
        self.ofp = dp.ofproto
        self.ofpp = dp.ofproto_parser

    def dump_flows(self, table_id=None):
        if table_id is None:
            table_id = self.ofp.OFPTT_ALL
        msg = self.ofpp.OFPFlowStatsRequest(self.dp, table_id=table_id)
        if self.dp is not None:
            replies = self.dp.send_msg(msg,
                                 reply_cls=self.ofpp.OFPFlowStatsReply,
                                 reply_multi=True)
        else:
            replies = []
        flows = []
        for rep in replies:
            flows += rep.body
        return flows

    #Under the hood function, you should not use it directly
    def install_instructions(self, actions, match, command,
                             table_id=None, priority=32768):
        kwargs={"match":match, "priority":priority, "command": command}
        if table_id is None:
            table_id = self.ofp.OFPTT_ALL
        
        if OPENFLOW_PROTOCOL.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            kwargs["actions"]=actions
            if (command == self.ofp.OFPFC_DELETE_STRICT or 
                  command == self.ofp.OFPFC_DELETE):
                kwargs["out_port"]=self.ofp.OFPP_ANY
        
        else:
            kwargs["instructions"]=actions
            if (command == self.ofp.OFPFC_DELETE_STRICT or 
                  command == self.ofp.OFPFC_DELETE):
                kwargs["out_port"]=self.ofp.OFPP_ANY
                kwargs["out_group"]=self.ofp.OFPG_ANY
        
        if self.dp is not None:
            msg = self.ofpp.OFPFlowMod(self.dp, **kwargs)
            self.dp.send_msg(msg)

# Miscellaneous processing functions
            
def _match(switch, **match_kwargs):
    return switch.ofpp.OFPMatch(**match_kwargs)

def _actions(switch, actions):
    returned_instructions = []
    returned_actions = None
    if actions:
        if not isinstance(actions, list):
            raise RuntimeError("A list of actions is expected")
        
        for action_set in actions:
            if not isinstance(action_set, dict):
                raise RuntimeError("This action is not a dictionnary")
            if action_set["action"] not in switch.ofpp.__dict__:
                raise KeyError("Unknown action/instruction")
            action_set.setdefault("args",[])
            action_set.setdefault("kwargs",{})
            
            if action_set["action"].startswith("OFPAction"):
                if returned_actions is None:
                    returned_actions = []
                
                action_type = action_set["action"]
                action_args = action_set["args"]
                action_kwargs = action_set["kwargs"]
                action = switch.ofpp.__dict__[action_type](*action_args, **action_kwargs)
                returned_actions.append(action)
            
            elif action_set["action"].startswith("OFPInstruction"):
                if returned_actions is not None:
                    returned_instructions.append(switch.ofpp.OFPInstructionActions(
                        switch.ofp.OFPIT_APPLY_ACTIONS,list(returned_actions)))
                    returned_actions = None
                
                instruction_type = action_set["action"]
                instruction_args = action_set["args"]
                instruction_kwargs = action_set["kwargs"]
                instruction = switch.ofpp.__dict__[instruction_type](*instruction_args, **instruction_kwargs)
                returned_instructions.append(instruction)
            
            else:
                raise RuntimeError("Unexpected action")
                
    if OPENFLOW_PROTOCOL.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
        if returned_actions is None:
            returned_actions = []
        return returned_actions
    else:
        if returned_actions is not None:
            returned_instructions.append(switch.ofpp.OFPInstructionActions(
                    switch.ofp.OFPIT_APPLY_ACTIONS,list(returned_actions)))
        return returned_instructions


def _process_flows(switch, command, flows_list):
    if switch is None or flows_list is None :
        raise RuntimeError("Install_flow input error")
    if not isinstance(flows_list, list):
        raise RuntimeError("A list of flows is expected")
    
    for flow in flows_list:
        _process_flow(switch, command, flow)
    
    #Special case for delete : no flow = delete all
    if not flows_list and command == switch.ofp.OFPFC_DELETE:
        _process_flow(switch, command, {})

        
def _process_flow(switch, command, flow):
    if not isinstance(flow, dict):
        raise RuntimeError("The flows are expected as dictionnaries")
    
    kwargs = {"command":command}
    
    if "actions" in flow:
        kwargs["actions"] = _actions(switch, flow["actions"])
    else:
        kwargs["actions"] = []
    
    if "match" in flow:
        kwargs["match"] = _match(switch, **flow["match"])
    else:
        kwargs["match"] = _match(switch)

    if "priority" in flow:
        kwargs["priority"] = flow["priority"]
    
    if "table" in flow:
        kwargs["table_id"] = flow["table"]
    
    switch.install_instructions(**kwargs)
