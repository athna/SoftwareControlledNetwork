#!/usr/bin/python2.7

# Copyright 2017 Mael Kimmerlin
# Modified by Hammad Kabir, Dec 2018
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


import json
import uuid

#The supported version are ofproto_v1_0 and ofproto_v1_3
OPENFLOW_PROTOCOL = ofproto_v1_3

# run with ryu-manager <filenameWithout.py> --wsapi-port 8880
# for example run with ryu-manager template --wsapi-port 8880

agent_name = 'sdn_assignment_app'


#########################################################
# SDN application                                       #
# This contains the SDN logic that runs your controller #
#########################################################

class SDNapp(app_manager.RyuApp):
    OFP_VERSIONS = [OPENFLOW_PROTOCOL.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SDNapp, self).__init__(*args, **kwargs)
        self.datapaths          = {}        # Contains the OpenFlowSwitch object for each connected switch
        self.data               = {}        # Contains the data to pass to the REST API
        #For example, passing a dictionnary of names and the dictionnary of switches
        self.data["names"]      = {}
        self.data["switches"]   = self.datapaths
        self.mac_to_port        = {}
        self.virtual_switches   = [1,3,4,6]
        self.physical_switches  = [2,5]
        self.switch_host_ports  = [1,2]
        self._initialize_load_balancing()
        self._initialize_vlan_ports()
        wsgi = kwargs['wsgi']
        # self.data object is given to the RESTControlAPI, and within it we can store all the parameters upon parsing the REST query.
        # Beware! a copy of data is given to the app, not data itself, so any structural modifications made in the copy of data would be lost
        # So it has to be done here before registering to the app.
        wsgi.register(RESTControlAPI, self.data)

    def _initialize_vlan_ports(self):
        # Initialize VLANs to empty values - The dictionary is populated based on inputs from REST API
        self.logger.info("Dictionary to register VLAN tags associated with VMs")
        self.data["ports"]  = {}
        link_ids            = ["1A", "1B", "3A", "3B", "4A", "4B", "6A", "6B"]
        for link_id in link_ids:
            self.data["ports"][link_id] = None
    
    def _initialize_load_balancing(self):
        """ Setting the initial outbound port of all the switches to port-3"""
        self.logger.info("Setting a default outbound port on all switches")
        self.switch_last_port = {}
        for s in self.virtual_switches:
            self.switch_last_port[s] = 3

    #This handles the packet in events (reactive)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Get datapath-ID to identify OpenFlow switches.
        dpid = datapath.id          # dpid = hex(ev.dp.id)
        self.mac_to_port.setdefault(dpid, {})
        
        # Analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)           # Get Ethernet packet
        vlan_pkt = pkt.get_protocol(vlan.vlan)                  # Get VLAN VID from packet
        vid = 0
        dst = eth_pkt.dst
        src = eth_pkt.src
        in_port = msg.match['in_port']
        if vlan_pkt:
            vid = vlan_pkt.vid
        self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, vid)
        
        # MAC address learning to avoid FLOODing next time.
        self.mac_to_port[dpid][src] = in_port
        output_ports = []
        flood        = False
        pop_vlan     = False
        push_vlan    = False
        
        # If the destination MAC address is already learned, Find corresponding output port. Else, Flood.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            output_ports= [self.mac_to_port[dpid][dst]]
            if dpid in self.virtual_switches:
                if out_port in self.switch_host_ports:       # [1,2]
                    # Find the link-ID and corresponding VLAN-ID, AND pop this VLAN-ID
                    if out_port == 1: link_id = str(dpid) + "A"
                    else:             link_id = str(dpid) + "B"
                    link_vid = self.data["ports"][link_id ]
                    
                    if type(link_vid)==type(1) and link_vid != None:
                        if vid == link_vid:
                            pop_vlan = True
                        else:
                            self.logger.info("Packet with Mismatching VLAN-ID arrived at switch='{}' & Link-id '{}'".format(dpid, link_id))
                            return
            
                else:
                    # Based on input-port, find the link-ID and the corresponding VLAN-ID, AND push the VLAN-ID on to the packet
                    if in_port == 1:  link_id = str(dpid) + "A"
                    else:             link_id = str(dpid) + "B"
                    output_ports  = [self.run_load_balancing(dpid)]
                    link_vid      = self.data["ports"][link_id]
                    if link_vid  != None:    
                        push_vlan =True
                    
        else:
            flood = True
            if dpid in self.physical_switches:
                output_ports= [ofproto.OFPP_FLOOD]
            else:
                # Run selective Broadcasting/Flooding for virtual switches
                if in_port in self.switch_host_ports:       # [1,2]
                    # If packet comes from host-ports, we attempt to find port's VLAN-ID and push it on to packet.
                    if in_port == 1:  link_id = str(dpid) + "A"
                    else:             link_id = str(dpid) + "B"
                    link_vid = self.data["ports"][link_id]
                    if link_vid != None:        # Need to push VLAN, if REST API has provided a VLAN-ID for the port.
                        push_vlan = True
                    output_ports = self.selective_flooding(in_port)
                    
                else:
                    # Incoming packet from port: 3 or 4
                    output_ports= []
                    port_to_hosts = ["A", "B"]
                    for p in port_to_hosts:
                        private_linkid = '{}{}'.format(dpid, p)
                        link_vid = self.data["ports"][private_linkid]
                        if p == "A": output_ports += [1]
                        else:        output_ports += [2]
                        
                        # if the packet is going to switch-ports 1 & 2, and VLAN-ID is present, the strip the VLAN.
                        if (link_vid != None) and (vid == link_vid):
                            pop_vlan = True          
                        
        # construct action list.
        actions=[]
        
        if pop_vlan and output_ports:
            self.logger.info("Strip the the VLAN-ID")
            actions.append(parser.OFPActionPopVlan())
        elif push_vlan and output_ports and link_vid:
            self.logger.info("Push VLAN-ID on the packet")
            actions.append(parser.OFPActionPushVlan())
            actions.append(parser.OFPActionSetField(vlan_vid=link_vid|ofproto_v1_3.OFPVID_PRESENT))
            
        for port in output_ports:
            actions.append(parser.OFPActionOutput(port))
        
        # install a flow to avoid packet_in next time.
        if not flood:
            if pop_vlan is True:     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=link_vid)
            else:               match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # Adding a flow rule to the switch
            self.add_flow(datapath, 1, match, actions)
    
        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
        						  buffer_id=ofproto.OFP_NO_BUFFER,
        						  in_port=in_port, actions=actions,
        						  data=msg.data)
        
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
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)

        #The switch disconnects
        else:
            if dpid in self.datapaths:
                del self.datapaths[dpid]
            self.logger.info(str(dpid)+": Switch disconnected")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    def run_load_balancing(self, dpid):
        """ Balancing the load on port-3 and 4 of virtual switches """
        out_port = 3            # Initializing with some port
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
        
                
###################################################
# REST application                                #
# This contains the REST logic that runs your API #
###################################################

class RESTControlAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RESTControlAPI, self).__init__(req, link, data, **config)
        self.data = data


    @route('Ports', '/task2/ports', methods=['GET','POST'])
    def portsList(self, req, **kwargs):
        if req.method == "GET":
            # Dump ports
            return json.dumps(self.data["ports"])+"\n"
        
        elif req.method == "POST":
            # Verify arguments and set VLAN VID of the port
            if not req.body or not req.json:
                return Response(status=400, body="Missing parameters")
            if "name" in req.json and "vlan" in req.json:
                if req.json["name"] in self.data["ports"]:
                    self.data["ports"][req.json["name"]] = req.json["vlan"]
                    return "\n"
                else:
                    return Response(status=400, body="Invalid port name")
            else:
                return Response(status=400, body="Missing parameters")
    @route('Ports', '/task2/port/{portid}', methods=['GET','PUT','DELETE'])
    def portNonList(self, req, **kwargs):
        """
        print("req: ", req)
        print("kwargs: ", kwargs)
        print("portid" in kwargs)
        print("req.json: ", req.json)
        print("vlan" in req.json)
        print(type(req))
        """
        if req.method == "GET":
            # Verify arguments and dump VLAN VID of one port
            if "portid" in kwargs:
                portid = kwargs["portid"]
                if portid in self.data["ports"]:
                    return json.dumps(self.data["ports"][portid])+"\n"
                else:
                    return Response(status=404, body="Not found")
            else:
                return Response(status=404, body="Not found")
        elif req.method == "PUT":
            # Verify arguments and set VLAN VID to the correct value
            if "portid" in kwargs and "vlan" in req.json:
                portid = kwargs["portid"]
                vlan = req.json["vlan"]
                print("portid, vlan: ", portid, vlan)
                if portid in self.data["ports"]:
                    self.data["ports"][portid] = vlan
                    return "\n"
                else:
                    return Response(status=404, body="Not found")
            else:
                return Response(status=404, body="Not found")
        elif req.method == "DELETE":
            # Verify arguments and delete the VLAN VID from the port
            if "portid" in kwargs:
                portid = kwargs["portid"]
                if portid in self.data["ports"]:
                    self.data["ports"][portid] = None
                    return "\n"
                else:
                    return Response(status=404, body="Not found")
            else:
                return Response(status=404, body="Not found")
        
    @route('HelloWorld', '/helloworld', methods=['GET','POST'])
    def helloWorldList(self, req, **kwargs):
        if req.method == "GET":
            #Do something for GET, for example
            return json.dumps(self.data["names"])+"\n"
        
        elif req.method == "POST":
            #Do something for POST, for example
            if not req.body or not req.json:
                return Response(status=400, body="Missing parameters")
            if "name" in req.json:
                tmpUuid = str(uuid.uuid4())
                self.data["names"][tmpUuid]=req.json["name"]
                return json.dumps({tmpUuid:self.data["names"][tmpUuid]})+"\n"
            else:
                return Response(status=400, body="Missing parameters")

    @route('HelloWorld', '/helloworld/{uuid}', methods=['GET','DELETE','PUT'])
    def helloWorldElement(self, req, **kwargs):
        if req.method == "GET":
            #Do something for GET, for example
            if "uuid" in kwargs:
                return json.dumps({kwargs["uuid"]:self.data["names"][kwargs["uuid"]]})+"\n"
            else:
                return Response(status=404, body="Not found")
        
        elif req.method == "DELETE":
            #Do something for DELETE, for example
            if "uuid" in kwargs:
                del self.data["names"][kwargs["uuid"]]
                return Response(status=200)
            else:
                return Response(status=404, body="Not found")
        
        elif req.method == "PUT":
            #Do something for PUT, for example
            if "name" in req.json:
                self.data["names"][kwargs["uuid"]]=req.json["name"]
                return json.dumps({kwargs["uuid"]:self.data["names"][kwargs["uuid"]]})+"\n"
            else:
                return Response(status=400, body="Missing parameters")


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

