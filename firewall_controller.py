from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types


class FirewallController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # Use OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(FirewallController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # store MAC to port mapping for learning switch behavior

        # Define blocked IP pair (h1 -> h2) - firewall rule: block traffic from src to dst
        self.blocked_src = "10.0.0.1"  # h1
        self.blocked_dst = "10.0.0.2"  # h2

    # Install table-miss flow (send packets to controller)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)
        ]  # send to controller

        self.add_flow(datapath, 0, match, actions)  # add flow rule

    # Function to add flow rule
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]  # create instruction to apply actions

        if buffer_id:  # if buffer_id is provided, include it in the flow mod message
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=60,
                hard_timeout=300,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )

        datapath.send_msg(mod)

        # message contains what needs to be sent to the switch to add a flow rule

    # Handle incoming packets (CORE LOGIC)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        in_port = msg.match["in_port"]

        self.logger.info("Packet in: %s -> %s (port %s)", src, dst, in_port)

        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port

        # FIREWALL LOGIC (IP-based blocking)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            if src_ip == self.blocked_src and dst_ip == self.blocked_dst:
                self.logger.info("🚫 BLOCKED: %s -> %s", src_ip, dst_ip)

                # Install DROP rule (no actions)
                match = parser.OFPMatch(
                    eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip
                )

                self.add_flow(datapath, 100, match, [])
                return

        # NORMAL LEARNING SWITCH BEHAVIOR
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

        # Install forwarding rule
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 1, match, actions)

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
