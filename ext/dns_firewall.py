# Author: Thien Pham (c) 2016


from pox.lib.revent import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.packet.dns as pkt_dns



log = core.getLogger()


class DNSUpdateNotification(Event):
    def __init__(self):
        Event.__init__(self)



class DNSLookupNotification(Event):

    def __init__(self, pkt_dns_question, src_ip, src_mac):
        Event.__init__(self)
        self.name = pkt_dns_question.name
        self.qtype = pkt_dns_question.qtype
        self.src_ip = src_ip
        self.src_mac = src_mac


class DNSFirewall(EventMixin):

    _eventMixin_events = set([ DNSUpdateNotification, DNSLookupNotification ])

    def __init__(self, install_flow = True):
        self._install_flow = install_flow
        self.ip_to_name_map = {}
        self.name_to_ip_map = {}
        self.cname = {}
        self.blocking = {}
        core.openflow.addListeners(self)
        self.addListener(DNSLookupNotification, self._handle_DNSLookupNotification)

    def block_this_domain(self, domain, expire):
        self.blocking[domain] = expire

    def is_blocking(self, domain):
        return domain in self.blocking.keys()

    def _handle_DNSLookupNotification(self, event):

        def check_for_blocking(domain):
            if self.is_blocking(domain):
                return "BLOCKED"
            return "NON-BLOCKED"

        log.info("Host at %s [%s] dns to %s, question type = %s, which is %s", event.src_ip, event.src_mac,
                 event.name, event.qtype, check_for_blocking(event.name))


    def _handle_ConnectionUp (self, event):
        if self._install_flow:
            # incoming DNS
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_type = pkt.ethernet.IP_TYPE
            msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
            msg.match.tp_src = 53
            msg.priority = 10
            msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
            event.connection.send(msg)
            # outgoing DNS
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_type = pkt.ethernet.IP_TYPE
            msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
            msg.match.tp_dst = 53
            msg.priority = 10
            msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
            event.connection.send(msg)

    def _handle_PacketIn(self, event):
        dns_packet = event.parsed.find('dns')
        if dns_packet is not None and dns_packet.parsed:
            #log.info(p)
            src_ip =  event.parsed.payload.srcip
            src_mac = event.parsed.src
            for question in dns_packet.questions:
                if question.qclass != 1:
                    continue # internet only
                self.raiseEvent(DNSLookupNotification, question, src_ip, src_mac)
                print "here3"