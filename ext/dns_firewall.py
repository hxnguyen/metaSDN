# Author: Thien Pham (c) 2016


from pox.lib.revent import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.lib.packet.dns as pkt_dns



log = core.getLogger()


class DNSUpdateNotification(Event):
    def __init__(self, item):
        Event.__init__(self)
        self.item = item

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
        self.ip_to_name = {}
        self.name_to_ip = {}
        self.cname = {}
        self.blocking = {}
        core.openflow.addListeners(self)
        self.addListener(DNSLookupNotification, self._handle_DNSLookupNotification)
        self.addListener(DNSUpdateNotification, self._handle_DNSUpdateNotification)

    def block_this_domain_global(self, domain, expire):
        self.blocking[domain] = expire

    def block_host_from_accessing_domain(self, domain, src_ip, src_mac):
        pass

    def is_blocking_global(self, domain):
        return domain in self.blocking.keys()

    def lookup (self, something):
        if something in self.name_to_ip:
            return self.name_to_ip[something]
        if something in self.cname:
            return self.lookup(self.cname[something])
        try:
            return self.ip_to_name.get(IPAddr(something))
        except:
            return None

    def _record (self, ip, name):
        # Handle reverse lookups correctly?
        modified = False
        val = self.ip_to_name.setdefault(ip, [])
        if name not in val:
            val.insert(0, name)
            modified = True

        val = self.name_to_ip.setdefault(name, [])
        if ip not in val:
            val.insert(0, ip)
            modified = True

        return modified

    def _record_cname (self, name, cname):
        modified = False
        val = self.cname.setdefault(name, [])
        if name not in val:
            val.insert(0, cname)
            modified = True

        return modified

    def _handle_DNSLookupNotification(self, event):

        def check_for_blocking(domain):
            if self.is_blocking_global(domain):
                return "BLOCKED"
            return "NON-BLOCKED"

        log.info("Host at %s [%s] DNS lookup for %s, question type = %s, which is %s", event.src_ip, event.src_mac,
                 event.name, event.qtype, check_for_blocking(event.name))

    def _handle_DNSUpdateNotification(self, event):
        log.info("CNAME lists is now %s", self.cname)
    def _handle_ConnectionUp (self, event):
        self.current_connection = event.connection
        if self._install_flow:
            # incoming DNS
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_type = pkt.ethernet.IP_TYPE
            msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
            msg.match.tp_src = 53
            msg.priority = 1000
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
                if not self.is_blocking_global(question.name):
                     e = event.parsed
                     msg = of.ofp_packet_out()
                     msg.data = e.pack()
                     msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                     self.current_connection.send(msg)

            def process_q (entry):
                if entry.qclass != 1:
                    # Not internet
                    return

                if entry.qtype == pkt.dns.rr.CNAME_TYPE:
                    if self._record_cname(entry.name, entry.rddata):
                        self.raiseEvent(DNSUpdateNotification, entry.name)
                        log.info("add cname entry: %s %s" % (entry.rddata, entry.name))
                elif entry.qtype == pkt.dns.rr.A_TYPE:
                    if self._record(entry.rddata, entry.name):
                        self.raiseEvent(DNSUpdateNotification, entry.name)
                        log.info("add dns entry: %s %s" % (entry.rddata, entry.name))

            for answer in dns_packet.answers:
                #print "here4"
                process_q(answer)
            for addition in dns_packet.additional:
                process_q(addition)

            e = event.parsed
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.current_connection.send(msg)

