# Author: Thien Pham (c) 2016
# SDN controller: change routing to the internet for specific IP
#
from pox.core import core

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.revent import EventHalt, Event, EventMixin
import time
import thread
import pox.openflow.libopenflow_01 as of
from pox.boot import *
from pox.messenger.tcp_transport import *
from pox.messenger.web_transport import *
from pox.messenger.ajax_transport import *
from pox.messenger.log_service import *
from pox.messenger.example import *
from pox.messenger import *


class Controller(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.current_connection = None
        self.ARP_table = {}
        self.IP_to_Interface_Map = {}
        self.gateway = '10.0.0.1'
        self.interfaces = { 'wifi' : '00:00:00:00:00:01',
                            '4g'   : '00:00:00:00:00:04',
                            'priority' : 'wifi' }
    def send_arp_reply(self, connection, src_mac, src_ip, dst_mac, dst_ip, port_out):
        r = arp()
        r.opcode = r.REPLY
        r.hwsrc  = EthAddr(src_mac)
        r.protosrc = IPAddr(src_ip)
        r.hwdst  = EthAddr(dst_mac)
        r.protodst = IPAddr(dst_ip)
        e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(src_mac), dst=r.hwdst)
        e.payload = r
        msg  = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=port_out))
        msg.in_port = of.OFPP_NONE
        connection.send(msg)
    def send_arp_request(self, connection, src_mac, src_ip, dst_ip, port_out):
        r = arp()
        r.opcode = r.REQUEST
        r.hwsrc  = EthAddr(src_mac)
        r.protosrc = IPAddr(src_ip)
        r.hwdst = ETHER_BROADCAST
        r.protodst = IPAddr(dst_ip)
        e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(src_mac), dst=r.hwdst)
        e.payload = r
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        if port_out is None:
            port_out = of.OFPP_FLOOD
        msg.actions.append(of.ofp_action_output(port=port_out))
        msg.in_port = of.OFPP_NONE
        connection.send(msg)

    def _handle_PacketIn(self, event):
        dpid = event.connection.dpid
        inport = event.port
        packet = event.parsed
        if not packet.parsed:
            #log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
            return
        a = packet.find('arp')
        if not a:
            return
        if a.opcode == arp.REPLY:
            self.ARP_table[a.protosrc.toStr()] = a.hwsrc.toStr()
            return
        if a.opcode == arp.REQUEST:
            # Check if someone requesting gateway MAC
            if a.protodst.toStr() == self.gateway:
                # Perform ARP lookup here
                if a.protosrc.toStr() in self.IP_to_Interface_Map.keys():
                    self.send_arp_reply(self.current_connection, self.ARP_table[a.protosrc.toStr()],
                                        self.gateway, a.hwsrc.toStr(), a.protosrc.toStr(), inport)
                else:
                    # Default is using wifi
                    self.send_arp_reply(self.current_connection, self.interfaces[self.interfaces['priority']],
                                        self.gateway, a.hwsrc.toStr(), a.protosrc.toStr(), inport)
                    self.IP_to_Interface_Map[a.protosrc.toStr()] = self.interfaces['priority']

        # print '\nARP packet handled'
        # print self.ARP_table

    def getMacAddressOverNetwork(self, dst_ip):
        while dst_ip not in self.ARP_table.keys():
            print 'Sending ARP request for %s\n'  % (dst_ip)
            self.send_arp_request(self.current_connection, src_mac=self.switch_hwaddr,
                              src_ip='0.0.0.0', dst_ip=dst_ip, port_out=of.OFPP_FLOOD)
            time.sleep(1)
        print "\nMac address of %s is %s\n" % (dst_ip, self.ARP_table[dst_ip])



    def _handle_ConnectionUp(self, event):
        print "Switch %s has come up." % (event.dpid)
        self.current_connection = event.connection
        self.switch_hwaddr = dpid_to_str(event.dpid)
        print self.switch_hwaddr

    def getConnection(self):
        return self.current_connection

    def clear_flows (self):
        """ Clear flows on switch """
        d = of.ofp_flow_mod(command = of.OFPFC_DELETE)
        self.current_connection.send(d)

    # To instruct one host (ip) to use a specific interface (wifi or 4g, etc) when connecting to the internet
    def setInterfaceForIP(self, ip, interface):

        if interface not in self.interfaces.keys():
            print "\nUnknown interface."
            return

        thread.start_new_thread(self.getMacAddressOverNetwork, (ip, ) )

        while ip not in self.ARP_table.keys():
            pass

        self.send_arp_reply(self.current_connection, self.interfaces[interface], self.gateway,
                            self.ARP_table[ip], ip, of.OFPP_FLOOD)
        self.IP_to_Interface_Map[ip] = interface
        print self.IP_to_Interface_Map

    def setPriorityInterface(self, interface):
        self.interfaces['priority'] = interface


    #def add_flow(self,match,acions):



def test():
    print '\nTest thread is running'

    while(True):
        if core.controller.getConnection():
            msg = of.ofp_flow_mod()
            msg.priority = 1
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            core.controller.getConnection().send(msg)
            while (True):
                print 'Inside test function'
                # core.controller.send_arp_reply(core.controller.getConnection(),'00:00:00:00:00:01'
                #                    , '10.0.0.1', '00:00:00:00:00:02', '10.0.0.2', 2)
                # time.sleep(5)
                # core.controller.send_arp_reply(core.controller.getConnection(),'00:00:00:00:00:06'
                #                    , '10.0.0.1', '00:00:00:00:00:02', '10.0.0.2', 2)
                # time.sleep(5)
                #core.controller.send_arp_request(core.controller.getConnection(),'00:00:00:00:00:01'
                                                 # ,'10.0.0.1', '10.0.0.2', of.OFPP_FLOOD)
                # time.sleep(5)
                # core.controller.getMacAddressOverNetwork('10.0.0.2')
                #thread.start_new_thread(core.controller.getMacAddressOverNetwork, ('10.0.0.2',))
                core.controller.setInterfaceForIP('10.0.0.2', 'wifi')
                time.sleep(4)
                core.controller.setInterfaceForIP('10.0.0.2', '4g')
                time.sleep(4)
                break
            break



def messenger_service():
    def start():
        t = TCPTransport('0.0.0.0', '7790')
        t.start()
    core.call_when_ready(start, "MessengerNexus", __name__)

    Messenger()

class ChangeInterfaceService(object):
    def __init__ (self, parent, con, event):
        self.con = con
        self.parent = parent
        self.listeners = con.addListeners(self)

        # We only just added the listener, so dispatch the first
        # message manually.
        self._handle_MessageReceived(event, event.msg)

    def _handle_ConnectionClosed (self, event):
        self.con.removeListeners(self.listeners)
        self.parent.clients.pop(self.con, None)

    def _handle_MessageReceived (self, event, msg):
        if msg.get('CHANNEL') != 'change_interface':
            # drop msg target for other channels
            return
        ip = msg.get('ip')
        ip = str(ip)
        interface = msg.get('interface')
        interface = str(interface)
        priority = msg.get('priority')
        priority = str(priority)
        if ip is None:
            if priority is None:
                self.con.send(reply(msg, msg = str("Neither IP nor Priority Interface Provided")))
                return
        if priority is not None:
            core.controller.setPriorityInterface(priority)
            self.con.send(reply(msg, msg= str('Priority interface is now ' + priority)))
            print core.controller.interfaces
            return

        # print ip + " " + interface + "\n"
        if interface not in ['wifi', '4g', 'priority']:
            self.con.send(reply(msg,msg = "Unknown interface"))
        core.controller.setInterfaceForIP(ip, interface)
        self.con.send(reply(msg, msg = str(ip + ' is using ' + interface)))

class ChangeInterfaceBot(ChannelBot):
    def _init(self, extra):
        self.clients = {}
    def _unhandled(self, event):
        if event.msg.get('CHANNEL') == 'change_interface':
            connection = event.con
            if connection not in self.clients:
                self.clients[connection] = ChangeInterfaceService(self, connection, event)

class Messenger(object):
    def __init__(self):
        core.listen_to_dependencies(self)
    def _all_dependencies_met (self):
        # Set up the "controller" service
        ChangeInterfaceBot(core.MessengerNexus.get_channel("change_interface"))
        core.MessengerNexus.default_bot.add_bot(EchoBot)

    def _handle_MessengerNexus_ChannelCreate (self, event):
        if event.channel.name.startswith("echo_"):
            # Ah, it's a new echo channel -- put in an EchoBot
            # Information about bot can be found in pox/messenger/__init__.py
            EchoBot(event.channel)


def launch():
    controller = Controller()
    core.register("controller", controller)
    thread.start_new_thread(test,())
    core.registerNew(MessengerNexus)
    thread.start_new_thread(messenger_service, ())









