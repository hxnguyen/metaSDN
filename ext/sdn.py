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
from pox.messenger.tcp_transport import *
from pox.messenger import *
from pox.proto.dhcpd import *
from pox.py import *
from pox.proto.dns_spy import *


class Controller(object):

    def __init__(self):
        core.openflow.addListeners(self)
        self.current_connection = None
        self.ARP_table = {}
        self.IP_to_Interface_Map = {}
        self.gateway = '192.168.1.1'
        self.dhcp_server = ".".join(self.gateway.split('.')[0:3] +  ['254'])
        self.interfaces = { 'wifi' : '00:00:00:00:00:01',
                            '4g'   : '00:00:00:00:00:02',
                            'priority' : 'wifi' }
        self.dpid = None
        self.awaiting_for_ARP = {}

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
        """
        Args:
            event: event contains incoming packet

        Returns: None
        Handle ARP request for gateway and dhcp server mac address

        """
        self.dpid = event.connection.dpid
        inport = event.port
        packet = event.parsed
        if not packet.parsed:
            #log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
            return
        a = packet.find('arp')
        if not a:
            return
        if a.opcode == arp.REPLY:
            if a.protosrc.toStr() == self.gateway or a.protosrc.toStr() == self.dhcp_server:
                # Drop controller generated ARP packets
                return
            if a.protosrc.toStr() in self.awaiting_for_ARP.keys():
                # ARP reply received from the IP address we want
                interface = self.awaiting_for_ARP.pop(a.protosrc.toStr()) # remove from memorized dictionary
                self.send_arp_reply(self.current_connection, self.interfaces[interface], self.gateway,
                            a.hwsrc.toStr(), a.protosrc.toStr(), of.OFPP_FLOOD)
                self.IP_to_Interface_Map[a.protosrc.toStr()] = interface
                self.ARP_table[a.protosrc.toStr()] = a.hwsrc.toStr()
                print self.IP_to_Interface_Map
                return
            # Unintended ARPs from clients
            self.ARP_table[a.protosrc.toStr()] = a.hwsrc.toStr()
            self.IP_to_Interface_Map[a.protosrc.toStr()] = self.interfaces['priority']
            return
        if a.opcode == arp.REQUEST:
            # Check if someone requesting gateway MAC
            if a.protodst.toStr() == self.gateway:
                # Perform ARP lookup here
                if a.protosrc.toStr() in self.IP_to_Interface_Map.keys():
                    self.send_arp_reply(self.current_connection,
                                        self.interfaces[self.IP_to_Interface_Map[a.protosrc.toStr()]],
                                        self.gateway,
                                        a.hwsrc.toStr(),
                                        a.protosrc.toStr(),
                                        inport)
                else:
                    # Default is using priority interface as specified in self.interfaces
                    self.send_arp_reply(self.current_connection,
                                        self.interfaces[self.interfaces['priority']],
                                        self.gateway,
                                        a.hwsrc.toStr(),
                                        a.protosrc.toStr(),
                                        inport)
                    # Add IP to ARP lookup table
                    self.IP_to_Interface_Map[a.protosrc.toStr()] = self.interfaces['priority']
                    self.ARP_table[a.protosrc.toStr()] = a.hwsrc.toStr()
                return

            if a.protodst.toStr() == self.dhcp_server:
                if a.protodst.toStr() in self.IP_to_Interface_Map.keys():
                    self.send_arp_reply(self.current_connection,
                                        self.interfaces[self.IP_to_Interface_Map[a.a.protosrc.toStr()]],
                                        self.dhcp_server,
                                        a.hwsrc.toStr(),
                                        a.protosrc.toStr(),
                                        inport)
                else:
                    self.send_arp_reply(self.current_connection,
                                        self.interfaces[self.interfaces['priority']],
                                        self.dhcp_server,
                                        a.hwsrc.toStr(),
                                        a.protosrc.toStr(),
                                        inport)
                    self.IP_to_Interface_Map[a.protosrc.toStr()] = self.interfaces['priority']
                    self.ARP_table[a.protosrc.toStr()] = a.hwsrc.toStr()

        # print '\nARP packet handled'
        # print self.ARP_table

    def getMacAddressOverNetwork(self, dst_ip, interface):
        timeout = 10
        if dst_ip in self.ARP_table.keys():
            log.info("Sent ARP reply for %s" ,dst_ip)
            self.send_arp_reply(self.current_connection, src_mac=self.interfaces[interface],
                              src_ip=self.gateway, dst_mac=self.ARP_table[dst_ip],dst_ip=dst_ip, port_out=of.OFPP_FLOOD)
            log.info("Mac address of %s is %s", dst_ip, self.ARP_table[dst_ip])
            return

        while dst_ip not in self.ARP_table.keys() and timeout > 0:
            log.info("Sending ARP request for %s" ,dst_ip)
            self.send_arp_request(self.current_connection, src_mac=self.interfaces[self.interfaces['priority']],
                              src_ip=self.gateway, dst_ip=dst_ip, port_out=of.OFPP_FLOOD)
            time.sleep(1)
            timeout = timeout - 1


        if timeout == 0 and dst_ip not in self.ARP_table.keys():
            log.warning("ARP request timeout. Controller cannot obtain MAC of %s", dst_ip)
        log.info("MAC address of %s is %s", dst_ip, self.ARP_table[dst_ip])



    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has come up." ,event.dpid)
        self.current_connection = event.connection
        self.switch_hwaddr = dpid_to_str(event.dpid)
        # print self.switch_hwaddr
        self.dpid = event.dpid
        #controllerDHCP = ControllerDHCPD(event, {'eth0':""})
        #core.register("dhcp", controllerDHCP)

    def getConnection(self):
        return self.current_connection

    def clear_flows (self):
        """ Clear flows on switch """
        d = of.ofp_flow_mod(command = of.OFPFC_DELETE)
        self.current_connection.send(d)

    # To instruct one host (ip) to use a specific interface (wifi or 4g, etc) when connecting to the internet
    def setInterfaceForIP(self, ip, interface):

        if interface not in self.interfaces.keys():
            log.warning("Unknown interface.")
            return
        self.awaiting_for_ARP[ip] = interface
        thread.start_new_thread(self.getMacAddressOverNetwork, (ip, interface, ) )

    def setPriorityInterface(self, interface):
        self.interfaces['priority'] = interface


    def clear_arp_table(self):
        self.ARP_table = {}

    def clear_IP_to_interface_map(self):
        self.IP_to_Interface_Map = {}




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
                #core.controller.setInterfaceForIP('192.168.1.9', 'wifi')
                #time.sleep(4)
                #core.controller.setInterfaceForIP('192.168.1.9', '4g')
                #time.sleep(4)
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
        if ip == 'None':
            if priority == 'None':
                self.con.send(reply(msg, msg = str("Neither IP nor Priority Interface Provided")))
                return
        if priority != 'None':
            core.controller.setPriorityInterface(priority)
            self.con.send(reply(msg, msg= str('Priority interface is now ' + priority)))
            print core.controller.interfaces
            return

        # print ip + " " + interface + "\n"
        if interface not in ['wifi', '4g', 'priority']:
            self.con.send(reply(msg,msg = "Unknown interface. Available interface are: 'wifi', '4g', 'priority'"))
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

class HelperService(object):
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
        if msg.get('CHANNEL') != '':
            # drop msg target for other channels
            return

        self.con.send(reply(msg, msg = str("This is helper channel.\n" +
                                           "Available channels: 'default', 'change_interface', 'add_flow'\n")))


class HelperBot(ChannelBot):
    def _init(self, extra):
        self.clients = {}
    def _unhandled(self, event):
        if event.msg.get('CHANNEL') == '':
            connection = event.con
            if connection not in self.clients:
                self.clients[connection] = HelperService(self, connection, event)
class Messenger(object):
    def __init__(self):
        core.listen_to_dependencies(self)

    def _all_dependencies_met (self):
        # Set up the "change interface" service
        ChangeInterfaceBot(core.MessengerNexus.get_channel("change_interface"))
        # Set up the "Helper" service
        HelperBot(core.MessengerNexus.get_channel(""))

    def _handle_MessengerNexus_ChannelCreate (self, event):
        # It's a new channel -- put in an HelperBot
        # Information about bot can be found in pox/messenger/__init__.py
        HelperBot(event.channel)


class ControllerDHCPD(DHCPD):

    def __init__ (self, listen_to_ports = {}, *args, **kw):
        self._listen_to_ports = listen_to_ports
        self._switch_ports = {}
        self._install_flow = True
        self._dpid = None
        super(ControllerDHCPD,self).__init__(*args,**kw)

    def _handle_ConnectionUp (self, event):
        ports = event.connection.ports
        self._dpid = event.dpid
        #print str(ports['s1-eth1']).split(':')
        for port in ports:
            port_name, port_no = str(ports[port]).split(':')
            # print port_name, port_no
            self._switch_ports[port_name] = port_no
            if self._listen_to_ports.has_key(port_name):
                self._listen_to_ports[port_name] = port_no
        # print "listen : "
        # print self._listen_to_ports.keys()
        # print "switch : "
        # print self._switch_ports.keys()
        if not set(self._listen_to_ports.keys()).issubset(set(self._switch_ports.keys())):
            log.warn("No port %s on DPID %s", self._listen_to_ports,
            dpid_to_str(self._dpid))
            return
        for port_name, port_no in self._listen_to_ports.items():
            log.info("DHCP service serving for incoming requests on: %s (port_name) : %s (port_number)", port_name, port_no)
        return super(ControllerDHCPD,self)._handle_ConnectionUp(event)

    def _handle_PacketIn (self, event):
        if self._dpid != event.dpid:
            return
        if str(event.port) not in self._listen_to_ports.values():
            return
        return super(ControllerDHCPD,self)._handle_PacketIn(event)


def launch(disable_interactive_shell = False):
    controller = Controller()
    core.register("controller", controller)
    thread.start_new_thread(test,())
    core.registerNew(MessengerNexus)
    pool = SimpleAddressPool(network="192.168.1.0/24", first=2, last=253, count=1)
    core.registerNew(ControllerDHCPD, listen_to_ports={'eth0':''}, install_flow=True,
                     router_address=core.controller.gateway, dns_address=core.controller.gateway,
                     ip_address="192.168.1.254", pool=pool)
    thread.start_new_thread(messenger_service, ())
    core.registerNew(DNSSpy)











