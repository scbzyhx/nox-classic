from nox.lib.core import *
import nox.lib.pyopenflow as of
from nox.coreapps.pyrt.pycomponent import *
#from nox.netapps.routing import pyrouting
#from nox.netapps.topology.pytopology import pytopology
#from nox.netapps.monitoring.monitoring import Monitoring
#from nox.netapps.discovery.discovery import discovery
#from nox.netapps.authenticator.pyflowutil import Flow_in_event
#from nox.netapps.firewall.msg import MSG
from nox.lib.packet.ethernet import *
from nox.lib.packet.packet_utils import ipstr_to_int,ip_to_str


from nox.lib.netinet import netinet
from nox.lib.netinet.netinet import c_ntohl
from nox.lib.util import set_match

from nox.lib.netinet import netinet

import simplejson as json
from socket import ntohs,htons

from twisted.python import log
import logging
import socket
import thread

log = logging.getLogger('nox.netapps.gateway.gateway')
INTERVAL = 10
U32_MAX = 0xffffffff
DP_MASK = 0xffffffffffff
PORT_MASK = 0xffff

BROADCAST_TIMEOUT = 2
FLOW_TIMEOUT = 20

#a dict to record xid
xid = 0
PORT = 12345
BUF_MAX_SIZE = 1024
FIREWALL_PRIORITY = of.OFP_DEFAULT_PRIORITY
PERMANENT = 0

CONTROLLER_IP = "192.168.1.3"
DPID = 0x00000001
MAXLEN_ETH = 1500

#def recv_packet)


class pyGateway(Component):

    def __init__(self, ctxt):
        self.ctxt_ = ctxt
        Component.__init__(self, ctxt)
        self.gates = {}
        self.dp = {}
        self.enableTimer = True

    def install(self):
        '''start a thread to receive message from victim servers
           and response to the request
        '''
        log.warning("gateway installed")
        self.register_for_datapath_join(self.handleDatapathJoinIn)
        self.register_for_datapath_leave(self.handleDatapathLeave)
        self.register_for_packet_in(self.handlePacketIn)
        
        

    def handleDatapathJoinIn(self,dpid,stats):
        '''datapath_join_in event handler
           add a flow rule and send ARP requests, once get ARP reply then store it 
           for each gate
        '''
        print 'datapath Join'
        #add a flow rule and sent ARP test,once get ARP request
        print dpid
        if dpid != DPID:
            return CONTINUE
        self.dp[dpid] = {}
        #dp[dpid][port_no][hw_addr]
        for port in stats['ports']:
            #print type(port['port_no']),type(port['hw_addr'])
            self.dp[dpid][port['port_no']] = port['hw_addr']
        #by the way store the MAC and inport
        #dst = 1.3 /op
        attrs = {}
        attrs[core.NW_DST] = self.getControllerIP()
        actions = [[of.OFPAT_OUTPUT,[MAXLEN_ETH,of.OFPP_CONTROLLER]]]
        self.install_datapath_flow(dpid,attrs,PERMANENT,PERMANENT,actions)
        #tempo
        self.gates[ipstr_to_int('192.168.1.1')] = {'mac':0,'port':0,'dpid':0}
        self.gates[ipstr_to_int('192.168.1.2')] = {'mac':0,'port':0,'dpid':0}

        
        self.sendARPRequest()

        self.post_callback(INTERVAL,self.sendARPRequest)
        return CONTINUE

    def handleDatapathLeave(self,dpid):
        if dpid == DPID:
            self.gates = {}
            self.enableTimer = False
            self.dp = {}
            
        return CONTINUE       

    def getInterface(self):
        return str(pyGateway)
    
    #
    #Interfaces for other modules to get gatewasy infomations
    #
    def getGateways(self):
        '''To get all gates' informations
        '''
        return self.gates
    def getDpidMacPort(self,ip):
        try:
            if type(ip) == type(''):
                #print self.gates.keys()
                return (self.gates[ipstr_to_int(ip)]['dpid'],\
                self.gates[ipstr_to_int(ip)]['mac'],\
                self.gates[ipstr_to_int(ip)]['port'])
            elif type(ip) == type(1):
                return (self.gates[ip]['dpid'],self.gates[ip]['mac'],self.gates[ip]['port'])
            return (None,None,None)
        except KeyError as e:
            return (None,None,None)

    def getMac(self,ip):
        try:
            if type(ip) == type(''):
                return self.gates[ipstr_to_int(ip)]['mac']
            elif type(ip) == type(1):
                return self.gates[ip]['mac']
            return None
        except KeyError as e:
            return None
    
    def getPort(self,ip):
        try:
            if type(ip) == type(''):
                return self.gates[ipstr_to_int(ip)]['port']
            elif type(ip) == type(1):
                return self.gates[ip]['port']
            return None
        except KeyError as e:
            return None

    def getDhcp(self):
        try:
            if len(self.gates.keys()) > 0:
                ip = self.gates.keys()[0]
                return (self.gates[ip]['dpid'],ip,self.gates[ip]['port'])
            else:
                return None
        except KeyError as e:
            return None

    #
    #Threee Interfaces are proposed
    #

    def getGateSets(self):
        '''TODO: To be changed here
        '''
        return ["192.168.1.1",'192.168.1.2']
    def getControllerIP(self):
        '''TODO: To be changed here
        '''
        return ipstr_to_int("192.168.1.3")

    def handlePacketIn(self,dpid,inport,reason,frameLen,bufId,packet):
        if not packet.parsed:
            packet.parese()
        if packet.type != ethernet.ARP_TYPE or reason != of.OFPR_ACTION:
            return CONTINUE
        #print 'reason = ',reason,"  ",of.OFPR_ACTION
        if self.receiveARPResponse(packet,dpid,inport):
            return STOP
        return CONTINUE
        
    def sendARPRequest(self):
        '''send ARP every 5 seconds to find gateways, 
           and find expires of gateways

           for simplicity, I just broadcast everytime.
           in fact, once get reply, You just needs to unicast instead of broadcast
        '''
        ethp = ethernet()
        #dpid = 0
        if len(self.dp.keys()) > 0:
            dpid = self.dp.keys()[0]
        else:
            return

        for port in self.dp[dpid].keys():
            if port > 1000:
                continue
            for dst in self.gates.keys():
                
                "physical layer"
                ethp.dst = ETHER_BROADCAST#
                ethp.src = self.dp[dpid][port]
                ethp.type = ethernet.ARP_TYPE

                "link layer"
                arpp = arp()
                arpp.opcode = arp.REQUEST
                arpp.hwsrc = self.dp[dpid][port]
                arpp.hwdst = ETHER_BROADCAST
                arpp.hwlen = 6
                arpp.protolen = 4
                arpp.protosrc = self.getControllerIP()
                arpp.protodst = dst

                ethp.set_payload(arpp)

                self.send_openflow_packet(dpid,ethp.tostring(),port)
        
        if self.enableTimer:
            self.post_callback(INTERVAL,self.sendARPRequest)

    def receiveARPResponse(self,packet,dpid,inport):
        '''when received ARP response packet, parsed here
        '''
        arpp = packet.find('arp')
        if arpp.protodst != self.getControllerIP() or arpp.opcode != arp.REPLY:
            return False

        gateip = arpp.protosrc
        gatehw = arpp.hwsrc
        if gateip in self.gates.keys():
            if gatehw == self.gates[gateip]['mac'] and \
                self.gates[gateip]['port'] == inport and \
                self.gates[gateip]['dpid'] == dpid:
                #print 'direct return'
                return
            self.gates[gateip]['mac'] = gatehw
            self.gates[gateip]['port'] = inport
            self.gates[gateip]['dpid'] = dpid
            print self.gates

        return True


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return pyGateway(ctxt)

    return Factory()

#if __name__ == "__main__":

