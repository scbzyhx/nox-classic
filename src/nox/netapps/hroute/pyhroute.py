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
from nox.lib.packet.dhcp import *
from nox.lib.packet.packet_utils import ipstr_to_int,ip_to_str
from nox.netapps.hroute.routetable import *

from nox.lib.netinet import netinet
from nox.lib.netinet.netinet import c_ntohl
from nox.lib.util import set_match

from nox.lib.netinet import netinet

import simplejson as json
from socket import ntohs,htons
import logging
import socket
import thread
#from twisted.python import log

from nox.netapps.gateway.gateway import *

logger = logging.getLogger('nox.netapps.hroute.pyhroute')
logger.setLevel(logging.DEBUG)
INTERVAL = 5
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
CACHE_TIMEOUT = 5

#def recv_packet)
TEST_DEBUG = True


class pyhroute(Component):

    def __init__(self, ctxt):
        self.ctxt_ = ctxt
        Component.__init__(self, ctxt)

    def install(self):
        '''start a thread to receive message from victim servers
           and response to the request
        '''
        logger.warning('install pyhroute')

        self.gates = self.resolve(pyGateway)

        self.register_for_datapath_join(self.handleDatapathJoinIn)
        #self.register_handler(Flow_in_event.static_get_name(),self.handleFlowIn)
        self.register_for_packet_in(self.handlePacketIn)
        self.count = 0
        self.routeTable = Table()
        #print self.routeTable
        

    def handleDatapathJoinIn(self,dpid,stats):
        '''datapath_join_in event handler
        '''
        return CONTINUE
    def handlePacketIn(self,dpid,inport,reason,length,bufid,packet):
        #if not event.active:
        #    return CONTINUE
        #print dir(event)
        #logger.warning('Packet_in in pyhroute')

        sloc = dpid#event.src_location['sw']['dp']
        #inport = event.src_location['port']

        eth = packet#ethernet(event.buf)
        #eth.parse()
        if eth.find('dhcp') != None:
            #print eth.find('dhcp')
            #self.handleDhcp(sloc,inport,bufid,eth)
            print eth.find('dhcp')
            return CONTINUE
        else:
            if eth.type == ethernet.ARP_TYPE:
                "broadcast here"
                #print eth.find('arp')
                return CONTINUE #leave to pyswitch
            elif eth.type == ethernet.IP_TYPE:
                ip = eth.find("ipv4")
                if self.isLocal(ip.dstip):
                    "Just Do nothing here, To add latter"
                    #print ip
                    print 'isLocal, ',ip_to_str(ip.srcip),'  ',inport 
                    #print ip
                    return CONTINUE #leave to pyswitch
                else:
                    "Ignore to cache server here now, just to the Internet"               
                    #self.randomRoute(sloc,inport,eth,bufid)
                    if TEST_DEBUG:
                        self.ipLayerRoute(sloc,inport,eth,bufid)
                    else:
                        self.route(sloc,inport,eth,bufid)
                    return STOP
            '''
                1. To local network
                2. To the Internet
                3. To the proxy server
            '''
        return STOP
    def isLocal(self,dstIP):
        ''' dstIP must be an integer
        '''
        localNet = ipstr_to_int("192.168.1.0")
        localMask = ipstr_to_int("255.255.255.0")
        if localMask & dstIP == localNet or dstIP == ipstr_to_int("255.255.255.255"):
            return True
        else:
            return False
        



    def route(self,sloc,inport,packet,bufid):
        flow = extract_flow(packet)
        ip = packet.find('ipv4')
        if ip == None:
            raise NotImplemented

        re = self.routeTable.getRoute(ip.dstip)
        if re == None:
            (k,_) = self.routeTable.getDefaultRoute()
        else:
            k,_ = re
        log.warning(k)

        
        kk,mac,out = self.gates.getDpidMacPort(k)
        if sloc != kk:#g[ipstr_to_int(k)]['dpid']:
            log.error('real dpid = %d',sloc,'hope dpid = %d', kk)
            raise NotImplemented

        flow[core.IN_PORT] = inport
        
        actions = [[of.OFPAT_OUTPUT,[0,out]]]
        self.install_datapath_flow(sloc,flow,CACHE_TIMEOUT,CACHE_TIMEOUT,actions,bufid,of.OFP_DEFAULT_PRIORITY,inport)

        
        #reverse flow

        attrs = reverseFlow(flow)
        attrs[core.IN_PORT] = out#g[k]['port'] 
        actions = [[of.OFPAT_OUTPUT,[0,inport]]]
        
        self.install_datapath_flow(sloc,attrs,CACHE_TIMEOUT,CACHE_TIMEOUT,actions)        
    
#
#To Test
#
    def ipLayerRoute(self,sloc,inport,packet,bufid):
        flow = {}
        ip = packet.find('ipv4')
        if ip == None:
            raise NotImplemented

        re = self.routeTable.getRoute(ip.dstip)
        if re == None:
            (k,_) = self.routeTable.getDefaultRoute()
        else:
            k,_ = re
        #log.warning(re)

        
        kk,mac,out = self.gates.getDpidMacPort(k)
        if sloc != kk:#g[ipstr_to_int(k)]['dpid']:
            print 'real dpid = %d, hope dpid = %d' % (sloc, kk)
            raise NotImplemented

        flow[core.NW_DST] = ip.dstip
        flow[core.IN_PORT] = inport
        
        actions = [[of.OFPAT_OUTPUT,[0,out]]]
        self.install_datapath_flow(sloc,flow,10,10,actions,bufid,of.OFP_DEFAULT_PRIORITY,inport)

        
        #reverse flow
        attrs = {}

        attrs[core.NW_DST] = ip.srcip#g[k]['port'] 
        attrs[core.IN_PORT] = out
        actions = [[of.OFPAT_OUTPUT,[0,inport]]]
        
        self.install_datapath_flow(sloc,attrs,10,10,actions)        


    def handleDhcp(self,sloc,inport,bufid,packet):
        '''We can just ignore it, leave it to a local module pyswitch
        '''
        attrs = {}
        (dh_dpid,tmip,dh_port) = self.gates.getDhcp()
        if dh_dpid != sloc:
            print sloc,"  ", dh_dpid
            raise NotImplemented
        
        #send
        attrs[core.IN_PORT] = inport
        attrs[core.DL_SRC] = packet.src
        attrs[core.NW_PROTO] = ipv4.UDP_PROTOCOL
        attrs[core.TP_DST] = 67#dhcp.SERVER_PORT
        actions = [[of.OFPAT_OUTPUT,[0,dh_port]]]
        
        #install here
        self.install_datapath_flow(sloc,attrs,CACHE_TIMEOUT,CACHE_TIMEOUT,actions,bufid,of.OFP_DEFAULT_PRIORITY,inport)
        
        'reversed flow'
        attrs[core.IN_PORT] = dh_port
        attrs[core.DL_DST] = packet.src #attrs[core.DL_SRC]
        del attrs[core.DL_SRC]
        attrs[core.NW_PROTO] = ipv4.UDP_PROTOCOL
        attrs[core.TP_DST] = 68#dhcp.CLIENT_PORT
        #attrs[core.TP_SRC] = 67#dhcp.SERVER_PORT
        actions = [[of.OFPAT_OUTPUT,[0,inport]]]
        self.install_datapath_flow(sloc,attrs,0,0,actions,None,of.OFP_DEFAULT_PRIORITY,None)

    def getRoute(self):
        '''Find a route, To gateway or local or cached server
        '''
        raise NotImplemented
        


    def getInterface(self):
        return str(pyhroute)

def reverseFlow(flow):
    ''' to contruct a reverse flow, every field must be filled
    '''
    attrs = {}
    attrs[core.DL_SRC] = flow[core.DL_DST]
    attrs[core.DL_DST] = flow[core.DL_SRC]
    attrs[core.DL_TYPE] = flow[core.DL_TYPE]
    
    'vlan'
    attrs[core.DL_VLAN] = flow[core.DL_VLAN]
    attrs[core.DL_VLAN_PCP] = flow[core.DL_VLAN_PCP]

    'network layer'

    attrs[core.NW_SRC] = flow[core.NW_DST]
    attrs[core.NW_DST] = flow[core.NW_SRC]
    attrs[core.NW_TOS] = flow[core.NW_TOS]
    attrs[core.NW_PROTO] = flow[core.NW_PROTO]

    "transport layer"
    attrs[core.TP_SRC] = flow[core.TP_DST]
    attrs[core.TP_DST] = flow[core.TP_SRC]

    return attrs
    


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return pyhroute(ctxt)

    return Factory()


