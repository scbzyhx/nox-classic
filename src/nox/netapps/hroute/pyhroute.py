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

#def recv_packet)


class pyhroute(Component):

    def __init__(self, ctxt):
        self.ctxt_ = ctxt
        Component.__init__(self, ctxt)

    def install(self):
        '''start a thread to receive message from victim servers
           and response to the request
        '''
        self.register_for_datapath_join(self.handleDatapathJoinIn)
        self.register_for_packet_in(self.handlePacketIn)
        
        

    def handleDatapathJoinIn(self,dpid,stats):
        '''datapath_join_in event handler
        '''
        return CONTINUE

        

    def getInterface(self):
        return str(pyhroute)
    


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return pyhroute(ctxt)

    return Factory()


