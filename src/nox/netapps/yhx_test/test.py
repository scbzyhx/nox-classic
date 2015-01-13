from nox.lib.core import *
import nox.lib.pyopenflow as of
from nox.coreapps.pyrt.pycomponent import *
from nox.lib.packet.packet_utils import ipstr_to_int,ip_to_str
from nox.netapps.hroute.routetable import *

from nox.lib.netinet import netinet
from nox.lib.netinet.netinet import c_ntohl
from nox.lib.util import set_match

from nox.lib.netinet import netinet



class pytest(Component):

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
        print "dpid = ",dpid
        print "stats = ",stats
        return CONTINUE
    def handlePacketIn(self,dpid,inport,reason,length,bufid,packet):
        #if packet.find('icmp') != None:
        #print "dpid = ",dpid
        print "reason = ",reason
        #print "bufid = ",bufid
        print "inport = ",inport
        #print "icmp = ", packet.find("icmp")
        flow = extract_flow(packet)
        flow[core.IN_PORT] = inport
        actions = []
            
        self.install_datapath_flow(dpid,flow,5,5,actions,bufid,of.OFP_DEFAULT_PRIORITY,inport,packet)
            
        return STOP
        


    def getInterface(self):
        return str(pytest)


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return pytest(ctxt)

    return Factory()


