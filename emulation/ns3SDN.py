#!/usr/bin/python -i
# vim:ts=2:expandtab:shiftwidth=2
#
#  Copyright 2013 Claudio Pisa, Andrea Detti
#
#  This file is part of wmSDN
#
#  wmSDN is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  wmSDN is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with wmSDN.  If not, see <http://www.gnu.org/licenses/>.
#

'''
ns3wifi.py - This script demonstrates using CORE with the ns-3 Wifi model.

How to run this:

    pushd ~/ns-allinone-3.16/ns-3.16
    sudo ./waf shell
    popd
    python -i ns3wifi.py

To run with the CORE GUI:

    pushd ~/ns-allinone-3.16/ns-3.16
    sudo ./waf shell
    cored
    
    # in another terminal
    cored -e ./ns3wifi.py
    # in a third terminal
    core
    # now select the running session

'''

import os, sys, time, optparse, datetime, math
try:
    from core import pycore 
except ImportError:
    # hack for Fedora autoconf that uses the following pythondir:
    if "/usr/lib/python2.6/site-packages" in sys.path:
        sys.path.append("/usr/local/lib/python2.6/site-packages")
    if "/usr/lib64/python2.6/site-packages" in sys.path:
        sys.path.append("/usr/local/lib64/python2.6/site-packages")
    if "/usr/lib/python2.7/site-packages" in sys.path:
        sys.path.append("/usr/local/lib/python2.7/site-packages")
    if "/usr/lib64/python2.7/site-packages" in sys.path:
        sys.path.append("/usr/local/lib64/python2.7/site-packages")
    from core import pycore

import ns.core
from core.misc import ipaddr 
from core.misc.ipaddr import MacAddr
from corens3.obj import Ns3Session, Ns3WifiNet, CoreNs3Net
import coreconf

# python interactive shell tab autocompletion
import rlcompleter, readline
readline.parse_and_bind('tab:complete')

def add_to_server(session):
    ''' Add this session to the server's list if this script is executed from
    the cored server.
    '''
    global server
    try:
        server.addsession(session)
        return True
    except NameError:
        return False

def wifisession(opt):
    ''' Run a test wifi session.
    '''
    #myservice = "Olsrd4Service"
    myservice = "OpenvswitchService"
    #myservice = "OpenflowService"
    numWirelessNode=6;
    numWiredNode=5;
    ns.core.Config.SetDefault("ns3::WifiMacQueue::MaxPacketNumber",ns.core.UintegerValue(100)) 
    session = Ns3Session(persistent=True, duration=opt.duration)
    session.cfg['openvswitch_dir'] = coreconf.openvswitch_dir
    session.cfg['olsr_dir'] = coreconf.olsr_dir
    session.cfg['olsrd_dir'] = coreconf.olsrd_dir
    session.name = "ns3SDN"
    session.filename = session.name + ".py"
    session.node_count = str(numWirelessNode + numWiredNode + 1)
    session.services.importcustom(coreconf.custom_services_dir)
    add_to_server(session)
    
    wifi = session.addobj(cls=Ns3WifiNet, name="wlan1", rate="OfdmRate54Mbps")
    #wifi.wifi.SetStandard(ns.wifi.WIFI_PHY_STANDARD_80211b)
    #wifi.wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",ns.core.StringValue("DsssRate11Mbps"), "NonUnicastMode", ns.core.StringValue("DsssRate11Mbps"))
    wifi.setposition(30, 30, 0)
    wifi.phy.Set("RxGain", ns.core.DoubleValue(20.0))
    prefix = ipaddr.IPv4Prefix("10.0.0.0/16")
    
    hub1 = session.addobj(cls=pycore.nodes.HubNode, name="hub1")
    hub1.setposition(450,300,0)
    ptp1 = session.addobj(cls=pycore.nodes.PtpNet, name="ptp1") 
    ptp2 = session.addobj(cls=pycore.nodes.PtpNet, name="ptp2") #controller network
    
    nodes = []
    def ourmacaddress(n):
        return MacAddr.fromstring("02:02:00:00:00:%02x" % n)
    
    node = session.addnode(name = "n1")
    node.newnetif(wifi, ["%s/%s" % (prefix.addr(1), prefix.prefixlen)], hwaddr=ourmacaddress(1))
    node.newnetif(ptp1,["192.168.1.2/24"])
    session.services.addservicestonode(node,"router",myservice,verbose=True)
    session.services.bootnodeservices(node)
    nodes.append(node)

    for i in xrange(2, numWirelessNode-2 + 1):
        node = session.addnode(name = "n%d" % i)
        node.newnetif(wifi, ["%s/%s" % (prefix.addr(i), prefix.prefixlen)], hwaddr=ourmacaddress(i))
        if i == 3: #the wireless node which is attached to the controller
                node.newnetif(ptp2,["10.100.100.2/24"])
        session.services.addservicestonode(node,"router",myservice,verbose=True)
        session.services.bootnodeservices(node)
        nodes.append(node)
    
    node = session.addnode(name = "gw5")
    node.newnetif(wifi, ["%s/%s" % (prefix.addr(5), prefix.prefixlen)], hwaddr=ourmacaddress(5))
    node.newnetif(hub1,["192.168.200.5/24"])
    session.services.addservicestonode(node,"router",myservice,verbose=True)
    session.services.bootnodeservices(node)
    nodes.append(node)
    
    node = session.addnode(name = "gw6")
    node.newnetif(wifi, ["%s/%s" % (prefix.addr(6), prefix.prefixlen)], hwaddr=ourmacaddress(6))
    node.newnetif(hub1,["192.168.200.6/24"])
    session.services.addservicestonode(node,"router",myservice,verbose=True)
    session.services.bootnodeservices(node)
    nodes.append(node)
    
    node = session.addnode(name = "client")
    node.newnetif(hub1,["192.168.200.1/24"])
    node.addaddr(0, "192.168.200.11/24")
    node.addaddr(0, "192.168.200.12/24")
    node.addaddr(0, "192.168.200.13/24")
    node.addaddr(0, "192.168.200.14/24")
    node.addaddr(0, "192.168.200.15/24")
    nodes.append(node)
    
    node = session.addnode(name = "server")
    node.newnetif(ptp1,["192.168.1.1/24"])
    nodes.append(node)
    
    node = session.addnode(name = "controller")
    node.newnetif(ptp2,["10.100.100.100/24"])
    nodes.append(node)
    
    session.setupconstantmobility()
    
    #n1
    nodes[0].setns3position(100,300,0)
    nodes[0].setposition(100,300,0)
    
    #n2
    nodes[1].setns3position(200,300,0)
    nodes[1].setposition(200,300,0)
    
    #n3
    nodes[2].setns3position(300,300,0)
    nodes[2].setposition(300,300,0)
    
    #n4
    nodes[3].setns3position(400,300,0)
    nodes[3].setposition(400,300,0)
    
    #gw5
    #nodes[4].setns3position(400,400,0)
    #nodes[4].setposition(400,400,0)
    nodes[4].setns3position(300,400,0)
    nodes[4].setposition(300,400,0)
    
    #gw6
    nodes[5].setns3position(400,200,0)
    nodes[5].setposition(400,200,0)
    
    #client
    nodes[6].setns3position(500,300,0)
    nodes[6].setposition(500,300,0)
    
    #server
    nodes[7].setns3position(100,200,0)
    nodes[7].setposition(100,200,0)
    
    
    
    
    
    #wifi.usecorepositions()
    # PHY tracing
    #wifi.phy.EnableAsciiAll("ns3wifi")
    
    
    session.thread = session.run(vis=False)
    
    #nodes[0].icmd(["sh", "./olsrdservice_start.sh", "start"])
    return session
    
def main():
    ''' Main routine when running from command-line.
    '''
    usagestr = "usage: %prog [-h] [options] [args]"
    parser = optparse.OptionParser(usage = usagestr)
    parser.set_defaults(duration = 600, verbose = False)

    parser.add_option("-d", "--duration", dest = "duration", type = int,
                      help = "number of seconds to run the simulation")
    parser.add_option("-v", "--verbose", dest = "verbose",
                      action = "store_true", help = "be more verbose")

    def usage(msg = None, err = 0):
        sys.stdout.write("\n")
        if msg:
            sys.stdout.write(msg + "\n\n")
        parser.print_help()
        sys.exit(err)

    (opt, args) = parser.parse_args()


    for a in args:
        sys.stderr.write("ignoring command line argument: '%s'\n" % a)

    return wifisession(opt)


if __name__ == "__main__" or __name__ == "__builtin__":
    session = main()
    print "\nsession =", session
