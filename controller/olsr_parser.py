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

import json
import networkx as nx      # apt-get install python-networkx
import urllib2
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.util import dpidToStr, strToDPID
from pox.openflow.of_json import list_switches

IP_MID = {'10.100.100.2': '10.0.0.3', '10.0.0.3': '10.100.100.2'}  # IP address aliases
ENTRANCE_GW = "10.0.0.5"  # the gateway through which stuff comes into the network

class InvalidOlsrJsonException(Exception):
  pass

class NoMacAddressException(Exception):
  pass


class oneWayLink():
  "a one-way OLSR link"
  def __init__(self, linkDict):
    if not linkDict.has_key('destinationIP') or not linkDict.has_key('lastHopIP') or not linkDict.has_key('tcEdgeCost'):
      raise InvalidOlsrJsonException
    self.__dict__.update(linkDict)

  def __repr__(self):
    return repr(self.__dict__)

class OlsrTopology():
  "an OLSR topology"
  linklist = []
  addressset = set()

  def update_topology(self):
    # download the topology
    try:
      fno = urllib2.urlopen(self.url + "/topology", timeout=180)
    except urllib2.URLError:
      return
    json_topology = ("".join(fno.readlines())).strip()
    fno.close()

    # workaround for a bug in the jsoninfo plug-in
    if json_topology[0] != "{":
      json_topology = "{" + json_topology
    topolist = json.loads(json_topology)['topology']

    # check for asymmetric links
    tmplinklist = [oneWayLink(ld) for ld in topolist]
    self.linklist = []
    for link in tmplinklist:
      reverselinks = [lnk for lnk in tmplinklist if lnk.destinationIP == link.lastHopIP and lnk.lastHopIP == link.destinationIP]
      assert len(reverselinks) == 1
      self.linklist.append(link)
    
    #TODO: download also MIDs

    self.addressset = set([lnk.destinationIP for lnk in self.linklist] + [lnk.lastHopIP for link in self.linklist])

  def update_gateways(self):
    try:
      fno = urllib2.urlopen(self.url + "/hna")
    except urllib2.URLError:
      return
    json_topology = "".join(fno.readlines())

    # workaround for a bug in the jsoninfo plug-in
    if json_topology[0] != "{":
      json_topology = "{" + json_topology
    self.hnalist = json.loads(json_topology)['hna']
    fno.close()

    self.gatewaylist = [hna['gateway'] for hna in self.hnalist if hna['destination'] == "0.0.0.0"]

  def __init__(self, url):
    self.url = url
    self.addresset = set()
    self.gatewaylist = []
    self.update_topology()
    self.update_gateways()

  def update(self):
    self.update_topology()
    self.update_gateways()
 
  def is_in_topology(self, address):
    "returns true if the given IP address is a node of the topology graph"
    return address in self.addressset

  def is_gateway(self, address):
    return address in self.gatewaylist

  def get_gateway_list(self):
    return self.gatewaylist

  def get_shortest_path(self, source, destination):
    G = nx.DiGraph()
    self.update()
    G.add_weighted_edges_from([(link.lastHopIP, link.destinationIP, link.tcEdgeCost) for link in self.linklist])
    if self.is_in_topology(source) and self.is_in_topology(destination):
      return nx.shortest_path(G, source, destination)
    elif self.is_in_topology(source):
      # find the closest gateway
      closestgw = None
      cost = 0
      for gw in self.gatewaylist:
        try:
          splen = nx.shortest_path_length(G, source, gw)
        except nx.NetworkXNoPath:
          return None
        if splen > cost:
          cost = splen
          closestgw = gw
      if closestgw:
        return nx.shortest_path(G, source, closestgw)
      else:
        return None
    elif self.is_in_topology(destination):
      # should this happen?
      res = self.get_shortest_path(destination, source)
      res.reverse()
      return res

  def get_shortest_path_through_gateways(self, source):
    "return the path lengths to the source ip address to all the gateways"
    G=nx.DiGraph()
    G.add_weighted_edges_from([(link.lastHopIP, link.destinationIP, link.tcEdgeCost) for link in self.linklist])
    
    paths_length=dict()
    for gw in self.gatewaylist:
      paths_length[gw]=nx.dijkstra_path_length(G, source, gw)

    return paths_length

  def find_closest_olsr_node(self, ipaddress): 
    """returns the closest OLSR node, i.e. the given IP address if it's 
    an OLSR router, or if the IP address belongs to an HNA, one of the 
    OLSR nodes that is announcing it"""
    if self.is_in_topology(ipaddress):
      return ipaddress
    for hna in self.hnalist:
      if hna['genmask'] != 24: # assuming HNAs are /24 #FIXME
        continue
      hna_bytes = hna['destination'].split('.')
      ipa_bytes = ipaddress.split('.')
      res = True
      for i in range(3):
        res = res and hna_bytes[i] == ipa_bytes[i]
      if res:
        return hna['gateway']
    # not found
    return None

class OpenFlowOlsrHelper():
  "a class that helps the controller with OLSR stuff"
  def __init__(self, url, logger):
    self.topology = OlsrTopology(url)
    self.priority = 10000
    self.switchdict = {}
    self.ip2switchdict = {}
    self.log = logger

  def updateSwitchInfo(self, event):
    "update switch information"
    remoteip, remoteport = event.connection.sock.getpeername()
    self.switchdict.update({dpidToStr(event.dpid): event.connection})
    self.ip2switchdict.update({remoteip: dpidToStr(event.dpid)})

  def ip2switchId(self, ip_address):
    "given an IP address return the switch id"
    #TODO: not 100% sure that the keys of this dict are the switch ids
    for switchid, connection in core.openflow._connections.items():  
      switchip = connection.sock.getpeername()[0]
      if switchip == ip_address:
        return switchid
      if IP_MID.has_key(ip_address) and switchip == IP_MID[ip_address]:
        return switchid
    return -1

  def switchId2Connection(self, switchid):
    try:
      res = self.switchdict[switchid]
    except KeyError:
      res = None
    return res

  def ip2mac(self, ip_address):
    "given an IP address return the corresponding wireless MAC address"
    try:
      #self.log.debug("search for the wireless MAC address of %s" % ip_address)
      #res = "02:02:00:00:00:%02x" % int(ip_address.split(".")[3])
      res = "00:00:00:00:00:%02x" % int(ip_address.split(".")[3])
    except IndexError:
      raise NoMacAddressException
    return res

  def ip2nexthopsmac(self, src_address, dst_address):
    "return the MAC address of the nexthop on the path from src_address to dst_address"
    path = self.topology.get_shortest_path(src_address, dst_address)
    if not path: 
      return None    # empty path
    nexthop = path[1]
    return self.ip2mac(nexthop)

  def isSwitch(self, ip_address):
    "return true if the given IP address belongs to an Openflow switch"
    return ip_address.startswith("10.0.0.")

  def isGateWay(self, ip_address):
    "return True if the given IP address belongs to a Gateway"
    return self.topology.is_gateway(ip_address)

  def getPortInfo(self, switchid, port_name_or_number=None):
    "return a port object carrying port info, or by omitting the port_name_or_number the whole switch info object"
    req_switch_info = None
    for s in list_switches():
      if strToDPID(s['dpid']) == switchid:
        req_switch_info = s
        break

    if not req_switch_info:
      self.log.debug("info for switch %s not found" % switchid)
      return None

    if port_name_or_number == None:
      return req_switch_info

    if type(port_name_or_number) == int:
      for p in req_switch_info['ports']:
        if p['port_no'] == port_name_or_number:
          return p
    else:
      for p in req_switch_info['ports']:
        if p['name'] == port_name_or_number:
          return p

    self.log.debug("info for port %s on switch %s not found" % (port_name_or_number, switchid))
    return None

  def genRule(self, hop, nexthop, source, destination, first=False, last=False, cookie=0x0c):
    """generate a list of openflow rules

       first: hop is the first hop
       last: nexthop is the last hop
       returngateway: hop is a gateway on the return path
    
    """
    #DEFAULT_HARD_TIMEOUT = of.OFP_FLOW_PERMANENT
    #DEFAULT_HARD_TIMEOUT = 0
    #DEFAULT_IDLE_TIMEOUT = of.OFP_FLOW_PERMANENT
    DEFAULT_IDLE_TIMEOUT = 60

    if not self.isSwitch(hop):
      return []

    orules = []
    try:
      if first:
        orule = of.ofp_flow_mod(
            command = of.OFPFC_ADD,
            priority = self.priority,
            idle_timeout = DEFAULT_IDLE_TIMEOUT,
            #hard_timeout = DEFAULT_HARD_TIMEOUT,
            #flags= of.OFPFF_CHECK_OVERLAP,
            cookie = cookie,
            match = of.ofp_match(
              dl_type = 0x800,
              nw_src = IPAddr(source),
              nw_dst = IPAddr(destination),
              #dl_dst = of.EthAddr(self.ip2mac(nexthop)),
              in_port = of.OFPP_LOCAL
              ),
            )
        oactions = [of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_DST, dl_addr = self.ip2mac(nexthop)),
                    of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_SRC, dl_addr = self.ip2mac(hop)),
                    of.ofp_action_output(port = of.OFPP_ALL)]
        orule.actions = oactions
        orule.switchip = hop
        orules.append(orule)
      
      elif last or self.isGateWay(hop):
        localport = self.getPortInfo(self.ip2switchId(hop), of.OFPP_LOCAL) 

        orule = of.ofp_flow_mod(
            command = of.OFPFC_ADD,
            priority = self.priority,
            idle_timeout = DEFAULT_IDLE_TIMEOUT,
            #hard_timeout = DEFAULT_HARD_TIMEOUT,
            #flags= of.OFPFF_CHECK_OVERLAP,
            cookie = cookie,
            match = of.ofp_match(
              dl_type = 0x800,
              nw_src = IPAddr(source),
              nw_dst = IPAddr(destination),
              # matching all the switch MAC addresses here would be better
              ),
            )

        oactions = []
        try:
          oactions.append(of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_DST, dl_addr = localport['hw_addr']))
        except TypeError:
          pass

        oactions.append(of.ofp_action_output(port = of.OFPP_LOCAL))

        orule.actions = oactions
        orule.switchip = hop
        orules.append(orule)

      else:
        # Needed for HNAs
        orule = of.ofp_flow_mod(
            command = of.OFPFC_ADD,
            priority = self.priority,
            idle_timeout = DEFAULT_IDLE_TIMEOUT,
            #hard_timeout = DEFAULT_HARD_TIMEOUT,
            #flags= of.OFPFF_CHECK_OVERLAP,
            cookie = cookie,
            match = of.ofp_match(
              dl_type = 0x800,
              nw_src = IPAddr(source),
              nw_dst = IPAddr(destination),
              in_port = of.OFPP_LOCAL
              ),
            )
        oactions = []
        try:
          oactions.append(of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_DST, dl_addr = self.ip2mac(nexthop)))
          oactions.append(of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_SRC, dl_addr = self.ip2mac(hop)))
          wirelessport = self.getPortInfo(self.ip2switchId(hop), "eth0") #TODO: parametrize
          if wirelessport != None and wirelessport.has_key('port_no'):
            oactions.append(of.ofp_action_output(port = wirelessport['port_no']))
            orule.actions = oactions
            orule.switchip = hop
            orules.append(orule)
          else:
            self.log.warn("No wireless port info for %s?" % hop)
        except Exception, e:
          self.log.warn("HNA rule problem (%s -> %s): %s" % (hop, nexthop, e))

        self.priority += 1

        # intermediate node
        orule = of.ofp_flow_mod(
            command = of.OFPFC_ADD,
            priority = self.priority,
            idle_timeout = DEFAULT_IDLE_TIMEOUT,
            #hard_timeout = DEFAULT_HARD_TIMEOUT,
            #flags= of.OFPFF_CHECK_OVERLAP,
            cookie = cookie,
            match = of.ofp_match(
              dl_type = 0x800,
              nw_src = IPAddr(source),
              nw_dst = IPAddr(destination),
              dl_dst = of.EthAddr(self.ip2mac(hop))
              ),
            )
        oactions = [of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_DST, dl_addr = self.ip2mac(nexthop)),
                    of.ofp_action_dl_addr(type = of.OFPAT_SET_DL_SRC, dl_addr = self.ip2mac(hop)),
                    of.ofp_action_output(port = of.OFPP_IN_PORT)]

        orule.actions = oactions
        orule.switchip = hop
        orules.append(orule)

      self.priority += 1
      if self.priority>11000 :
          self.priority=10000

    except NoMacAddressException:
      orules = []
    return orules

  def computeCookie(self, ipaddress):
    "use the last byte of the IP address to compute a controller (0xc) cookie"
    return int("0x%02x0c" % int(ipaddress.split('.')[-1]), 16)

  def path2OpenFlowRules(self, src, gw, dst):
    """
    src: source IP address
    gw: chosen gateway's IP address
    dst: destination IP address

    compute the path from firstswitch to gw, then the matches and actions to be installed on OpenFlow switches
    return a couple (rules, gwwasused) where rules is a list of openflow rules, and gwwasused is a boolean that
    is True iif the gateway was actually used in the computation
    """
    cookie = self.computeCookie(gw)
    # first openflow switch on the path
    firstswitch = self.topology.find_closest_olsr_node(src)
    if firstswitch != None:
      self.log.debug("first switch: %s" % firstswitch)
      path = self.topology.get_shortest_path(firstswitch, gw)
      reverse = False
    else:
      lastswitch = self.topology.find_closest_olsr_node(dst)
      self.log.debug("last switch: %s" % lastswitch)
      if lastswitch == None:
        return ([], False)
      path = self.topology.get_shortest_path(ENTRANCE_GW, lastswitch)
      reverse = True
    res = []
    hops = zip(path, path[1:] + [""])
    self.log.debug(hops)
    source = src
    destination = dst
    # first hop on the path
    n0, m0 = hops[0]
    res.extend(self.genRule(n0, m0, source, destination, first=(reverse or (n0 == src)), cookie=cookie))
    for (n,m) in hops[1:-1]:
      res.extend(self.genRule(n, m, source, destination, cookie=cookie))
    n0, m0 = hops[-1]
    res.extend(self.genRule(n0, m0, source, destination, last=True, cookie=cookie))
    return (res, not reverse)


if __name__ == "__main__":
  t = OlsrTopology("http://127.0.0.1:9090")
  print t.is_in_topology("10.0.0.4")
  print t.is_in_topology("10.0.1.113")
  print t.get_shortest_path("10.0.0.2", "10.0.0.5")
  print t.is_gateway("10.0.0.5")
  print t.get_shortest_path("10.0.0.2", "10.0.1.113")

