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


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.revent import *
from pox.lib.addresses import IPAddr
from pox.lib.recoco import Timer
import time
import collections
from pox.openflow.of_json import *
from olsr_parser import *
from random import choice

# python interactive shell tab autocompletion
import rlcompleter, readline
readline.parse_and_bind('tab:complete')

OLSR_TOPO_URL = "http://10.100.100.2:9090"
GATEWAY_SELECTION_TIMEOUT = 60
GW_FAILURE_CHECK_INTERVAL = 3
CONTROLLER_IP = "10.100.100.100"

log = core.getLogger()

def decode_packet(pkt, log):
  "try to dissect pkt and output some info on the log"
  if pkt.type == pkt.ARP_TYPE:
    if pkt.payload.opcode == of.arp.REQUEST:
      log.debug("ARP request")
    else:
      log.debug("ARP packet")
  elif pkt.type == pkt.IP_TYPE:
    ippkt = pkt.payload
    if ippkt.protocol == ippkt.ICMP_PROTOCOL:
      log.debug("ICMP from %s to %s" % (ippkt.srcip, ippkt.dstip))
    elif ippkt.protocol == ippkt.TCP_PROTOCOL:
      try:
         log.debug("TCP from %s to %s dport %d" % (ippkt.srcip, ippkt.dstip, ippkt.payload.dstport))
      except AttributeError:
         log.debug("TCP from %s to %s" % (ippkt.srcip, ippkt.dstip))
    elif ippkt.protocol == ippkt.UDP_PROTOCOL:
      log.debug("UDP from %s to %s dport %d" % (ippkt.srcip, ippkt.dstip, ippkt.payload.dstport))
    else:
      log.debug("IP protocol: 0x%02x" % pkt.payload.protocol)
  else:
    log.debug("Unknown ethernet type 0x%04x" % pkt.type)

class GwSelectionInfo():
  def __init__(self, flowkey, selectedgateway):
    self.flowkey = flowkey
    self.selectedgateway = selectedgateway
    self.selectiontime = time.time()
    self.rulelist = []
  def getGateway(self):
    if time.time() - self.selectiontime < GATEWAY_SELECTION_TIMEOUT:
      return None
    else:
      return self.selectedgateway
  def addRules(self, rulelist):
    assert type(rulelist) == type([])
    self.rulelist = rulelist[:]
    self.selectiontime = time.time()
  def getRules(self):
    "returns None if time has expired"
    if time.time() - self.selectiontime > GATEWAY_SELECTION_TIMEOUT:
      return None
    return self.rulelist
  def getAllRules(self):
    "returns also the expired rules"
    return self.rulelist
  def delRules(self):
    self.rulelist = []
    
class PathSelectionCollection():
  def __init__(self):
    self.gwselections = {}
  def addOrUpdateGw(self, flowkey, gateway):
    self.gwselections[flowkey] = GwSelectionInfo(flowkey, gateway)
  def getGwSelectionInfo(self, flowkey):
    if self.gwselections.has_key(flowkey):
      return self.gwselections[flowkey]
    else:
      return None
  def getGw(self, flowkey):
    gwinfo = self.getGwSelectionInfo(flowkey)
    if gwinfo == None:
      return None
    return gwinfo.getGateway()
  def addRules(self, flowkey, gateway, rulelist):
    "store a list of computed flow rules"
    assert type(rulelist) == type([])
    if not self.gwselections.has_key(flowkey):
      self.gwselections[flowkey] = GwSelectionInfo(flowkey, gateway)
    self.gwselections[flowkey].addRules(rulelist)
  def getRulesForSwitch(self, switchip, flowkey):
    """return rules to be installed on a switch, matching the given flow key.
       Returning None means that the flowkey does not match or that the time has 
       expired, while returning an empty list means that there are no precomputed 
       rules for the given switch IP
    """
    if not self.gwselections.has_key(flowkey):
      log.debug("getRulesForSwitch: flow does not match")
      return None 
    res = []
    gwinfo = self.gwselections[flowkey]
    rules = gwinfo.getRules()
    if rules == None:
      log.debug("getRulesForSwitch: expired rules")
      return None
    for rule in rules:
      if rule.switchip == switchip or (IP_MID.has_key(switchip) and IP_MID[switchip] == rule.switchip):
        res.append(rule)
    log.debug("getRulesForSwitch: good rules (%d)" % len(res))
    return res
  def getRulesForGw(self, gwip):
    """return all the rules that match the given gateway ip address"""
    log.debug("get rules for %s" % gwip)
    res = []
    for gwinfo in self.gwselections.values():
      if gwinfo.selectedgateway == gwip:
        res.extend(gwinfo.getAllRules())
    return res
  def getAllRules(self):
    """return all the rules"""
    res = []
    for gwinfo in self.gwselections.values():
      res.extend(gwinfo.getAllRules())
    return res
  def deleteRulesForGw(self, gwip):
    """delete all the stored rules for a given gateway"""
    self.gwselections = {flowid: gwinfo for flowid, gwinfo in self.gwselections.iteritems() if gwinfo.selectedgateway != gwip}
  def deleteAllRules(self):
    """delete all the stored rules"""
    self.gwselections = {}

def pushRulesToSwitch(connection, rulelist):
  "install a set of rules using a connection to a switch"
  log.debug("Installing %d rules on switch %s" % (len(rulelist), connection.sock.getpeername()[0]))
  for rule in rulelist:
    connection.send(rule)
  connection.send(of.ofp_barrier_request())

class GwSwOlsrdSwitch (object):
  def __init__ (self):
    core.openflow.clear_flows_on_connect = False
    core.openflow.addListeners(self)
    self.helper = OpenFlowOlsrHelper(OLSR_TOPO_URL, log)
    log.info("Number of links in topology: %d" % len(self.helper.topology.linklist))
    self.gatewayselections = PathSelectionCollection()
    self.rr_lastchosengw = 0
    self.gwset = set(self.helper.topology.gatewaylist)

  def _handle_ConnectionUp(self, event):
    remoteip, remoteport = event.connection.sock.getpeername()
    log.debug("Switch %s (%s:%d) connected." % (dpidToStr(event.dpid), remoteip, remoteport))
    #self.helper.updateSwitchInfo(event)
    for port in event.ofp.ports:
      log.debug("%d %s %s" % (port.port_no, port.name, port.hw_addr))

  def _handle_PacketIn(self, event):
    remoteip, remoteport = event.connection.sock.getpeername()
    firstswitch = str(remoteip)
    pkt = event.parsed
    log.debug("packet in from %s type 0x%04x src %s dst %s" % (dpidToStr(event.dpid), pkt.type, pkt.src, pkt.dst))

    # output some info on the received packet
    decode_packet(pkt, log)
    
    if str(pkt.dst) == "ff:ff:ff:ff:ff:ff":
      log.debug("broadcast packet, do nothing")
      return
    
    if pkt.type == pkt.IP_TYPE:
       ippkt = pkt.payload
       srcip = str(ippkt.srcip)
       dstip = str(ippkt.dstip)

       if srcip == CONTROLLER_IP:
         return

       #let's see if we already have some rules for this flow and this switch
       previousrules = self.gatewayselections.getRulesForSwitch(remoteip, (srcip, dstip))
       if previousrules == None:
         # no rules or rules have expired: compute rules for this flow and install them
         assert self.gatewayselections.getGw((srcip,dstip)) == None
         #chosengateway = "10.0.0.5"
         #chosengateway = right_gateway(remoteip) 
         chosengateway = self.round_robin_gateway(srcip, dstip)
         log.debug("!!!!!! GATEWAY : %s ",chosengateway)
         if chosengateway != None and not (self.helper.topology.is_in_topology(srcip) and self.helper.topology.is_in_topology(dstip)):
           # path2OpenFlowRules(<source address>, <chosen gateway>, <destination address>)
           newrules, gwwasused = self.helper.path2OpenFlowRules(srcip, chosengateway, dstip)
           # check if the gateway was useful. If it was, advance the round robin.
           if gwwasused:
             self.gatewayselections.addRules((srcip, dstip), chosengateway, newrules)
             self.round_robin_gateway_advance()
           else:
             self.gatewayselections.addRules((srcip, dstip), ENTRANCE_GW, newrules)
           con = event.connection # connection to the switch that sent us this packetIn
           switchrules = self.gatewayselections.getRulesForSwitch(remoteip, (srcip, dstip)) # rules for this switch
           # install the rules
           pushRulesToSwitch(con, switchrules)
       else:
         if len(previousrules) > 0:
           # install the previous rules
           con = event.connection 
           pushRulesToSwitch(con, previousrules)
         else:
           # no rules for this switch, do nothing here
           pass

    # packet out 
    msg = of.ofp_packet_out(data = event.parsed, in_port = event.port)
    msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
    event.connection.send(msg)
    log.debug("packet out")

  def _handle_ConnectionClosed(self, event):
    remoteip, remoteport = event.connection.sock.getpeername()
    log.debug("Switch %s (%s:%d) disconnected." % (dpidToStr(event.dpid), remoteip, remoteport))

  def _handle_ConnectionDown(self, event):
    remoteip, remoteport = event.connection.sock.getpeername()
    log.debug("Switch %s (%s:%d) down." % (dpidToStr(event.dpid), remoteip, remoteport))

  def round_robin_gateway(self, srcip, dstip):
    if len(self.helper.topology.gatewaylist) < 1:
      return None
    nextgw = (self.rr_lastchosengw + 1) % len(self.helper.topology.gatewaylist)
    return self.helper.topology.gatewaylist[nextgw]

  def round_robin_gateway_advance(self):
    nextgw = (self.rr_lastchosengw + 1) % len(self.helper.topology.gatewaylist)
    self.rr_lastchosengw = nextgw

  def getFreshConnectionDict(self, failedswitches=[]):
    """check connections to the controller, delete dead connections and return 
    a dictionary with active connections, including aliases.
    failedswitches is an optional list of known failed switches"""
    connectiondict = {}
    deadconnections = []
    for switchid, con in core.openflow._connections.iteritems():
      try:
        conaddress = con.sock.getpeername()[0]
      except:
        con.sock.close()
        deadconnections.append(switchid)
        continue
      if not conaddress in failedswitches and not (IP_MID.has_key(conaddress) and IP_MID[conaddress] in failedswitches):
        connectiondict[conaddress] = con
    for alias, value in IP_MID.iteritems():
      if connectiondict.has_key(value):
        connectiondict[alias] = connectiondict[value]
    # clean all dead connections
    for switchid in deadconnections:
      del core.openflow._connections[switchid]
    return connectiondict

  def check_gw_failures(self):
    log.debug("old gateway set: %s" % self.gwset)
    log.debug("topology update")
    self.helper.topology.update()
    newgwset = set(self.helper.topology.gatewaylist)
    log.debug("new gateway set: %s" % newgwset)
    failedgws = list(self.gwset.difference(newgwset))
    newgws = list(newgwset.difference(self.gwset))
    if len(failedgws) > 0 or len(newgws) > 0:
      connectiondict = self.getFreshConnectionDict(failedswitches=failedgws)
      log.debug("connectiondict: %d items" % len(connectiondict.values()))
      rules = self.gatewayselections.getAllRules()
      if rules != None:
        # delete all the rules stored in the controller
        self.gatewayselections.deleteAllRules()
        log.debug("rules: %d items" % len(rules))
        for rule in rules:
          rule.command = of.OFPFC_DELETE_STRICT
          if connectiondict.has_key(rule.switchip):
            log.debug("send deletion rule to switch %s" % rule.switchip)
            con = connectiondict[rule.switchip]
            con.send(rule)
          else:
            log.debug("no connection found for %s" % rule.switchip)
      else:
        log.debug("no rules to update?!")
    self.gwset = newgwset

  def delete_rules_on_all_switches(self, cookie):
    "delete rules matching the given cookie on all switches"
    # XXX: this does not work, it just deletes all the rules :(
    m = of.ofp_match()
    m.cookie = cookie
    dr = of.ofp_flow_mod(
          command = of.OFPFC_DELETE,
          cookie = cookie,
          match = m
        )
    for con in core.openflow._connections.values():
      con.send(dr)

def _con_func ():
  log.debug([str(con) for con in core.openflow._connections])

def gw_failure_monitoring():
  go = core.components['GwSwOlsrdSwitch']
  go.check_gw_failures()

def launch ():
  core.registerNew(GwSwOlsrdSwitch)
  Timer(5, _con_func, recurring = True)
  Timer(GW_FAILURE_CHECK_INTERVAL, gw_failure_monitoring, recurring = True)

