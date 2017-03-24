""" fauxmo_minimal.py - Fabricate.IO

    This is a demo python file showing what can be done with the debounce_handler.
    The handler prints True when you say "Alexa, device on" and False when you say
    "Alexa, device off".

    If you have two or more Echos, it only handles the one that hears you more clearly.
    You can have an Echo per room and not worry about your handlers triggering for
    those other rooms.

    The IP of the triggering Echo is also passed into the act() function, so you can
    do different things based on which Echo triggered the handler.
"""
###########

## functions available for wemo
#output(switch.on())
#output(switch.off())
#output(switch.toggle())
#output(switch.status())

## For emulated wemo switch
import fauxmo
import logging
import time

from time import gmtime, strftime
from debounce_handler import debounce_handler
from subprocess import call

## for turning off/on wemo devices
import re
import urllib2

## for tplink devices
import socket
import argparse

commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
      'on'       : '{"system":{"set_relay_state":{"state":1}}}',
      'off'      : '{"system":{"set_relay_state":{"state":0}}}',
      'cloudinfo': '{"cnCloud":{"get_info":{}}}',
      'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
      'time'     : '{"time":{"get_time":{}}}',
      'schedule' : '{"schedule":{"get_rules":{}}}',
      'countdown': '{"count_down":{"get_rules":{}}}',
      'antitheft': '{"anti_theft":{"get_rules":{}}}',
      'reboot'   : '{"system":{"reboot":{"delay":1}}}',
      'reset'    : '{"system":{"reset":{"delay":1}}}'
}

def validIP(ip):
  try:
    socket.inet_pton(socket.AF_INET, ip)
  except socket.error:
    parser.error("Invalid IP Address.")
  return ip 

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
  key = 171
  result = "\0\0\0\0"
  for i in string: 
    a = key ^ ord(i)
    key = a
    result += chr(a)
  return result

def decrypt(string):
  key = 171 
  result = ""
  for i in string: 
    a = key ^ ord(i)
    key = ord(i) 
    result += chr(a)
  return result

class tplink:
  port = 9999
  def __init__(self, switch_ip):
    self.ip = switch_ip

  def off(self):
    cmd = "{\"system\":{\"set_relay_state\":{\"state\":0}}}"
    try:
      sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock_tcp.connect((self.ip, port))
      sock_tcp.send(encrypt(cmd))
      data = sock_tcp.recv(2048)
      sock_tcp.close()
      return "ok"
    except socket.error:
      print("Cound not connect to host " + self.ip + ":" + str(port))

  def on(self):
    cmd = "{\"system\":{\"set_relay_state\":{\"state\":1}}}"
    try:
      sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock_tcp.connect((self.ip, port))
      sock_tcp.send(encrypt(cmd))
      data = sock_tcp.recv(2048)
      sock_tcp.close()
      return "ok"
    except socket.error:
      print("Cound not connect to host " + self.ip + ":" + str(port))

############### main

logging.basicConfig(level=logging.DEBUG)
### This class does the switch on/off
class wemo:
  OFF_STATE = '0'
  ON_STATES = ['1', '8']
  ip = None
  ports = [49153, 49152, 49154, 49151, 49155]

  def __init__(self, switch_ip):
    self.ip = switch_ip      
   
  def toggle(self):
    status = self.status()
    if status in self.ON_STATES:
      result = self.off()
      result = 'WeMo is now off.'
    elif status == self.OFF_STATE:
      result = self.on()
      result = 'WeMo is now on.'
    else:
      raise Exception("UnexpectedStatusResponse")
    return result    

  def on(self):
    return self._send('Set', 'BinaryState', 1)

  def off(self):
    return self._send('Set', 'BinaryState', 0)

  def status(self):
    return self._send('Get', 'BinaryState')

  def name(self):
    return self._send('Get', 'FriendlyName')

  def signal(self):
    return self._send('Get', 'SignalStrength')
  
  def _get_header_xml(self, method, obj):
    method = method + obj
    return '"urn:Belkin:service:basicevent:1#%s"' % method
   
  def _get_body_xml(self, method, obj, value=0):
    method = method + obj
    return '<u:%s xmlns:u="urn:Belkin:service:basicevent:1"><%s>%s</%s></u:%s>' % (method, obj, value, obj, method)
  
  def _send(self, method, obj, value=None):
    body_xml = self._get_body_xml(method, obj, value)
    header_xml = self._get_header_xml(method, obj)
    for port in self.ports:
      result = self._try_send(self.ip, port, body_xml, header_xml, obj) 
      if result is not None:
        self.ports = [port]
      return result
    raise Exception("TimeoutOnAllPorts")

  def _try_send(self, ip, port, body, header, data):
    try:
      request = urllib2.Request('http://%s:%s/upnp/control/basicevent1' % (ip, port))
      request.add_header('Content-type', 'text/xml; charset="utf-8"')
      request.add_header('SOAPACTION', header)
      request_body = '<?xml version="1.0" encoding="utf-8"?>'
      request_body += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
      request_body += '<s:Body>%s</s:Body></s:Envelope>' % body
      request.add_data(request_body)
      result = urllib2.urlopen(request, timeout=3)
      return self._extract(result.read(), data)
    except Exception as e:
      print str(e)
      return None

  def _extract(self, response, name):
    exp = '<%s>(.*?)<\/%s>' % (name, name)
    g = re.search(exp, response)
    if g:
      return g.group(1)
    return response

def output(message):
  print message

  ### This class acts like a wemo switch

class device_handler(debounce_handler):
  """Publishes the on/off state requested,
    and the IP address of the Echo making the request.
  """
  TRIGGERS = {"hal": 52000, "sal" : 52001, "kit" : 52002, "lights" : 52003 }

  def act(self, client_address, state, name):

    print strftime("%Y-%m-%d %H:%M:%S", gmtime()), "State", state, "on ", name, "from Alexa @", client_address
    # True is on
    if name == 'sal':
      if state == True:
        print "Turning on SAL"
        call(["sudo","etherwake","-i","eth0","xxx"])
      if state == False:
        print "Turning off SAL"
        call(["ssh","sal","sudo","shutdown","-h","now"])
    if name == 'hal':
      if state == True:
        print "Turning on HAL"
        call(["sudo","etherwake","-i","eth0","xxx"])
      if state == False:
        print "Turning off HAL"
        call(["ssh","hal","sudo","shutdown","-h","now"])
    if name == 'kitt':
      if state == True:
        print "Turning on KITT"
        call(["sudo","etherwake","-i","eth0","xxx"])
      if state == False:
        print "Turning off KITT"
        call(["ssh","kitt","sudo","shutdown","-h","now"])
    if name == 'lights':
      # If sent from upstairs alexa
      if client_address == "192.168.2.170":
        print "[Lights upstairs]"
        if state == True:
          switch = tplink('192.168.2.151')
          output(switch.on())
          switch = tplink('192.168.2.150')
          output(switch.on())
          switch = wemo('192.168.2.145')
          output(switch.on())        
      else:
          switch = tplink('192.168.2.151')
          output(switch.off())
          switch = tplink('192.168.2.150')
          output(switch.off())
          switch = wemo('192.168.2.145')
          output(switch.off())        
      
      # If sent from downstairs alexa
      if client_address == "192.168.2.171":
        print "[Lights downstairs]"
        if state == True:
          switch = wemo('192.168.2.144')
          output(switch.on())
        else:
          switch = wemo('192.168.2.144')
          output(switch.off())
    return True

if __name__ == "__main__":
  # Startup the fauxmo server
  fauxmo.DEBUG = True
  p = fauxmo.poller()
  u = fauxmo.upnp_broadcast_responder()
  u.init_socket()
  p.add(u)

  # Register the device callback as a fauxmo handler
  d = device_handler()
  for trig, port in d.TRIGGERS.items():
    fauxmo.fauxmo(trig, u, p, None, port, d)
  # Loop and poll for incoming Echo requests
  logging.debug("Entering fauxmo polling loop")
  while True:
    try:
      # Allow time for a ctrl-c to stop the process
      p.poll(100)
      time.sleep(0.1)
    except Exception, e:
      logging.critical("Critical exception: " + str(e))
      break

