#!/usr/bin/env python
# 
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#  
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
#
import socket
import argparse

version = 0.1

# Check if IP is valid
def validIP(ip):
  try:
    socket.inet_pton(socket.AF_INET, ip)
  except socket.error:
    parser.error("Invalid IP Address.")
  return ip 

# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
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


ip = '192.168.2.151'
port = 9999
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
      print("Cound not connect to host " + ip + ":" + str(port))

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
      print("Cound not connect to host " + ip + ":" + str(port))


def output(message):
  print message

# Send command and receive reply 
switch = tplink(ip)  
output(switch.off())

