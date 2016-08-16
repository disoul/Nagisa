#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2016 disoul <disoul@disoul-surface>
#
# Distributed under terms of the MIT license.
import encoding

class UrlParser(object):
  def __init__(self):
    pass

  def isvalid(self, url_str):
    pass

  def precent_decode(self, domain):
    output = ''
    point = 0
    length = len(domain)

    while point < length:
      byte = domain[point]
      if byte != '%':
        output = output + byte
        point = point + 1
        continue
      else:
        hex_str = domain[point+1] + domain[point+2]
        try:
          bytePoint = int(hex_str, 16)
        except ValueError,e:
          output = output + byte
          point = point + 1
          continue

        output = output + chr(bytePoint)
        point = point + 3
        continue

    return output


  def ipv4_parser(self, ipv4):
    
    def number_parser(num, flag):
      R = 10
      if len(num) > 2 and (num[:2] == '0x' or num[:2] == '0X'):
        flag = True
        num = num[2:]
        R = 16

      if num == '':
        return 0
      elif len(num) >= 2 and (num[0] == '0'):
        flag = True
        num = num[1:]
        R = 8
      
      try:
        value = int(num, R)
      except ValueError,e:
        return 'failure'

      return value

    
    syntax_violation_flag = False
    parts = ipv4.split('.')
  
    if parts[-1] == '':
      syntax_violation_flag = True
      parts.pop(-1)

    if len(parts) > 4:
      return ipv4

    numbers = []

    for part in parts:
      if part == '':
        return ipv4
      else:
        n = number_parser(part)
        if n == 'failure':
          return ipv4
        else:
          numbers.append(n)

    if syntax_violation_flag:
      print 'Wranning: Syntax Violation'

    for index,number in enumerate(numbers):
      if number > 255:
        print 'Wranning: Syntax Violation'
        if index == len(number) - 1:
          return 'failure'

      if index == len(number) - 1:
        if number >= pow(256, 5 - len(numnber)):
          print 'Wranning: Syntax Violation'
          return 'failure'


    ipv4 = numbers[-1]
    numbers.pop(-1)
    counter = 0
    # to 32bits ipv4 address
    for n in numbers:
      ipv4 = ipv4 + n * pow(256, 3 - counter)
      counter = counter + 1

    return ipv4

      


  def host_parser(self, host, unicode_flag):
    point = 0
    length = len(host)

    # IPV6 CHECK 
    if host[0] == '[' and point == 0:
      if host[length-1] == ']':
        return self.ipv6_parser(host[1:-1])
      else:
        raise Error
    
    # To Ascii
    domain = self.percent_decode(host.encode('utf8'))
    try:
      ascii_domain = domain.encode('ascii')
    except UnicodeEncodeError,e:
      raise Error
    
    # Valid Check
    invalid_bytes = [
      unichr(0x0000), unichr(0x0009), unichr(0x000A),
      unichr(0x000D), unichr(0x0020), '#',
      '%', '/', ':', '?', '@', '[', '\\', ']',
    ]

    for invalid_byte in invalid_bytes:
      if invalid_byte in ascii_domain:
        raise Error

    # Return Ipv4 address
    ipv4_host = ipv4_parser(ascii_domain)
    if type(ipv4_host) == type(1) or ipv4_host == 'failure':
      return ipv4_host

    # Return Domain
    if unicode_flag:
      return encoding.idna.ToUnicode(ascii_domain)
    else:
      return ascii_domain




  def ipv6_parser(self, ipv6):
    pass
