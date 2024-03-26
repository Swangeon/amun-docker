"""
[Amun - low interaction honeypot]
Copyright (C) [2008]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import struct
import random
import dns_shellcodes

class vuln:

	def __init__(self):
		try:
			self.vuln_name = "DNS Vulnerability"
			self.stage = "DNS_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
		except KeyboardInterrupt:
			raise

	def print_message(self, data):
		print "\n"
		counter = 1
		for byte in data:
			if counter==16:
				ausg = hex(struct.unpack('B',byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split('x')
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg
				else:
					print ausg
				counter = 0
			else:
				ausg = hex(struct.unpack('B',byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split('x')
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg,
				else:
					print ausg,
			counter += 1
		print "\n>> %s Incoming Codesize: %s\n\n" % (self.vuln_name, len(data))

	def getVulnName(self):
		return self.vuln_name

	def getCurrentStage(self):
		return self.stage

	def getWelcomeMessage(self):
                return self.welcome_message

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			self.reply = []
			for i in range(0,510):
				try:
					self.reply.append("\x00")
				except KeyboardInterrupt:
					raise
			resultSet = {}
			resultSet['vulnname'] = self.vuln_name
			resultSet['result'] = False
			resultSet['accept'] = False
			resultSet['shutdown'] = False
			resultSet['reply'] = "None"
			resultSet['stage'] = self.stage
			resultSet['shellcode'] = "None"
			resultSet["isFile"] = False

			if not message:
				print ".::[Amun - DNS] no data ::."
				return resultSet

			if self.stage=="DNS_STAGE1" and bytes==72:
				if dns_shellcodes.dns_request_stage1==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					rplmess = "\x00"*20
					rplmess += "50abc2a4-574d-40b3-9d66-ee4fd5fba076 1.00 ncalrpc:[DNSResolver] (Messenger Service)".encode("hex")
					#resultSet['reply'] = "".join(self.reply)
					resultSet['reply'] = rplmess 
					self.stage = "DNS_STAGE2"
					return resultSet
			elif self.stage=="DNS_STAGE2":
				#if dns_shellcodes.dns_request_stage2==message:
				#	resultSet['result'] = True
				#	resultSet['accept'] = True
				#	self.reply[9] = "\x00"
				#	resultSet['reply'] = "".join(self.reply)
				#	self.stage = "DNS_STAGE3"
				#	return resultSet
				#self.print_message( message )
				resultSet['result'] = False
				resultSet['accept'] = False
				return resultSet
			elif self.stage=="DNS_STAGE3" and (bytes==96 or bytes==98 or bytes==100):
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "DNS_STAGE4"
				return resultSet
			elif self.stage=="DNS_STAGE4":
				if dns_shellcodes.dns_request_stage4==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "DNS_STAGE5"
					return resultSet
			elif self.stage=="DNS_STAGE5" and bytes==160:
				if dns_shellcodes.dns_request_stage5==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "SHELLCODE"
					return resultSet
			elif self.stage=="SHELLCODE":
				if message=="None":
					#print ".::[Amun - DNS] client quit finished collecting shellcode (bytes: %s) ::." % (bytes)
					resultSet['result'] = False
					resultSet['accept'] = True
					resultSet['reply'] = "None"
					resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				elif bytes>0:
					#print ".::[Amun - DNS] collecting shellcode: %s ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				else:
					#print ".::[Amun - DNS] finish collecting shellcode (bytes %s) ::." % (bytes)
					resultSet['result'] = False
					resultSet['accept'] = True
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
			else:
				#if message!="None":
				#	print ".::[Amun - DNS] unkown stage: (stage: %s bytes: %s data: %s) ::." % (self.stage, bytes, message)
				resultSet['result'] = False
				resultSet['reply'] = "None"
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			print e
			return resultSet
