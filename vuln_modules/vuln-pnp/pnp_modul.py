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
import pnp_shellcodes

class vuln:

	def __init__(self):
		try:
			self.vuln_name = "PNP Vulnerability"
			self.stage = "PNP_STAGE1"
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
		print "\n>> Incoming Codesize: %s\n\n" % (len(data))

        def getVulnName(self):
                return self.vuln_name

        def getCurrentStage(self):
                return self.stage

	def getWelcomeMessage(self):
                return self.welcome_message

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			self.reply = []
			for i in range(0,62):
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

			#if self.stage=="PNP_STAGE1" and (bytes==137 or bytes==88 or bytes==176):
			if self.stage=="PNP_STAGE1" and (bytes==137 or bytes==176):
				if pnp_shellcodes.pnp_request_stage1==message:
					#print ".::[Amun - PNP] %s -1 ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "PNP_STAGE2"
					return resultSet
				else:
					#print ".::[Amun - PNP] %s -2 ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[0] = "\x73"
					self.reply[3] = "\x80"
					self.reply[4] = "\x10"
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "PNP_STAGE2"
					return resultSet
			elif self.stage=="PNP_STAGE2" and bytes==168:
				if pnp_shellcodes.pnp_request_stage2==message:
					#print ".::[Amun - PNP] %s -1 ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "PNP_STAGE3"
					return resultSet
			elif self.stage=="PNP_STAGE2" and bytes==4:
				if message=='\x00\x00\x10\xbf':  
					#print ".::[Amun - PNP] %s -2 ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "PNP_STAGE2"
					return resultSet
			elif self.stage=="PNP_STAGE2" and bytes==1024:
				#print ".::[Amun - PNP] %s -3 ::." % (self.stage)
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage=="PNP_STAGE3" and bytes==222:
				if pnp_shellcodes.pnp_request_stage3==message or pnp_shellcodes.pnp_request_stage3_2==message:
					#print ".::[Amun - PNP] %s ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "PNP_STAGE4"
					return resultSet
			elif self.stage=="PNP_STAGE4":
				#print ".::[Amun - PNP] %s ::." % (self.stage)
				resultSet['result'] = True
				resultSet['accept'] = True
				self.reply[9] = "\x00"
				resultSet['reply'] = "".join(self.reply)
				self.stage = "PNP_STAGE5"
				return resultSet
			elif self.stage=="PNP_STAGE5" and bytes==106:
				if pnp_shellcodes.pnp_request_stage5==message:
					#print ".::[Amun - PNP] %s ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "PNP_STAGE6"
					return resultSet
			elif self.stage=="PNP_STAGE6" and bytes==160:
				if pnp_shellcodes.pnp_request_stage6==message or pnp_shellcodes.pnp_request_stage6_2==message:
					#print ".::[Amun - PNP] %s ::." % (self.stage)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
			elif self.stage=="SHELLCODE":
				if bytes>0:
					#print ".::[Amun - PNP] collecting shellcode: %s ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				else:
					#print ".::[Amun - PNP] finish collecting shellcode (bytes %s) ::." % (bytes)
					resultSet['result'] = False
					resultSet['accept'] = True
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
			else:
				resultSet['result'] = False
				resultSet['accept'] = False
				resultSet['reply'] = "None"
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			print e
			return resultSet
