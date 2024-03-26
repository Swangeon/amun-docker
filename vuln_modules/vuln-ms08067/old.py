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
import ms08067_shellcodes

import amun_logging

### Modul to analyze new vulnerabilities, get everything send to a port and send it to shellcode_manager

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "MS08067 Vulnerability"
			self.stage = "MS08067_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
		except KeyboardInterrupt:
			raise

	def print_message(self, data):
		print "\n"
		counter = 1
		for byte in data:
			if counter==16:
				ausg = hex(struct.unpack("B",byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split("x")
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg
				else:
					print ausg
				counter = 0
			else:
				ausg = hex(struct.unpack("B",byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split("x")
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

	def incoming(self, message, bytes, ip, vuLogger, random_reply):
		try:
			self.log_obj = amun_logging.amun_logging("vuln_analyzer", vuLogger)

			### construct standard reply
			#self.reply = random_reply
			#self.reply = []
			#for i in range(0,80):
			#	try:
			#		self.reply.append( struct.pack("B", 0) )
			#	except KeyboardInterrupt:
			#		raise

			### SMB Negotiate Request
			### 0x00 0x00 0x00 0x2f 0xff 0x53 0x4d 0x42 0x72 0x00 0x00 0x00 0x00 0x00 0x00 0x00
			### 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0xcf 0x6b
			### 0x00 0x00 0x00 0x00 0x00 0x0c 0x00 0x02 0x4e 0x54 0x20 0x4c 0x4d 0x20 0x30 0x2e
			### 0x31 0x32 0x00
			
			### SMB COM NONE
			### 0x00 0x00 0x00 0x4b 0xff 0x53 0x4d 0x42 0x73 0x00 0x00 0x00 0x00 0x08 0x00 0x00
			### 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0xff 0xff 0x49 0x68
			### 0x00 0x00 0x00 0x00 0x0d 0xff 0x00 0x00 0x00 0xff 0xff 0x02 0x00 0x49 0x68 0x00
			### 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x0e
			### 0x00 0x00 0x00 0x70 0x6f 0x73 0x69 0x78 0x00 0x70 0x79 0x73 0x6d 0x62 0x00


			###"\x00\x00\x00\x55\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x01\x28"
			###"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xaa"
			###"\x00\x00\xc6\xa3\x11\x03\x00\x03\x0a\x00\x01\x00\x04\x11\x00\x00"
			###"\x00\x00\x01\x00\x00\x00\x00\x00\xfd\xe3\x00\x00\x67\xd9\x26\x46"
			###"\xad\x3d\xc9\x01\xc4\xff\x00\x10\x00\xcf\x93\x98\x87\x52\x1d\x7c"
			###"\x42\x9a\xed\x0f\x24\x73\xdb\x5c\x46";


			### prepare default resultSet
			resultSet = {}
			resultSet["vulnname"] = self.vuln_name
			resultSet["accept"] = False
			resultSet["result"] = False
			resultSet["shutdown"] = False
			resultSet["reply"] = "None"
			resultSet["stage"] = self.stage
			resultSet["shellcode"] = "None"
			resultSet["isFile"] = False

			if self.stage == "MS08067_STAGE1" and bytes==51:
				print ".::[Amun - MS08-067 STAGE1] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
				#print message
				#print ">> Request:"
				#self.print_message(message)
				self.reply = []
				for char in ms08067_shellcodes.neg_response:
					self.reply.append(char)
				self.reply[30] = message[30]
				self.reply[31] = message[31]
				self.reply[34] = message[34]
				self.reply[35] = message[35]
				print "<< Response:"
				self.print_message(self.reply)
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS08067_STAGE2"
				return resultSet
			elif self.stage == "MS08067_STAGE2":
				print ".::[Amun - MS08-067 STAGE2] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
				print ">> Request:"
				self.print_message(message)
				#resultSet["result"] = True
				#resultSet["accept"] = True
				#print "<< Response:"
				#self.print_message(self.reply)
				#resultSet['reply'] = "".join(self.reply)
				#self.stage = "MS08067_STAGE2"
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					print ".::[Amun - Analyzer] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
				else:
					print ".::[Amun - Analyzer] finish collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					self.shellcode.append(message)
					resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
			else:
				resultSet["result"] = False
				resultSet["accept"] = False
				resultSet["reply"] = "None"
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			print e
		except:
			print "Analyzer fatal error"
