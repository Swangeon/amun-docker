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
import asn1_shellcodes

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "ASN1 Vulnerability"
			self.stage = "ASN1_STAGE1"
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
			self.reply = random_reply[:62]

			resultSet = {}
			resultSet['vulnname'] = self.vuln_name
			resultSet['result'] = False
			resultSet['accept'] = False
			resultSet['shutdown'] = False
			resultSet['reply'] = "None"
			resultSet['stage'] = self.stage
			resultSet['shellcode'] = "None"
			resultSet["isFile"] = False

			if self.stage=="ASN1_STAGE1" and (bytes==len(asn1_shellcodes.asn1_request_stage1) or bytes==1024 or bytes==4 or bytes==133 or bytes==536 or bytes==141 or bytes==677):
				if asn1_shellcodes.asn1_request_stage1==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[6] = "\x78"
					self.reply[16] = "\x05"
					self.reply[17] = "\x37"
					self.reply[18] = "\x1e"
					self.reply[19] = "\x90"
					self.reply[40] = "\x78"
					self.reply[41] = "\xae"
					self.reply[42] = "\xf8"
					self.reply[43] = "\x77"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "ASN1_STAGE1"
					return resultSet
				elif message=='\x00\x00\x00\x85' or message=='\x00\x00\x10\xbf':
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "ASN1_STAGE1"
					return resultSet
				elif asn1_shellcodes.asn1_request_stage1_2==message or asn1_shellcodes.asn1_request_stage1_3==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "ASN1_STAGE1"
					return resultSet
				elif bytes==141:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "ASN1_STAGE1"
					return resultSet
				elif bytes==1024 or bytes==536 or bytes==677:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					#resultSet['shellcode'] = "".join(self.shellcode)
					self.stage = "SHELLCODE"
					return resultSet
			elif self.stage=="SHELLCODE":
				if bytes>0:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				else:
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
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(1)
