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

import StringIO
import traceback

import struct
import random
import lsass_shellcodes
import sys

sys.path.append("../../core")
import amun_smb_core

class vuln(object):
	__slots__ = ("vuln_name", "stage", "welcome_message", "shellcode", "reply", "smbHandler")

	def __init__(self):
		try:
			self.vuln_name = "LSASS Vulnerability"
			self.stage = "LSASS_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
			self.smbHandler = amun_smb_core.amun_smb_prot()
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
			for i in range(0,254):
				try:
					self.reply.append( struct.pack("B", random.randint(0,255)) )
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

			if self.stage=="LSASS_STAGE1" and bytes==137:
				if lsass_shellcodes.lsass_request_stage1==message or lsass_shellcodes.lsass_request_stage1_2==message:

					reply = self.smbHandler.consume(message, ownIP)
					if reply!=None:
						resultSet['reply'] = reply+'*'
					else:
						return resultSet


					#self.reply[9] = "\x00"
					#resultSet['reply'] = "".join(self.reply[:62])

					resultSet['result'] = True
					resultSet['accept'] = True
					self.stage = "LSASS_STAGE2"
					return resultSet
			elif self.stage=="LSASS_STAGE1" and bytes==133:
				if lsass_shellcodes.lsass_request_stage1_3==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply[:62])
					self.stage = "LSASS_STAGE2"
					return resultSet
			elif self.stage=="LSASS_STAGE2" and (bytes==168 or bytes==390 or bytes==597):
				if lsass_shellcodes.lsass_request_stage2==message or lsass_shellcodes.lsass_request_stage2_2==message or lsass_shellcodes.lsass_request_stage2_3==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply[:62])
					self.stage = "LSASS_STAGE3"
					return resultSet
			elif self.stage=="LSASS_STAGE2" and bytes==1024:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply[:62])
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				#resultSet['shellcode'] = "".join(self.shellcode)
				return resultSet
			elif self.stage=="LSASS_STAGE3" and (bytes==222 or bytes==324 or bytes==96 or bytes==98):
				if lsass_shellcodes.lsass_request_stage3==message or lsass_shellcodes.lsass_request_stage3_2==message or lsass_shellcodes.lsass_request_stage3_3==message or lsass_shellcodes.lsass_request_stage3_4==message or lsass_shellcodes.lsass_request_stage3_5==message or lsass_shellcodes.lsass_request_stage3_6==message:
					self.reply[48:69] = "W i n d o w s  5 . 1 "
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply[:254])
					self.stage = "LSASS_STAGE4"
					return resultSet
			elif self.stage=="LSASS_STAGE3" and bytes==1024:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply[:254])
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				#resultSet['shellcode'] = "".join(self.shellcode)
				return resultSet
			elif self.stage=="LSASS_STAGE4":
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply[:62])
				self.stage = "LSASS_STAGE5"
				return resultSet
			elif self.stage=="LSASS_STAGE5" and (bytes==104 or bytes==162 or bytes==105 or bytes==264):
				if lsass_shellcodes.lsass_request_stage5==message or lsass_shellcodes.lsass_request_stage5_2==message or lsass_shellcodes.lsass_request_stage5_3==message or lsass_shellcodes.lsass_request_stage5_4==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply[:62])
					self.stage = "LSASS_STAGE6"
					return resultSet
			elif self.stage=="LSASS_STAGE5" and bytes==1024:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply[:62])
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				#resultSet['shellcode'] = "".join(self.shellcode)
				return resultSet
			elif self.stage=="LSASS_STAGE6" and (bytes==160 or bytes==162):
				if lsass_shellcodes.lsass_request_stage6==message or lsass_shellcodes.lsass_request_stage6_2==message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply[:62])
					self.stage = "SHELLCODE"
					return resultSet
			elif self.stage=="LSASS_STAGE6" and bytes==1024:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply[:62])
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				#resultSet['shellcode'] = "".join(self.shellcode)
				return resultSet
			elif self.stage=="SHELLCODE":
				if bytes>0:
					#print ".::[Amun - LSASS] collecting shellcode: %s ::." % (bytes)

					try:
						reply = self.smbHandler.consume(message, ownIP)
						if reply!=None:
							resultSet['reply'] = reply+'*'
					except:
						resultSet['reply'] = "".join(self.reply[:62])
					#else:
					#	return resultSet


					resultSet['result'] = True
					resultSet['accept'] = True
					#resultSet['reply'] = "".join(self.reply[:62])
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				else:
					#print ".::[Amun - LSASS] finish collecting shellcode (bytes %s) ::." % (bytes)
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
			print "LSASS error: %s" % (self.stage)
			print e
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(1)
			return resultSet
		except:
			print "LSASS FATAL ERROR!"
