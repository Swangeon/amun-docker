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
import netbiosname_shellcodes

import traceback
import sys
import StringIO

sys.path.append("../../core")
import amun_smb_core

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "NETBIOSNAME Vulnerability"
			self.stage = "NETBIOSNAME_STAGE1"
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

			if self.stage=="NETBIOSNAME_STAGE1" and (bytes==72 or bytes==51 or bytes==1024):
				if netbiosname_shellcodes.netbiosname_session_request == message:
		
					reply = self.smbHandler.consume(message, ownIP)
					if reply!=None:
						resultSet['reply'] = reply+'*'
					else:
						return resultSet

					resultSet['result'] = True
					resultSet['accept'] = True
					#self.reply = []
					#self.reply.append("\x82")
					#self.reply.append("\x00")
					#self.reply.append("\x00")
					#self.reply.append("\x00")
					#resultSet['reply'] = "".join(self.reply)
					self.stage = "SHELLCODE"
					return resultSet
				elif netbiosname_shellcodes.netbiosname_nego_request == message:
					
					reply = self.smbHandler.consume(message, ownIP)
					if reply!=None:
						resultSet['reply'] = reply+'*'
					else:
						return resultSet

					resultSet['result'] = True
					resultSet['accept'] = True
					#resultSet['reply'] = netbiosname_shellcodes.netbiosname_nego_reply
					self.stage = "SHELLCODE"
					return resultSet
				else:
					reply = self.smbHandler.consume(message, ownIP)
					if reply!=None:
						resultSet['reply'] = reply+'*'
					else:
						return resultSet

					resultSet['result'] = True
					resultSet['accept'] = True
					#resultSet['reply'] = "".join(self.reply)
					self.stage = "SHELLCODE"
					return resultSet
			#elif self.stage=="NETBIOSNAME_STAGE2" and bytes==137:
			#	resultSet['result'] = True
			#	resultSet['accept'] = True
			#	resultSet['reply'] = "".join(self.reply)
			#	self.stage = "SHELLCODE"
			#	return resultSet
			elif self.stage=="SHELLCODE":
				if bytes>0:
					reply = self.smbHandler.consume(message, ownIP)
					if reply!=None:
						resultSet['reply'] = reply+'*'
					else:
						resultSet['reply'] = "None"

					resultSet['result'] = True
					resultSet['accept'] = True
					#resultSet['reply'] = "None"
					self.shellcode.append(message)
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
