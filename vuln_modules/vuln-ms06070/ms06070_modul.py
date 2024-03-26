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
import ms06070_shellcodes

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "MS06070 Vulnerability"
			self.stage = "MS06070_STAGE1"
			self.welcome_message = ""
			self.userid = []
			self.userid.append( struct.pack('B', random.randint(0,255)) )
			self.userid.append( struct.pack('B', random.randint(0,255)) )

			self.treeid = []
			self.treeid.append( struct.pack('B', random.randint(0,255)) )
			self.treeid.append( struct.pack('B', random.randint(0,255)) )

			self.fid = []
			self.fid.append( struct.pack('B', random.randint(0,255)) )
			self.fid.append( struct.pack('B', random.randint(0,255)) )
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
			### construct standard reply
			self.reply = []
			for i in range(0,510):
				try:
					self.reply.append( struct.pack("B", random.randint(0,255)) )
				except KeyboardInterrupt:
					raise

			### prepare default resultSet
			resultSet = {}
                        resultSet['vulnname'] = self.vuln_name
			resultSet['accept'] = False
			resultSet['result'] = False
			resultSet['shutdown'] = False
			resultSet['reply'] = "None"
			resultSet['stage'] = self.stage
			resultSet['shellcode'] = "None"
			resultSet["isFile"] = False

			#self.print_message(message)

			if self.stage == "MS06070_STAGE1" and (bytes == 148):
				#print ".::[Amun - MS06070] Stage 1 complete (%s) ::." % (bytes)
				resultSet['result'] = True
				resultSet['accept'] = True
				self.reply = []
				for i in range(0,62):
					self.reply.append( struct.pack('B', random.randint(0,255)) )
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06070_STAGE2"
				return resultSet
			elif self.stage == "MS06070_STAGE2" and (bytes == 88):
				if ms06070_shellcodes.ms06070_request_stage2 == message or ms06070_shellcodes.ms06070_request_stage2_1 == message or ms06070_shellcodes.ms06070_request_stage2_2 == message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[0x20] = self.userid[0]
					self.reply[0x21] = self.userid[1]
					resultSet['reply'] = "".join(self.reply)
					self.stage = "MS06070_STAGE3"
					#print ".::[Amun - MS06070] Stage 2 complete (%s) ::." % (bytes)
					return resultSet
			elif self.stage == "MS06070_STAGE3" and bytes == 185:
				if ms06070_shellcodes.ms06070_request_stage3 == message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[0x1c] = self.treeid[0]
					self.reply[0x1d] = self.treeid[1]
					resultSet['reply'] = "".join(self.reply)
					self.stage = "MS06070_STAGE4"
					#print ".::[Amun - MS06070] Stage 3 complete (%s) ::." % (bytes)
					return resultSet
			elif self.stage == "MS06070_STAGE4" and bytes == 264:
				if ms06070_shellcodes.ms06070_request_stage4 == message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[0x2a] = self.fid[0]
					self.reply[0x2b] = self.fid[1]
					resultSet['reply'] = "".join(self.reply)
					self.stage = "MS06070_STAGE5"
					#print ".::[Amun - MS06070] Stage 4 complete (%s) ::." % (bytes)
					return resultSet
			elif self.stage == "MS06070_STAGE5" and bytes == 62:
				if ms06070_shellcodes.ms06070_request_stage5 == message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "SHELLCODE"
					#print ".::[Amun - MS06070] Stage 5 complete (%s) ::." % (bytes)
					return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					#print ".::[Amun - MS06070] collecting shellcode: %s ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				else:
					#print ".::[Amun - MS06070] finish collecting shellcode (bytes: %s) ::." % (bytes)
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
