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
import wins_shellcodes

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "WINS Vulnerability"
			self.stage = "SHELLCODE"
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
					#self.reply.append( struct.pack("B", random.randint(0,255)) )
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

			if self.stage=="SHELLCODE":
				if bytes>0:
					#print ".::[Amun - WINS] collecting shellcode: %s ::." % (bytes)
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
					self.shellcode.append(message)
					#resultSet['shellcode'] = "".join(self.shellcode)
					self.stage = "SHELLCODE"
					return resultSet
				else:
					#print ".::[Amun - WINS] finish collecting shellcode (bytes %s) ::." % (bytes)
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
		except:
			print "WINS FATAL ERROR!"
