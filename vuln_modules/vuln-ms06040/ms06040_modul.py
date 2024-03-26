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
import ms06040_shellcodes
import amun_logging


class vuln:
	def __init__(self):
		try:
			self.vuln_name = "MS06040 Vulnerability"
			self.stage = "MS06040_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
		except KeyboardInterrupt:
			raise

        def getVulnName(self):
                return self.vuln_name

        def getCurrentStage(self):
                return self.stage

	def getWelcomeMessage(self):
                return self.welcome_message

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			### construct standard reply
			self.reply = random_reply[:62]

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
			
			if self.stage == "MS06040_STAGE1" and (bytes==72 or bytes==88):
				if ms06040_shellcodes.ms06040_request_stage1 == message or ms06040_shellcodes.ms06040_request_stage1_1 == message or ms06040_shellcodes.ms06040_request_stage1_2 == message:
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[9] = "\x00"
					resultSet['reply'] = "".join(self.reply)
					self.stage = "MS06040_STAGE2"
					#print ".::[Amun - MS06040] Stage 1 complete (%s) ::." % (bytes)
					return resultSet
			elif self.stage == "MS06040_STAGE2" and bytes==88:
				if ms06040_shellcodes.ms06040_request_stage2 == message or ms06040_shellcodes.ms06040_request_stage2_1 == message:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.stage = "MS06040_STAGE3"
					#print ".::[Amun - MS06040] Stage 2 complete (%s) ::." % (bytes)
					return resultSet
			elif self.stage == "MS06040_STAGE3" and (bytes==185 or bytes==176 or bytes==422 or bytes==484):
				#if ms06040_shellcodes.ms06040_request_stage3 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE4"
				#print ".::[Amun - MS06040] Stage 3 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE4" and (bytes==264 or bytes==246 or bytes==308):
				#if ms06040_shellcodes.ms06040_request_stage4 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE5"
				#print ".::[Amun - MS06040] Stage 4 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE5" and (bytes==62 or bytes==158 or bytes==655):
				#if ms06040_shellcodes.ms06040_request_stage5 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE6"
				#print ".::[Amun - MS06040] Stage 5 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE5" and bytes==1024:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "SHELLCODE"
				self.shellcode.append(message)
				#resultSet['shellcode'] = "".join(self.shellcode)
				return resultSet
			elif self.stage == "MS06040_STAGE6" and (bytes==96 or bytes==246):
				#if ms06040_shellcodes.ms06040_request_stage6 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE7"
				#print ".::[Amun - MS06040] Stage 6 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE7" and (bytes==150 or bytes==497):
				#if ms06040_shellcodes.ms06040_request_stage7 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE8"
				#print ".::[Amun - MS06040] Stage 7 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE7" and bytes==1024:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "SHELLCODE"
				self.shellcode.append(message)
				#resultSet['shellcode'] = "".join(self.shellcode)
				return resultSet
			elif self.stage == "MS06040_STAGE8" and bytes==347:
				#if ms06040_shellcodes.ms06040_request_stage8 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE9"
				#print ".::[Amun - MS06040] Stage 8 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE9" and bytes==347:
				#if ms06040_shellcodes.ms06040_request_stage9 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE10"
				#print ".::[Amun - MS06040] Stage 9 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE10" and (bytes==347 or bytes==453):
				#if ms06040_shellcodes.ms06040_request_stage10 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "MS06040_STAGE11"
				#print ".::[Amun - MS06040] Stage 10 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "MS06040_STAGE11" and bytes==106:
				#if ms06040_shellcodes.ms06040_request_stage11 == message:
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply)
				self.stage = "SHELLCODE"
				#print ".::[Amun - MS06040] Stage 11 complete (%s) ::." % (bytes)
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					#print ".::[Amun - MS06040] collecting shellcode: %s ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
				else:
					#print ".::[Amun - MS06040] finish collecting shellcode (bytes: %s ip: %s) ::." % (bytes, ip)
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
