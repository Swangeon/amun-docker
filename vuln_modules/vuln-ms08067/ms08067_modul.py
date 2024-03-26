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

import sys
import struct
import random
import ms08067_shellcodes

import traceback
import StringIO

sys.path.append("../../core")
import amun_smb_core


class vuln:
	def __init__(self):
		try:
			self.vuln_name = "MS08067 Vulnerability"
			self.stage = "MS08067_STAGE1"
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

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:

			### construct standard reply
			self.reply = random_reply
			#self.reply = []
			#for i in range(0,400):
			#	try:
			#		self.reply.append( struct.pack("B", 0) )
			#	except KeyboardInterrupt:
			#		raise

			### prepare default resultSet
			resultSet = {}
			self.vuln_name = "MS08067 Vulnerability"
			resultSet["vulnname"] = self.vuln_name
			resultSet["accept"] = False
			resultSet["result"] = False
			resultSet["shutdown"] = False
			resultSet["reply"] = "None"
			resultSet["stage"] = self.stage
			resultSet["shellcode"] = "None"
			resultSet["isFile"] = False


			if self.stage == "MS08067_STAGE1" and (bytes==51 or bytes==88 or bytes==137):
				""" Negotiation Response """
				if message[8]!='\x72':
					return resultSet
				#print ".::[Amun - MS08-067 STAGE1] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)

				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "MS08067_STAGE2"
				return resultSet
			elif self.stage == "MS08067_STAGE2" and (bytes==106 or bytes==79 or bytes==77 or bytes==189 or bytes==76):
				""" Session Setup AndX Response 1 """
				#print ".::[Amun - MS08-067 STAGE2] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
				
				self.smbHandler.setStage(self.getCurrentStage())
				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "MS08067_STAGE3"
				return resultSet
			elif self.stage == "MS08067_STAGE3" and (bytes == 76 or bytes==72 or bytes==273):
				""" Session Setup AndX Response 2 """
				#print ".::[Amun - MS08-067 STAGE3] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
				    
				self.smbHandler.setStage(self.getCurrentStage())
				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "MS08067_STAGE4"
				return resultSet
			elif self.stage == "MS08067_STAGE4" and (bytes==96 or bytes==111 or bytes==95):
				""" Session Setup AndX Response 3 """
				#print ".::[Amun - MS08-067 STAGE4] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)

				self.smbHandler.setStage(self.getCurrentStage())
				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "MS08067_STAGE5"
				return resultSet
			elif self.stage == "MS08067_STAGE5" or (bytes==150 or bytes==71 or bytes==39):
				""" Tree Connect AndX Response """
				#print ".::[Amun - MS08-067 STAGE5] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)

				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "MS08067_STAGE6"
				return resultSet
			elif self.stage == "MS08067_STAGE6" and bytes>0:
				""" NT Create AndX Response """
				#print ".::[Amun - MS08-067 STAGE6] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
				
				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet
				
				resultSet["result"] = True
				resultSet["accept"] = True
				self.shellcode.append(message)
				self.stage = "MS08067_STAGE7"				
				return resultSet
			elif self.stage == "MS08067_STAGE7" and bytes>0:
				""" Write andX Response / Read andX Response """
				#print ".::[Amun - MS08-067 STAGE7] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
		
				reply = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.shellcode.append(message)
				if message[8]!='\x2f':
					self.stage = "SHELLCODE"
				return resultSet
				
			elif self.stage == "SHELLCODE":
				if bytes>0:
					#print ".::[Amun - MS08-067 SHELLCODE] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					reply = self.smbHandler.consume(message, ownIP)
                                	if reply!=None:
                                        	resultSet['reply'] = reply+'*'
                                	else:
                                        	return resultSet
					
					resultSet["result"] = True
					resultSet["accept"] = True
					#resultSet['reply'] = "".join(self.reply)
					#resultSet["reply"] = "None"
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
				else:
					#print ".::[Amun - MS08-067 SHELLCODE] finish collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					#reply = self.smbHandler.consume(message, ownIP)
                                        #if reply!=None:
                                        #        resultSet['reply'] = reply+'*'
                                        #else:
                                        #        return resultSet
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
			print "MS08067 error: %s" % (self.stage)
			print e
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
		except:
			print "Analyzer fatal error"
