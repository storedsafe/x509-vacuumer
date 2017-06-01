#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# when          who                     why             what
# 20170601      norin@storedsafe.com    login/refresh   Created
#

#
# This is small script to login and aquire a token.
# This can also be used to keep the token alive by schedule it.
# It is built for version 1.0  of StoredSafes REST-Like API
# Dependencies below in the "import" statements.
#

import getpass
import httplib
import ssl
import json
import getopt, sys
import re
import os.path
import syslog

from os.path import expanduser
homeDir = expanduser("~")
os.umask (0066)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "lco" )
	except getopt.GetoptError as err:
		print(err)
		usage()
		sys.exit(2)
	if opts:
		pass
	else:
		usage()
		sys.exit(2)
	for o, a in opts:
		if o in ("-l", "--login"):
			login()
			break
		if o in ("-o", "--logout"):
			logout()
			break
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o in ("-c", "--check"):
			check()
			break
		else:
			assert False, "unhandled option"

def usage():
	print "\n"
	print "All actions require that you firstly authenticate in order to obtain a token"
	print "Once you have a token you can do other stuff"
	print "\n"
	print "Login				by appending -l"
	print "Logout				by appending -o"
	print "Check/Refresh token	by appending -c"

def login():
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
		for line in file_:
			if "username" in line:
				line = re.sub('username:([a-zA-Z0-9]+)\n$', r'\1', line)
				answer = str(raw_input("Username is set to: " + line + " do you want to keep it? (Y/n): "))
				if answer == ('n' or 'N'):
					userName = str(raw_input('Enter Username: '))
				else:
					userName = line
			if "mysite" in line:
				line = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
				answer = str(raw_input("Site is set to: " + line + " do you want to keep it? (Y/n): "))
				if answer == ('n' or 'N'):
					mysite = str(raw_input('Enter Site(storedsafe.example.com): '))
				else:
					mysite = line
			if "apikey" in line:
				line = re.sub('apikey:([a-zA-Z0-9]+)\n$', r'\1', line)
				answer = str(raw_input("Apikey is set to: " + line + " do you want to keep it? (Y/n): "))
				if answer == ('n' or 'N'):
					apiKey = str(raw_input('Enter Apikey: '))
				else:
					apiKey = line
		file_.close()
	else:
		userName = str(raw_input("Enter Username: "))
		apiKey = str(raw_input("Enter Apikey: "))
		mysite = str(raw_input("Enter Site(storedsafe.example.com): "))
	passWord = getpass.getpass('Enter Password: ')
	otp = getpass.getpass('Press Yubikey:')
	loginJson = {
			'username':userName,
			'keys':passWord + apiKey + otp
	}
	c = httplib.HTTPSConnection(mysite, context=ssl._create_unverified_context())
	c.request("POST", "/api/1.0/auth", json.dumps(loginJson))
	response = c.getresponse()
	print response.status, response.reason
	data = response.read()
	jsonObject = json.loads(data)
        if jsonObject["CALLINFO"]["status"] == 'SUCCESS':
		print "Login succeeded, please remember to log out when done."
		with open(homeDir + '/.storedsafe-client.rc', 'w') as file_:
                        file_.write('token:' + jsonObject["CALLINFO"]["token"] + '\n')
                        file_.write('username:' + userName + '\n')
			file_.write('apikey:' + apiKey + '\n')
			file_.write('mysite:' + mysite + '\n')
			file_.close()
	else:
		print "Login failed"
		sys.exit()

def checktoken():
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		pass
	else:
		print "You need to log on first"
		sys.exit()
	file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
	for line in file_:
		if "token" in line:
			token = re.sub('token:([a-zA-Z0-9]+)\n$', r'\1', line)
			if token == 'none':
				syslog.syslog(syslog.LOG_ERR, 'ERROR: StoredSafe Token Handler not logged in')
				print "Not logged in"
				sys.exit()
			return token
	file_.close()

def updatetoken(token):
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		pass
	else:
		print "You need to log on first"
		sys.exit()
	file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
	for line in file_:
		if "token" in line:
			ftoken = re.sub('token:([a-zA-Z0-9]+)\n$', r'\1', line)
		if "username" in line:
			fusername = re.sub('username:([a-zA-Z0-9]+)\n$', r'\1', line)
		if "apikey" in line:
			fapikey = re.sub('apikey:([a-zA-Z0-9]+)\n$', r'\1', line)
		if "mysite" in line:
			fmysite = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
	file_.close()
	if token != ftoken:
		with open(homeDir + '/.storedsafe-client.rc', 'w') as file_:
			file_.write('token:' + token + '\n')
			file_.write('username:' + fusername + '\n')
			file_.write('apikey:' + fapikey + '\n')
			file_.write('mysite:' + fmysite + '\n')
			file_.close()

def cleartoken():
	with open(homeDir + '/.storedsafe-client.rc', 'r') as file_:
		for line in file_:
			if "username" in line:
				userName = re.sub('username:([a-zA-Z0-9]+)\n$', r'\1', line)
			if "apikey" in line:
				apiKey = re.sub('apikey:([a-zA-Z0-9]+)\n$', r'\1', line)
			if "mysite" in line:
				mysite = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
		file_.close()
	with open(homeDir + '/.storedsafe-client.rc', 'w') as file_:
		file_.write('apikey:' + apiKey + '\n')
		file_.write('mysite:' + mysite + '\n')
		file_.write('username:' + userName + '\n')
		file_.write('token:none' + '\n')
		file_.close()

def checksite():
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		pass
	else:
		print "You need to log on first"
		sys.exit()
	file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
	for line in file_:
		if "mysite" in line:
			mysite = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
			if mysite == 'none':
				print "Not logged in"
				sys.exit()
			return mysite
	file_.close()

def logout():
	token = checktoken()
	mysite = checksite()
	c = httplib.HTTPSConnection(mysite, context=ssl._create_unverified_context())
	c.request("GET", "/api/1.0/auth/logout?token=" + token)
	response = c.getresponse()
	data = response.read()
	jsonObject = json.loads(data)
        if jsonObject["CALLINFO"]["status"] == 'SUCCESS':
		print "Logout successful"
		cleartoken()
	else:
		print "Login has expired"
		cleartoken()
		sys.exit()

def check():
	token = checktoken()
	mysite = checksite()
	checkJson = { 'token':token }
	c = httplib.HTTPSConnection(mysite, context=ssl._create_unverified_context())
	c.request("POST", "/api/1.0/auth/check", json.dumps(checkJson))
	response = c.getresponse()
	print response.status, response.reason
	data = response.read()
	jsonObject = json.loads(data)
        if jsonObject["CALLINFO"]["status"] == 'SUCCESS':
		pass
	else:
		syslog.syslog(syslog.LOG_ERR, 'ERROR: StoredSafe Token Handler not logged in')
		print "Not logged in"
		cleartoken()
		sys.exit()

if __name__ == '__main__':
    main()
