#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
argus.py: search for x509 certificates and store them i storedsafe.
"""

from __future__ import print_function
import sys
import ssl
import OpenSSL
import json
import datetime
import getopt
import socket
import getpass
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from netaddr import *

__author__     = "Fredrik Soderblom"
__copyright__  = "Copyright 2017, AB StoredSafe"
__license__    = "GPL"
__version__    = "1.0.1"
__maintainer__ = "Fredrik Soderblom"
__email__      = "fredrik@storedsafe.com"
__status__     = "Production"

# Globals

url              = False
token            = False
verbose          = False
import_expired   = False
create_vault     = False
unique_vault     = False
allow_duplicates = False

"""
  # FIXME: Skapa valv per nytt cert
  # FIXME: Skapa valv om det inte finns
"""

def main():
  timeout = 2
  hosts = []
  cidr = []
  tcp_port = [ '443']
  user = apikey = vaultid = vaultname = supplied_token = False
  global token, url, verbose, import_expired, create_vault, unique_vault, allow_duplicates

  try:
   opts, args = getopt.getopt(sys.argv[1:], "c:p:s:u:a:v:t:h:", ["verbose","cidr=","port=","storedsafe=","token=","user=","apikey=","vault=","vaultid=","import-expired","create-vault","unique-vault","timeout=","host=","allow-duplicates"] )
  except getopt.GetoptError as err:
    print("%s" % str(err))
    usage()
    sys.exit(1)

  if opts:
    pass
  else:
    usage()
    sys.exit(2)

  for opt, arg in opts:
    if opt in ("--verbose"):
      verbose = True
    elif opt in ("-c", "--cidr"):
      try:
        cidr.append(IPNetwork(arg)) # Append to existing list
      except:
        print("Invalid network %s specified." % arg)
        sys.exit()
    elif opt in ("-h", "--host"):
      hosts.append(arg)
    elif opt in ("-p", "--port"):
      if int(arg) > 0 and int(arg) < 65536:
        tcp_port.append(arg) # Append to existing list
      else:
        print("Invalid port %s specified." % arg)
        sys.exit()
    elif opt in ("-s", "--storedsafe"):
      storedsafe = arg
    elif opt in ("-u", "--user"):
      user = arg
    elif opt in ("-a", "--apikey"):
      if len(str(arg)) == 10:
        apikey = arg
      else:
        print("Invalid API key.")
        sys.exit()
    elif opt in ("-t", "--token"):
      if len(str(arg)) == 42:
        supplied_token = arg
      else:
        print("Invalid token.")
        sys.exit()
    elif opt in ("-v", "--vault"):
      vaultname = arg
    elif opt in ("--vaultid"):
      vaultid = arg
    elif opt in ("--import-expired"):
      import_expired = True
    elif opt in ("--create-vault"):
      create_vault = True
    elif opt in ("--unique-vault"):
      unique_vault = True
    elif opt in ("--allow-duplicates"):
      allow_duplicates = True
    elif opt in ("--timeout"):
      timeout = int(arg)
    elif opt in ("-?", "--help"):
      usage()
      sys.exit()
    else:
      assert False, "Unrecognized option"

  # Resolve any hosts to IP and add them to list
  if hosts:
    cidr = addHosts(cidr, hosts)

  if not cidr and not tcp_port and not storedsafe:
    print("ERROR: StoredSafe Server address (--storedsafe), Targets (--cidr) and what port (--port) to scan is mandatory arguments.")
    sys.exit(3)

  url = "https://" + storedsafe + "/api/1.0"

  if not supplied_token:
    if not user and not apikey:
      print("ERROR: StoredSafe User (--user) and a StoredSafe API key (--apikey) or a valid StoredSafe Token (--token) is mandatory arguments.")
      sys.exit(3)
    else:
      pp = passphrase(user)
      otp = OTP(user)
      token = login(user, pp + apikey + otp)
  else:
    token = supplied_token

  # Check if Vaultname exists
  if vaultname:
    vaultid = findVaultID(vaultname)

  # Check if Vault-ID exists
  if vaultid:
    vaultname = findVaultName(vaultid)
  else:
    if not create_vault and not unique_vault:
      print("ERROR: One of \"--vault\", \"--vaultid\", \"--create-vault\" or \"--unique-vault\" is mandatory.")
      sys.exit()

  if verbose:
    printInfo(storedsafe, supplied_token, user, apikey, vaultname, cidr, tcp_port)

  candidates = scan(cidr, tcp_port, timeout)
  (imported, duplicates) = uploadCert(candidates, vaultid)

  if imported:
    print("Imported %d certificate/s." % imported)
  if duplicates:
    print("Found %d duplicate certificate/s. " % duplicates)

  sys.exit(0)

def usage():
  print("%s [--verbose] <-c|--cidr <CIDR>> <-h|--host <host>> <-p|--port <port>> <-s|--storedsafe <host>> <-u|--user <user>> <-a|--apikey <APIKEY>> [-v|--vault <Vaultname>] [--vaultid <Vault-ID>][--import-expired] [--create-vault] [--unique-vault] [--allow-duplicates]" % sys.argv[0])

def passphrase(user):
  p = getpass.getpass('Enter ' + user + '\'s passphrase: ')
  return(p)

def OTP(user):
  otp = getpass.getpass('Press ' + user + '\'s Yubikey: ')
  return(otp)

def login(user, key):
  global url
  payload = { 'username': user, 'keys': key }
  r = requests.post(url + '/auth', data=json.dumps(payload))
  data = json.loads(r.content)
  if r.ok:
    return data["CALLINFO"]["token"]
  else:
    print("ERROR: %s" % data["ERRORS"][0])
    sys.exit(6)

def findVaultID(vaultname):
  global token, url, verbose
  vaultid = False

  payload = { 'token': token }
  r = requests.get(url + '/vault', params=payload)
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any vaults.")
    sys.exit()

  for v in data["GROUP"].iteritems():
    if vaultname == data["GROUP"][v[0]]["groupname"]:
      vaultid = v[0]
      if verbose: print("Found Vault \"%s\" via Vaultname as Vault-ID \"%s\"" % (vaultname, vaultid))

  if not vaultid:
    print("ERROR: Can not find Vaultname \"%s\"." % vaultname)
    sys.exit()

  return(vaultid)

def findVaultName(vaultid):
  global token, url, create_vault, verbose

  payload = { 'token': token }
  r = requests.get(url + '/vault/' + vaultid, params=payload)
  data = json.loads(r.content)
  if not r.ok:
    if create_vault:
      print("WARNING: Can not find Vault-ID \"%s\", will try to create a new vault." % vaultid)
      vaultname = False
    else:
      print("ERROR: Can not find Vault-ID \"%s\" and \"--create-vault\" not specified." % vaultid)
      sys.exit()

  if data["CALLINFO"]["status"] == "SUCCESS":
    vaultname = data["GROUP"][vaultid]["groupname"]
    if verbose: print("Found Vault \"%s\" via Vault-ID \"%s\"" % (vaultname, vaultid))
  else:
    print("ERROR: Can not retreive Vaultname for Vault-ID %s." % vaultid)
    sys.exit()

  return(vaultname)

def addHosts(cidr, hosts):
  for host in hosts:
    try:
      ip = socket.gethostbyname(host)
    except:
      print("WARNING: Unknown host \"%s\"" % host)
    else:
      try:
        cidr
      except:
        cidr = [IPNetwork(ip)]
      else:
        cidr.append(IPNetwork(ip))

  return(cidr)

def printInfo(storedsafe, supplied_token, user, apikey, vaultname, cidr, tcp_port):
    global token, url, create_vault, import_expired, unique_vault
    print("Using StoredSafe Server \"%s\" (URL: \"%s\")" % (storedsafe, url))
    if not supplied_token:
      print("Logged in as \"%s\" with the API key \"%s\"" % (user, apikey))
    print("Using the token \"%s\"" % token)

    if vaultname:      print("Will store found certificates in Vault \"%s\"" % (vaultname))
    if create_vault:   print("Will create missing vaults.")
    if import_expired: print("Will import expired certificates.")
    if unique_vault:   print("Importing each certificates into a unique vault.")

    networks = []
    for p in cidr_merge(cidr):
      networks.append(str(p))

    print("Scanning network/s: %s" % ', '.join(networks), end='')
    print(" on port/s: %s" % ', '.join(tcp_port))
    print("[Legend: \".\" for no response, \"!\" for an open port]")

def scan(cidr, tcp_port, timeout):
  global verbose
  candidates = []
  for net in cidr_merge(cidr):
    for ip in list(net):
      for port in tcp_port:
        try:
          if ip.version == 6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
          else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)            
          s.settimeout(timeout)
          result = s.connect_ex((str(ip), int(port)))
          s.close()
          if result == 0: 
            candidates.append(str(ip) + ';' + str(port))
            if verbose: sys.stdout.write('!')
          else:
            if verbose: sys.stdout.write('.')
          if verbose: sys.stdout.flush()           
        except:
          if verbose: print("\nWARNING: Could not connect to \"%s:%s\"" % (ip, str(port)))

        if verbose: sys.stdout.flush()

  if verbose: sys.stdout.write('\n')
  return candidates

def uploadCert(candidates, vaultid):
  imported = duplicates = 0
  exists = False
  global token, url, verbose, import_expired, create_vault, unique_vault, allow_duplicates

  for candidate in candidates:
    (host, port) = candidate.split(';')

    try:
      (name, _, ipaddress_list) = socket.gethostbyaddr(host)
    except:
      name = IPAddress(host).reverse_dns

    try:
      certinfo = ssl.get_server_certificate((host, port))
    except:
      print("WARNING: No SSL/TLS listener on \"%s:%s\" (%s)" % (host, str(port), name))
      continue

    try:
      x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certinfo)
    except:
      print("WARNING: Unparseable certificate from host \"%s:%s\" (PTR: %s)" % (host, str(port), name))
      continue

    if verbose: print("Host \"%s:%s\" (PTR: %s) X509 CommonName=\"%s\" " % (host, str(port), name, x509.get_subject().CN), end='')
    if is_expired(x509):
      if not import_expired:
        continue

    multipart_data = MultipartEncoder(fields={
        'file': (x509.get_subject().CN + '.crt', certinfo, 'application/x-x509-ca-cert'),
        'file1': x509.get_subject().CN + '.crt', 
        'token': token
      }
    )
    r = requests.post(url + '/filecollect', data=multipart_data, headers={'Content-Type': multipart_data.content_type})
    if not r.ok:
      print("ERROR: Could not obtain file meta data on \"%s\"" % x509.get_subject().CN)
      sys.exit()

    data = json.loads(r.content)
    multipart_data = MultipartEncoder(fields={
        'file':       (x509.get_subject().CN + '.crt', certinfo, 'application/x-x509-ca-cert'),
        'file1':      data["DATA"]["file1"],
        'templateid': data["DATA"]["templateid"],
        'cn':         data["DATA"]["cn"],
        'issuer':     data["DATA"]["issuer"],
        'validfrom':  data["DATA"]["validfrom"],
        'validto':    data["DATA"]["validto"],
        'algorithm':  data["DATA"]["algorithm"],
        'keylength':  data["DATA"]["keylength"],
        'keyusage':   data["DATA"]["keyusage"],
        'altnamedns': data["DATA"]["altnamedns"],
        'info':       name,
        'parentid':   '0',
        'groupid':    vaultid,
        'token':      token
      }
    )

    if not allow_duplicates:
      exists = find_duplicates(data["DATA"]["cn"], data["DATA"]["validto"], data["DATA"]["altnamedns"], vaultid)

    if not exists:
      r = requests.post(url + '/object', data=multipart_data, headers={'Content-Type': multipart_data.content_type})
      if not r.ok:
        print("ERROR: Could not save certificate for \"%s\"" % x509.get_subject().CN)
        sys.exit(5)

      imported += 1
    else:
      duplicates += 1

  return(imported, duplicates)

def find_duplicates(cn, validto, altnamedns, vaultid):
  duplicate = False
  payload = { 'token': token, 'needle': cn }
  r = requests.get(url + '/find', params=payload)
  data = json.loads(r.content)
  if not r.ok:
    return(False)

  for v in data["OBJECT"].iteritems():
    if vaultid == data["OBJECT"][v[0]]["groupid"]:
      if cn == data["OBJECT"][v[0]]["public"]["cn"]:
        if validto == data["OBJECT"][v[0]]["public"]["validto"]:
          if altnamedns == data["OBJECT"][v[0]]["public"]["altnamedns"]:
            if verbose: print("Found existing certificate as Object-ID \"%s\" in Vault-ID \"%s\"" % (v[0], vaultid))
            duplicate = True

  return(duplicate)

def parse_expire_date(x509): # Code from certmon
  expire_date_str = str(x509.get_notAfter()).replace("b'", "").replace("'", "")
  expire_date = datetime.datetime.strptime(expire_date_str, "%Y%m%d%H%M%SZ")
  return expire_date

def cur_date():
  return datetime.datetime.now()

def is_expired(x509):
  global verbose
  expire_date = parse_expire_date(x509)
  delta = expire_date - cur_date()
  if delta.days < 0:
    print("- expired certificate %s (%d days ago)" % (expire_date, (delta.days * -1)))
    return True
  else:
    if verbose: print("(expires in %d days)" % (delta.days))
    return False

if __name__ == '__main__':
  main()
