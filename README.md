# argus

argus.py is a simple script to locate, retrieve and store X.509 certificates in StoredSafe.

argus.py will parse the certificate and store relevant meta information alongside  the certificate in StoredSafe.

StoredSafe's PubSub system will receive a subscription on an alert 30 days prior to the expiration date of each stored certificate.

The script is written in Python v2 and has been tested on macOS Sierra and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

## Installation instructions

This script requires Python v2 and some libraries. 

It has been developed and tested using Python v2.7.10, on macOS Sierra 10.12.4.

Most of the required libraries are installed by default,  but others require manual installation. ("requests, requests_toolbelt, netaddr)

**requests:**
```
sudo -H pip install requests
```

**requests-toolbelt:**
```
sudo -H pip install requests-toolbelt
```

**netaddr:**
```
sudo -H pip install netaddr
```

## Syntax

```
$ argus --help
argus.py [--verbose] <-c|--cidr <CIDR>> <-h|--host <host>> <-p|--port <port>> <-s|--storedsafe <host>> <-u|--user <user>> <-a|--apikey <APIKEY>> [-v|--vault <Vaultname>] [--vaultid <Vault-ID>][--import-expired] [--allow-duplicates]
```

```
--verbose
``` 
> Add verbose output

```
--cidr|-c <ipv4 or IPv6 network>
```
> Specify one or more IPv4 or IPv6 networks. Overlapping will be resolved.

```
--host|-h <fqdn hostname>
```
> Full qualified domain name (host.domain.cc) of host to scan. Will be resolved to IP address and aggregated with any CIDR objects (```--cidr```)

```
--port|-p <tcp port to scan>
```
> TCP port to scan

```
--storedsafe|-s <server>
```
> Upload certificates to this StoredSafe server

```
--token <token>
```
> Use pre-authenticated token instead of ```--user``` and ```--apikey```, also removes requirement to login with passphrase and OTP.

```
--user|-u <user>
```
> Authenticate as this StoredSafe user

```
--apikey|-a <apikey>
```
> Use this unique API key when communicating with StoredSafe. (Unique per application and installation)

```
--vault|-v <Vaultname>
```
> Store any found certificates in this vault. Name has to match exactly.

```
--vaultid <Vault-ID>
```
> Store any found certificates in this Vault-ID.

```
--import-expired
```
> Import expired certificates. Normally, expired certificates are ignored.

```
--allow-duplicates
```
> Allow importing the same certificate to the same vault multiple times.

```
--timeout
```
> Set the timeout when scanning for open ports. Defaults to 2 seconds.

Usage
=====
Scan the networks 2001:db8:c016::202/128, 10.75.106.202/29 and 192.0.2.4/32 on port 443 for X.509 certificates. Store any certificates found in the "Public Web Servers" Vault on the StoredSafe server "safe.domain.cc" and arm an alarm that will fire 30 days prior to each certificates expiration date.

```
$ argus.py -c 2001:db8:c016::202 -c 10.75.106.202/29 -c 192.0.2.4 -p 443 -s safe.domain.cc -u bob --apikey myapikey --vault "Public Web Servers" --verbose
Enter bob's passphrase:
Press bob's Yubikey:
Found Vault "Public Web Servers" via Vaultname as Vault-ID "181"
Found Vault "Public Web Servers" via Vault-ID "181"
Using StoredSafe Server "safe.domain.cc" (URL: "https://safe.domain.cc/api/1.0")
Logged in as "bob" with the API key "myapikey"
Using the token "xyzzyxyzzy"
Will store found certificates in Vault "Public Web Servers"
Scanning network/s: 192.0.2.4/32, 10.75.106.202/29, 2001:db8:c016::202/128 on port/s: 443
[Legend: "." for no response, "!" for an open port]
!.!!.!..!!
Host "192.0.2.4:443" (PTR: inferno.example.org) X509 CommonName="inferno.example.org" (expires in 57 days)
Host "10.75.106.201:443" (PTR: webmail.domain.cc) X509 CommonName="*.domain.cc" (expires in 824 days)
Host "10.75.106.202:443" (PTR: freeloaders.domain.cc) X509 CommonName="*.domain.cc" (expires in 824 days)
Host "10.75.106.204:443" (PTR: domain.cc) X509 CommonName="domain.cc" (expires in 460 days)
Host "10.75.106.207:443" (PTR: d1.domain.cc) X509 CommonName="d1.domain.cc" (expires in 576 days)
Host "2001:db8:c016::202:443" (PTR: freeloaders.domain.cc) X509 CommonName="*.domain.cc" (expires in 824 days)
Imported 6 certificates.
```

Rescan the networks from the example above, argus.py will detect that the certificates are already present in the vault "Public Web Servers" and will avoid storing duplicates by default (can be changed with --allow-duplicates).

```
$ argus.py -c 2001:db8:c016::202 -c 10.75.106.202/29 -c 192.0.2.4 -s safe.domain.cc -u bob -a abcde12345 --vault "Public Web Servers" --verbose --timeout 1
Enter bob's passphrase:
Press bob's Yubikey:
Found Vault "Public Web Servers" via Vaultname as Vault-ID "181"
Found Vault "Public Web Servers" via Vault-ID "181"
Using StoredSafe Server "safe.domain.cc" (URL: "https://safe.domain.cc/api/1.0")
Logged in as "bob" with the API key "abcde12345"
Using the token "xyzzyxyzzy"
Will store found certificates in Vault "Public Web Servers"
Scanning network/s: 192.0.2.4/32, 10.75.106.202/29, 2001:db8:c016::202/128 on port/s: 443
[Legend: "." for no response, "!" for an open port]
!.!!.!..!.
Host "192.0.2.4:443" (PTR: inferno.example.org) X509 CommonName="inferno.example.org" (expires in 57 days)
Found existing certificate as Object-ID "587" in Vault-ID "181"
Host "10.75.106.201:443" (PTR: webmail.domain.cc) X509 CommonName="*.domain.cc" (expires in 823 days)
Found existing certificate as Object-ID "588" in Vault-ID "181"
Host "10.75.106.202:443" (PTR: freeloaders.domain.cc) X509 CommonName="*.domain.cc" (expires in 823 days)
Found existing certificate as Object-ID "588" in Vault-ID "181"
Host "10.75.106.204:443" (PTR: domain.cc) X509 CommonName="domain.cc" (expires in 459 days)
Found existing certificate as Object-ID "590" in Vault-ID "181"
Host "10.75.106.207:443" (PTR: d1.domain.cc) X509 CommonName="d1.domain.cc" (expires in 575 days)
Found existing certificate as Object-ID "591" in Vault-ID "181"
Found 5 duplicate certificate/s.
```

## Limitations / Known issues
None known.

## License
GPL
