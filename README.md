# x509-vacuumer

x509-vacuumer.py is a simple script to locate, retrieve and store X.509 certificates in StoredSafe.

x509-vacuumer.py will parse the certificate and store relevant meta information alongside the certificate in StoredSafe.

StoredSafe's PubSub system will receive a subscription on an alert 30 days prior to the expiration date of each stored certificate.

The script is written in Python v3 and has been tested on macOS Mojave and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

Support for previous versions of StoredSafe (pre v2.1.0) can be found in the legacy branch.

## Installation instructions

This script requires Python v3 and some libraries.

It has been developed and tested using Python v3.7.7, on macOS Catalina 10.15.3.

Most of the required libraries are installed by default, but others might require manual installation. (requests, requests_toolbelt, netaddr)

```bash
sudo pip install -r requirements.txt
```

or

**requests:**

```bash
sudo -H pip install requests
```

**requests-toolbelt:**

```bash
sudo -H pip install requests-toolbelt
```

**netaddr:**

```bash
sudo -H pip install netaddr
```

## Syntax

```bash
$ x509-vacuumer.py --help
Usage: x509-vacuumer.py [-vdsuatchp]
 --verbose (or -v)              (Boolean) Enable verbose output.
 --debug (or -d)                (Boolean) Enable debug output.
 --rc <rc file>                 Use this file to obtain a valid token and a server address.
 --storedsafe (or -s) <Server>  Upload certificates to this StoredSafe server.
 --user (or -u) <user>          Authenticate as this user to the StoredSafe server.
 --apikey (or -a) <API Key>     Use this unique API key when communicating with StoredSafe.
 --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.
 --basic-auth-user <user:pw>    Specify the user name and password to use for HTTP Basic Authentication
 --cidr (or -c) <Network/CIDR>  Specify one or more IPv4 or IPv6 networks. Overlapping will be resolved.
 --host (or -h) <Hostname/FQDN> Fully qualified domain name (host.domain.cc) of host to scan. Will be resolved to IP address and aggregated.
 --port (or -p) <TCP port>      TCP port to scan for X.509 certificates. (Can be specified multiple times)
 --vault <Vaultname>            Store any found certificates in this vault. Name has to match exactly.
 --vaultid <Vault-ID>           Store any found certificates in this Vault-ID.
 --create-vault                 (Boolean) Create missing vaults.
 --policy <policy-id>           Use this password policy for newly created vaults. (Default to policy #7)
 --description <text>           Use this as description for any newly created vault. (Default to "Created by x509-vacuumer.")
 --import-expired               (Boolean) Import expired certificates. Normally, expired certificates are ignored.
 --allow-duplicates             (Boolean) Allow importing the same certificate to the same vault multiple times.
 --timeout <seconds>            Set the timeout when scanning for open ports. (default is 2 seconds)
 --list-vaults                  List all vaults accessible to the authenticated user.

Example using interactive login:
$ x509-vacuumer.py --storedsafe safe.domain.cc --user bob --apikey myapikey --cidr 2001:db8:c016::202 --cidr 10.75.106.202/29 \
 --cidr 192.0.2.4 --vault "Public Web Servers" --verbose

Example using pre-authenticated login:
$ x509-vacuumer.py --rc ~/.storedsafe.rc --cidr 2001:db8:c016::202 --host www1.domain.cc --host www2.host.cc --vault "Public Web Servers"
```

```bash
--verbose
```

> Add verbose output

```bash
--debug
```

> Add debug output

```bash
--storedsafe|-s <server>
```

> Upload certificates to this StoredSafe server

```bash
--user|-u <user>
```

> Authenticate as this StoredSafe user

```bash
--apikey|-a <apikey>
```

> Use this unique API key when communicating with StoredSafe. (Unique per application and installation)

```bash
--token <token>
```

> Use pre-authenticated token instead of ```--user``` and ```--apikey```, also removes requirement to login with passphrase and OTP.

```bash
--basic-auth-user <user:pw>
```

> Specify the user name and password to use for HTTP Basic Authentication.

```bash
--cidr|-c <ipv4 or IPv6 network>
```

> Specify one or more IPv4 or IPv6 networks. Overlapping will be resolved.

```bash
--host|-h <fqdn hostname>
```

> Fully qualified domain name (host.domain.cc) of host to scan. Will be resolved to IP address and aggregated with any CIDR objects (```--cidr```)

```bash
--port|-p <tcp port to scan>
```

> TCP port to scan

```bash
--vault|-v <Vaultname>
```

> Store any found certificates in this vault. Name has to match exactly.

```bash
--vaultid <Vault-ID>
```

> Store any found certificates in this Vault-ID.

```bash
--create-vault
```

> Create missing vaults.

```bash
--policy <policy-id>
```

> Use this password policy for newly created vaults. (Default to 7)

```bash
--description <text>
```

> Use this as description for any newly created vault. (Default to "Created by x509-vacuumer.")

```bash
--import-expired
```

> Import expired certificates. Normally, expired certificates are ignored.

```bash
--allow-duplicates
```

> Allow importing the same certificate to the same vault multiple times.

```bash
--timeout
```

> Set the timeout when scanning for open ports. Defaults to 2 seconds.

```bash
--list-vaults
```

> List all vaults accessible to the authenticated user.

## Usage

Scan the networks 2001:db8:c016::202/128, 10.75.106.202/29 and 192.0.2.4/32 on port 443 for X.509 certificates. Store any certificates found in the "Public Web Servers" Vault on the StoredSafe server "safe.domain.cc" and arm an alarm that will fire 30 days prior to each certificates expiration date.

```bash
$ x509-vacuumer.py -c 2001:db8:c016::202 -c 10.75.106.202/29 -c 192.0.2.4 -p 443 -s safe.domain.cc -u bob --apikey myapikey --vault "Public Web Servers" --verbose
Enter bob's passphrase:
Press bob's Yubikey:
Using StoredSafe Server "safe.domain.cc" (URL: "https://safe.domain.cc/api/1.0")
Logged in as "bob" with the API key "MyAPIKey"
Using the token "XyzzyXyzzy"
Will store found certificates in Vault "Public Web Servers" (Vault-ID 181)
Scanning network/s: 192.0.2.4/32, 10.75.106.202/29, 2001:db8:c016::202/128 on port/s: 443
[Legend: "." for no response, "!" for an open port]
!.!!.!..!!
Host "192.0.2.4:443" (PTR: inferno.example.org, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="inferno.example.org" (expires in 57 days)
Host "10.75.106.201:443" (PTR: webmail.domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="*.domain.cc" (expires in 824 days)
Host "10.75.106.202:443" (PTR: freeloaders.domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="*.domain.cc" (expires in 824 days)
Host "10.75.106.204:443" (PTR: domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="domain.cc" (expires in 460 days)
Host "10.75.106.207:443" (PTR: d1.domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="d1.domain.cc" (expires in 576 days)
Host "2001:db8:c016::202:443" (PTR: freeloaders.domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="*.domain.cc" (expires in 824 days)
Imported 6 certificates.
```

Rescan the networks from the example above, x509-vacuumer.py will detect that the certificates are already present in the vault "Public Web Servers" and will avoid storing duplicates by default (can be changed with --allow-duplicates).

```bash
$ x509-vacuumer.py -c 2001:db8:c016::202 -c 10.75.106.202/29 -c 192.0.2.4 -s safe.domain.cc -u bob -a abcde12345 --vault "Public Web Servers" --verbose --timeout 1
Enter bob's passphrase:
Press bob's Yubikey:
Using StoredSafe Server "safe.domain.cc" (URL: "https://safe.domain.cc/api/1.0")
Logged in as "bob" with the API key "abcde12345"
Using the token "xyzzyxyzzy"
Will store found certificates in Vault "Public Web Servers" (Vault-ID 181)
Scanning network/s: 192.0.2.4/32, 10.75.106.202/29, 2001:db8:c016::202/128 on port/s: 443
[Legend: "." for no response, "!" for an open port]
!.!!.!..!.
Host "192.0.2.4:443" (PTR: inferno.example.org, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="inferno.example.org" (expires in 57 days)
Found existing certificate as Object-ID "587" in Vault-ID "181"
Host "10.75.106.201:443" (PTR: webmail.domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="*.domain.cc" (expires in 823 days)
Found existing certificate as Object-ID "588" in Vault-ID "181"
Host "10.75.106.202:443" (PTR: freeloaders.domain.cc, TLSv1.3: TLS_AES_256_GCM_SHA384) X509 CommonName="*.domain.cc" (expires in 823 days)
Found existing certificate as Object-ID "588" in Vault-ID "181"
Host "10.75.106.204:443" (PTR: domain.cc, TLSv1.2: ECDHE-RSA-AES128-GCM-SHA256) X509 CommonName="domain.cc" (expires in 459 days)
Found existing certificate as Object-ID "590" in Vault-ID "181"
Host "10.75.106.207:443" (PTR: d1.domain.cc, TLSv1.2: ECDHE-RSA-AES128-GCM-SHA256) X509 CommonName="d1.domain.cc" (expires in 575 days)
Found existing certificate as Object-ID "591" in Vault-ID "181"
Found 5 duplicate certificate/s.
```

## Limitations / Known issues

No known limitation.

## Contributors

Fredrik Eriksson  
Daniel Eriksson  
Willem Stolk  

## License

GPL
