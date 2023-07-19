# isdp
This repository is a compilation of Information Security and Data Privacy (ISDP) topics and concerns with some examples - everything accessible in the public domain. The content below can be structured better, and I am looking for assistance on this, for now, compiling self-notes.    


  * [ISDP](#isdp)  
     * [OSINT](#osint)  
     * [HTTP Response Headers](#http-response-headers)  
     * [SSL/TLS Certificates](#ssl-tls-certificates)
     * [Weak Links](#weak-links)
     * [Incidents or Examples](#incidents-or-examples)  
     * [Cyber Threat Intelligence](#cyber-threat-intelligence)  
     * [Practice and Hands-on](#hands\-on) 
     * [URL Schemes](#url-schemes) 
     * [Data Privacy](#data-privacy)  

## Shannon's Maxim 
Shannon's Maxim => _We should always assume that the enemy will fully know how our system works._   

## OSINT 
We hear about OSINT => _Open Source INTelligence_ often in the context of information security and data privacy to gather data stealthily or knock on the servers' doors.    

**Passive Reconnaissance** => Your queries or packets are going to umpteen resources available on the public internet to anyone willing to query, and they are not going to your target’s environment or network. e.g., using the whois database query or DNS query for a domain    

**OSINT** => Passive reconnaissance and intelligence gathered using your target’s resources explicitly meant for public use as to a potential user, role, or affiliate. e.g., sslscan or curl query for a domain.    


[OS Intelligence (OSINT) Tools](https://www.osinttechniques.com/osint-tools.html)   

[Information you share is valuable](https://teachingprivacy.org/information-is-valuable/) and [You are leaving your footprints](https://teachingprivacy.org/youre-leaving-footprints/) at [Teaching Privacy](https://teachingprivacy.org)    

[Our World in Data](https://ourworldindata.org/)   

----

## HTTP Response Headers   

You can use curl to view HTTP headers.    

```
$ curl -v eg.iitjammu.ac.in 
*   Trying 13.126.157.211:80...
* Connected to eg.iitjammu.ac.in (13.126.157.211) port 80 (#0)
> GET / HTTP/1.1                                      <-- Request Headers
> Host: eg.iitjammu.ac.in                             <--
> User-Agent: curl/7.81.0                             <--
> Accept: */*                                         <--
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Tue, 13 Jun 2023 13:19:30 GMT
< Server: Apache                                     <-- Response Headers
< Referrer-Policy: strict-origin                     <--
< X-Frame-Options: SAMEORIGIN                        <--
< Location: https://eg.iitjammu.ac.in/               <--
< Content-Length: 210 
< Content-Type: text/html; charset=iso-8859-1        <--
< 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="https://eg.iitjammu.ac.in/">here</a>.</p>
</body></html>
* Connection #0 to host eg.iitjammu.ac.in left intact
```
Or see only HTTP Response headers:    
```
$ curl -I eg.iitjammu.ac.in 
HTTP/1.1 302 Found
Date: Tue, 13 Jun 2023 13:19:36 GMT
Server: Apache
Referrer-Policy: strict-origin
X-Frame-Options: SAMEORIGIN
Location: https://eg.iitjammu.ac.in/
Content-Type: text/html; charset=iso-8859-1
```
Here is some more info using -Lvso options with curl:     
```
$ curl -Lvso /dev/null  eg.iitjammu.ac.in
*   Trying 13.126.157.211:80...
* Connected to eg.iitjammu.ac.in (13.126.157.211) port 80 (#0)
> GET / HTTP/1.1
> Host: eg.iitjammu.ac.in
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Tue, 13 Jun 2023 13:32:32 GMT
< Server: Apache
< Referrer-Policy: strict-origin
< X-Frame-Options: SAMEORIGIN
< Location: https://eg.iitjammu.ac.in/
< Content-Length: 210
< Content-Type: text/html; charset=iso-8859-1
< 
* Ignoring the response-body
{ [210 bytes data]
* Connection #0 to host eg.iitjammu.ac.in left intact
* Clear auth, redirects to port from 80 to 443
* Issue another request to this URL: 'https://eg.iitjammu.ac.in/'
*   Trying 13.126.157.211:443...
* Connected to eg.iitjammu.ac.in (13.126.157.211) port 443 (#1)
* ALPN, offering h2
* ALPN, offering http/1.1
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLSv1.0 (OUT), TLS header, Certificate Status (22):
} [5 bytes data]
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
} [512 bytes data]
* TLSv1.2 (IN), TLS header, Certificate Status (22):
{ [5 bytes data]
* TLSv1.3 (IN), TLS handshake, Server hello (2):
{ [108 bytes data]
* TLSv1.2 (IN), TLS header, Certificate Status (22):
{ [5 bytes data]
* TLSv1.2 (IN), TLS handshake, Certificate (11):
{ [5135 bytes data]
* TLSv1.2 (IN), TLS header, Certificate Status (22):
{ [5 bytes data]
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
{ [333 bytes data]
* TLSv1.2 (IN), TLS header, Certificate Status (22):
{ [5 bytes data]
* TLSv1.2 (IN), TLS handshake, Server finished (14):
{ [4 bytes data]
* TLSv1.2 (OUT), TLS header, Certificate Status (22):
} [5 bytes data]
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
} [70 bytes data]
* TLSv1.2 (OUT), TLS header, Finished (20):
} [5 bytes data]
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
} [1 bytes data]
* TLSv1.2 (OUT), TLS header, Certificate Status (22):
} [5 bytes data]
* TLSv1.2 (OUT), TLS handshake, Finished (20):
} [16 bytes data]
* TLSv1.2 (IN), TLS header, Finished (20):
{ [5 bytes data]
* TLSv1.2 (IN), TLS header, Certificate Status (22):
{ [5 bytes data]
* TLSv1.2 (IN), TLS handshake, Finished (20):
{ [16 bytes data]
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=eg.iitjammu.ac.in
*  start date: Oct  1 07:06:43 2022 GMT
*  expire date: Oct 27 10:53:42 2023 GMT
*  subjectAltName: host "eg.iitjammu.ac.in" matched cert's "eg.iitjammu.ac.in"
*  issuer: C=US; ST=Arizona; L=Scottsdale; O=GoDaddy.com, Inc.; OU=http://certs.godaddy.com/repository/; CN=Go Daddy Secure Certificate Authority - G2
*  SSL certificate verify ok.
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
} [5 bytes data]
> GET / HTTP/1.1
> Host: eg.iitjammu.ac.in
> User-Agent: curl/7.81.0
> Accept: */*
> 
* TLSv1.2 (IN), TLS header, Supplemental data (23):
{ [5 bytes data]
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Tue, 13 Jun 2023 13:32:32 GMT
< Server: Apache
< Referrer-Policy: strict-origin
< X-Frame-Options: SAMEORIGIN
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Vary: Accept-Encoding
< Strict-Transport-Security: max-age=31536000; includeSubDomains;
< Permissions-Policy: geolocation=self
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Content-Security-Policy: object-src 'self';
< Set-Cookie: PHPSESSID=119d24bsdd960eobotctq6vgm36oajqti37u69l94nf8pigatb11; path=/; HttpOnly;Secure
< Content-Length: 2108
< Content-Type: text/html; charset=UTF-8
< 
* TLSv1.2 (IN), TLS header, Supplemental data (23):
{ [5 bytes data]
* Connection #1 to host eg.iitjammu.ac.in left intact
```


You can check your website's HTTP **response headers** at [securityheaders.com](https://securityheaders.com/)   

For a top-graded website and W3C compliance, set the following HTTP headers to suitable values:    
Strict-Transport-Security <== HSTS   
X-Frame-Options   
X-Content-Type-Options   
Content-Security-Policy     
Referrer-Policy   
Permissions-Policy    

Every sysad and webmaster should consider [hardening HTTP response headers](https://scotthelme.co.uk/hardening-your-http-response-headers/).   

Some suggestions for [Apache server hardening](https://www.tecmint.com/apache-security-tips/)    

---- 

## SSL TLS Certificates 

[TLS v1.3](https://sectigostore.com/blog/tls-version-1-3-what-to-know-about-the-latest-tls-version/), [TLS v1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446) released in August 2018    

[Browser support or compatibility matrix for TLS v1.3](https://caniuse.com/tls1-3). You can upgrade your web browser once, and you should be fine.   

[TLS versions](https://www.covetus.com/blog/different-versions-of-transfer-layer-security-tls-its-working-and-benefits)   
[TLS versions comparison](https://thesecmaster.com/what-is-ssl-tls-how-ssl-tls-1-2-and-tls-1-3-differ-from-each-other/)    

[Enable/Disable TLS versions on popular servers](https://thesecmaster.com/how-to-enable-tls-1-3-on-popular-web-servers/) and [disable older TLS versions](https://www.ssl.com/guide/disable-tls-1-0-and-1-1-apache-nginx/)   

To disable obsolete versions of SSL/TLS supported by Apache on Ubuntu, specify them as follows in /etc/apache2/mods-enabled/ssl.conf, e.g.:
```
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```
and to allow TLSv1.2 and v1.3 only:   
```
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

Finally, check the sslscan output, TLS certificate checks like the one by [SSL Labs](https://www.ssllabs.com/ssltest) and [DigiCert](https://www.digicert.com/help/) for TLS certs, and some basic vulnerability checks.   

[Understand Online Certificate Status Protocol (OCSP) and Certificate Revokation](https://www.thesslstore.com/blog/ocsp-ocsp-stapling-ocsp-must-staple/)    

On the client side, do not ignore [SSL/TLS Certificate Errors and ways to address them](https://sematext.com/blog/ssl-certificate-error/)   

For **SendGrid domain whitelisting** validation error [check Top-Level-Domain auto-appending](https://web.archive.org/web/20170706082258/https://sendgrid.com/docs/Classroom/Troubleshooting/Authentication/i_have_created_dns_records_but_the_whitelabel_wizard_is_not_validating_them.html). You should check existing entries in DNS too.   

[SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)    

**System upgrade: You may need to upgrade the Apache server to v2.4.38 or higher, open SSL to v1.1.1 or higher, and Ubuntu OS for TLS v1.3    

Notes:-    
* SSL/TLS Certificates are valid for a maximum of 398 days. You should take care of the time zone if the issuer is not in the same time zone as the host.    
* Paid TLS certificates do not use better cryptography than free certificates (e.g., Let's Encrypt). Paid TLS can give you extended validity on certificates.    
* Subject Alternate Name (SAN) or multi-domain TLS certificates allow additional host names to be protected by the same /single TLS certificate when creating the certificate.   
* Apache allows you to virtually host multiple HTTPS sites with a single public IP address using SAN certificates.    
* Wildcard certificate can protect all sub-domains of the same suffix top-level domain (TLD), e.g., *.mydomain.com - while for *.mydomain.org, you need a separate certificate.   
* SSL is only referred to for historical reasons. Most SSL/TLS certificates currently use TLS v1.2 / v1.3.   
* Web browsers have a hardcoded list of trusted certificate authorities (CA) to check that your certificate is signed by someone it trusts.   
* You can make a "self-signed" TLS certificate. Because a trusted certificate authority does not sign that certificate, browsers won't accept it.   

\citations for TLS notes: [1](https://questions.wizardzines.com/tls-certificates.html) and [2](https://www.digicert.com/faq/public-trust-and-certificates)   

----

Using `openssl` for SSL/TLS certificates    

e.g., check if a remote server uses TLSv1.2 - if you get the certificate chain back, it's all good.    
```
openssl s_client -connect server:port -tls1_2 
```    

```
$ openssl s_client -connect eg.iitjammu.ac.in:443 -tls1_2
CONNECTED(00000003)
depth=2 C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
verify return:1
depth=1 C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
verify return:1
depth=0 CN = eg.iitjammu.ac.in
verify return:1
---
**Certificate chain** 
 0 s:CN = eg.iitjammu.ac.in
   i:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Oct  1 07:06:43 2022 GMT; NotAfter: Oct 27 10:53:42 2023 GMT
 1 s:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
   i:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: May  3 07:00:00 2011 GMT; NotAfter: May  3 07:00:00 2031 GMT
 2 s:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
   i:C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jan  1 07:00:00 2014 GMT; NotAfter: May 30 07:00:00 2031 GMT
 3 s:C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
   i:C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA1
   v:NotBefore: Jun 29 17:06:20 2004 GMT; NotAfter: Jun 29 17:06:20 2034 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIblahblahblahvsgfsgdfgdfgdghdhddhgdfgnfgdhfgfsgdfhhhdhdfnrjtukui
........
dshfjdshfssgfsjgjgsjfblahblahblahpakpakpakakpakpakpakakddsjldkd/w
pakpakpakakpakpakpakak==
-----END CERTIFICATE-----
subject=CN = eg.iitjammu.ac.in
issuer=C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
---
No client certificate CA names sent
Peer signing digest: SHA512
Peer signature type: RSA
Server Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 5831 bytes and written 340 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 79D976C30E8574E4D021E5CF187E27266DD42B368F351A4BFDA865E5EDD8419A
    Session-ID-ctx: 
    Master-Key: B398AD1FBD71E606C4070D86C95808257FB17019ABDA3170F3DFE0B66BC4ACD0D0A11717EA592ACFC9922B11C5D0D531
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 76 31 07 c5 fd 87 0a 74-32 80 20 c2 bd 6f dd 35   v1.....t2. ..o.5
    0010 - ef d7 ac b0 d1 bd 8a e0-15 b9 23 90 72 de 37 1a   ..........#.r.7.
    0020 - 02 08 81 65 2c 54 7a ea-65 77 c1 fb f2 0d a4 fc   ...e,Tz.ew......
    ..............                                           ...
    00b0 - a3 f6 13 72 2a 92 33 cc-68 46 b0 e4 ff 0c 73 24   ...r*.3.hF....s$
    00c0 - 3b 46 c5 64 02 62 f9 ac-01 1a d6 45 f4 b6 7a f3   ;F.d.b.....E..z.

    Start Time: 1689317360
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
```
----

What is my OpenSSL version? 
```
$ openssl version -a
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
built on: Wed May 24 17:12:55 2023 UTC
platform: debian-amd64
options:  bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -Wa,--noexecstack -g -O2 -ffile-prefix-map=/build/openssl-Z1YLmC/openssl-3.0.2=. -flto=auto -ffat-lto-objects -flto=auto -ffat-lto-objects -fstack-protector-strong -Wformat -Werror=format-security -DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2
OPENSSLDIR: "/usr/lib/ssl"
ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-3"
MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
Seeding source: os-specific
CPUINFO: OPENSSL_ia32cap=0x7ffaf3bfffebffff:0x18c05fdef3bfa7eb

```
[Online OpenSSL cookbook](https://www.feistyduck.com/library/openssl-cookbook/online/)     

----

## Weak Links 

Browser and passwords remain a weak link in the overall security posture.    

One should avoid [common or weak passwords](https://www.ncsc.gov.uk/blog-post/passwords-passwords-everywhere) in personal accounts as well as accounts at organizations.     

[How common is the password-reuse problem?](https://www.troyhunt.com/only-secure-password-is-one-you-cant/)    


Philosophy of a good and secure password:    
A secure password is the one:     
- you cannot remember    
- you can retrieve it with what you know and what you have     
- you never shared over wire/network, and the application never displays you back    
- you never shared with anyone     
- you never wrote in email drafts/notebook/online accounts     


----

## Incidents or Examples   

April 2023    
[Atomic macOS stealer](https://thehackernews.com/2023/04/new-atomic-macos-stealer-can-steal-your.html)    

Oct 2022   
[Insecure Direct Object Reference (IDOR)](https://www.varonis.com/blog/what-is-idor-insecure-direct-object-reference)   


April 2022   
Android Apps [circumventing permission model](https://blog.appcensus.io/2022/04/06/the-curious-case-of-coulus-coelib/) using SDK copying phone numbers and leaking from the device.   


March 2022   
A seemingly-legitimate looking Process Manager changes its avatar to malware and downloads another app to make money. [link1](https://www.androidpolice.com/malware-russian-hackers-tracks-you-records-audio/) app records audio and [link2](https://lab52.io/blog/complete-dissection-of-an-apk-with-a-suspicious-c2-server/) with dissection of the issue.  


Dec 2021   
[Location data leaked even app user opted-out](https://www.vice.com/en/article/5dgmqz/huq-location-data-opt-out-no-consent)   


October 2021    
[Facebook Papers](https://www.npr.org/2021/10/25/1049015366/the-facebook-papers-what-you-need-to-know)    

December 2020   
SolarWinds - supply chain attack    

May 2017   
WannaCry ransomware    

September 2016    
[Mirai Botnet](https://www.cloudflare.com/en-gb/learning/ddos/glossary/mirai-botnet/)   



1998    
[l0pht (group of 7 hackers) testifies on many things, bringing down the internet in 30 minutes](https://www.youtube.com/watch?v=VVJldn_MmMY), [link-3](https://www.washingtonpost.com/sf/business/2015/06/22/net-of-insecurity-part-3/), customer data thefts by organization, and security holes in the knowledge of companies - this was in 1998!     

1988    
[Morris Worm](https://en.wikipedia.org/wiki/Morris_worm)    

1979, 1994   
[Kevin Mitnick](https://www.mitnicksecurity.com/about-kevin-mitnick-mitnick-security) - Hacked into DEC, Bell computers, and attempts on other networks.    

----

## Cyber Threat Intelligence   

There are databases and organizations that provide a lot of data about cyber threats, incidents that occurred, and models to analyze threats.     

MITRE, OWASP, etc, have some known databases that can provide ample cyber threat intelligence.    

[OWASP top ten](https://owasp.org/www-project-top-ten/)    

[MITRE ATT&CK matrix for enterprise](https://attack.mitre.org/matrices/enterprise/). Several other [ATT&CK matrices](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf)  are published on Windows, macOS, Linux, Cloud, Mobile, etc. for categorization of adversary behavior.     


---- 

## Hands-on    

At times, creating and fiddling with environment setup is fun, learning, and hell yes, time consuming. These days, you can try out online environments or playgrounds without the need to install and create complex setups. So, for all those who cannot afford to have an environment or are too lazy to set up one, there are browser-based online learning kits available.     

[Try Hack Me](https://tryhackme.com) - gives virtual rooms or environments accessible from within the web browser to try out a few things.    

[Online Code Editors - Playgrounds](https://github.com/rks101/webapps#online-editors-playgrounds)    

[Jupyter Labs](https://jupyter.org/try)     

Besides these, follow-up articles that dissect recent incidents up to the minute details and try out for fun.   

[Null Byte](https://null-byte.wonderhowto.com/how-to/hack-like-pro-spy-anyone-part-1-hacking-computers-0156376/) on wonderhowto.com is a nice and scary read, at least to get a hang of what is possible in practice.     

This thread is incomplete without the mention of Offensive Security (OffSec) from where [Kali Linux](https://www.kali.org/), [Exploit-DB](https://www.exploit-db.com/), etc. have come up.   
Kali Linux has a long list of tools that can be used for OSINT and gathering details and working with tools of interest for checking on security and experiencing the joy of learning.   

[Damn Vulnerable Web Applications](https://github.com/digininja/DVWA)   

[Learn and teach to write secure code](https://cr.yp.to/qmail/guarantee.html)    

----

## URL Schemes 

[Android URL Schemes](https://dev.iridi.com/URL_Scheme/en#Android_URL_schemes)    
[Apple/Safari URL Schemes](https://dev.iridi.com/URL_Scheme/en#Apple_URL_schemes)     
e.g. open wallet:// or music:// in Safari on Apple phone/tablet/laptop.   

---- 

## Data Privacy  

[Five key privacy principles](https://www.computerworld.com/article/2574182/five-key-privacy-principles.html): Notice/Awareness, Choice/Consent, Access/Participation, Integrity/Security, and Enforcement/Redress    

[Terms of Service didn't read](https://tosdr.org/): “I have read and agree to the Terms” is the biggest lie on the web. TOSDR aims to fix that.   


[Sharing information - A day in your life](https://consumer.ftc.gov/media/video-0022-sharing-information-day-your-life) from [consumer.ftc.gov](https://consumer.ftc.gov).    


[A day in the life of your data](https://www.apple.com/privacy/docs/A_Day_in_the_Life_of_Your_Data.pdf) from Apple.    



----

## Guidelines and standards     

Compliance and hardening requirements   


FedRAMP    

HIPPA    

COPPA    

FIPS 140-2   

[DISA-STIG](https://www.perforce.com/blog/kw/what-is-DISA-STIG)   

[STIG](https://public.cyber.mil/stigs/)   

CIS and Coomon Criteria   

---- 
