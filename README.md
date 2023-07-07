# isdp
Information Security and Data Privacy topics and concerns with some examples - everything accessible in public domain. Surely, the content below can be structured in a better way and I am looking for assistance on this, for now, compliing self-notes.    


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
Shannon's Maxim => _We should always assume that the enemy will have full knowledge of how our system works._   

## OSINT 
OSINT => _Open Source INTelligence_   

**Passive Reconnaissance** => your queries or packets are going to umpteen resources that are available on the public internet to anyone willing to query and they are not going to your target’s environment or network. e.g. using whois database query or DNS query for a domain    
**OSINT** => Passive reconnaissance and intellegence gathered using your target’s resources that are explicitly meant for public use as to a potential user or role or affiliate. e.g. sslscan or curl query for a domain.    


Jan 2023   
[OS Intelligence (OSINT) Tools](https://www.osinttechniques.com/osint-tools.html)   

[Information you share is valuable](https://teachingprivacy.org/information-is-valuable/) and [You are leaving your footprints](https://teachingprivacy.org/youre-leaving-footprints/) at [Teaching Privacy](https://teachingprivacy.org)    

[SSL Labs](https://www.ssllabs.com/ssltest) and [DigiCert](https://www.digicert.com/help/)   

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
Even more info with -Lvso options with curl:     
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

For a top graded website and W3C compliance, set the following HTTP headers to suitable values:    
Strict-Transport-Security   
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
[Browser support or compatiability matrix for TLS v1.3](https://caniuse.com/tls1-3). Upgrade your web-browser once and you should be fine.   

[TLS versions](https://www.covetus.com/blog/different-versions-of-transfer-layer-security-tls-its-working-and-benefits)   
[TLS versions comparison](https://thesecmaster.com/what-is-ssl-tls-how-ssl-tls-1-2-and-tls-1-3-differ-from-each-other/)   
[Enable/Disable TLS versions on popular servers](https://thesecmaster.com/how-to-enable-tls-1-3-on-popular-web-servers/) and [disable older TLS versions](https://www.ssl.com/guide/disable-tls-1-0-and-1-1-apache-nginx/)   

To disable obsolete versions of SSL/TLS supported by Apache on Ubuntu specify them as follows in /etc/apache2/mods-enabled/ssl.conf, e.g.:
```
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```
and to allow TLSv1.2 and v1.3 only:   
```
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

Finally, keep on checking sslscan output, TLS certificate checks like one by [SSL Labs](https://www.ssllabs.com/ssltest/) for TLS certs and some basic vulnerability checks.   

At client side, do not ignore [SSL/TLS Certificate Errors and ways to address them](https://sematext.com/blog/ssl-certificate-error/)   
For SendGrid domain whitelisting validation error [check Top-Level-Domain auto-appending](https://web.archive.org/web/20170706082258/https://sendgrid.com/docs/Classroom/Troubleshooting/Authentication/i_have_created_dns_records_but_the_whitelabel_wizard_is_not_validating_them.html). You should check existing entries in DNS too.   

----

## Weak Links 

Browser and passwords remain a weak link in overall security posture.    

One should avoid [common or weak passwords](https://www.ncsc.gov.uk/blog-post/passwords-passwords-everywhere) in personal accounts as well as accounts at organizations.     

[How common is password-reuse problem?](https://www.troyhunt.com/only-secure-password-is-one-you-cant/)    


Philosophy of a good and secure password:    
A secure password is the one:     
- you cannot remember    
- you can retrieve it with what you know and what you have     
- you never shared over wire/network and application never displayed you back    
- you never shared with anyone     
- you never wrote in email drafts/notebook/online accounts     


----

## Incidents or Examples   

April 2023    
[Atomic macOS stealer](https://thehackernews.com/2023/04/new-atomic-macos-stealer-can-steal-your.html)    

Oct 2022   
[Insecure Direct Object Reference (IDOR)](https://www.varonis.com/blog/what-is-idor-insecure-direct-object-reference)   


April 2022   
Android Apps [circumventing permission model](https://blog.appcensus.io/2022/04/06/the-curious-case-of-coulus-coelib/) using SDK copying phone numbers and leaking from device.   


March 2022   
A seemingly-legitimate looking Process Manager changes its avatar to malware and downloads another app to make money. [link1](https://www.androidpolice.com/malware-russian-hackers-tracks-you-records-audio/) app records audio and [link2](https://lab52.io/blog/complete-dissection-of-an-apk-with-a-suspicious-c2-server/) with dissection of the issue.  


Dec 2021   
[Location data leaked even app user opted-out](https://www.vice.com/en/article/5dgmqz/huq-location-data-opt-out-no-consent)   


October 2021    
[Facebook Papers](https://www.npr.org/2021/10/25/1049015366/the-facebook-papers-what-you-need-to-know)    

September 2016    
[Mirai Botnet](https://www.cloudflare.com/en-gb/learning/ddos/glossary/mirai-botnet/)   



1998    
[l0pht testifies on many things and to bring down internet](https://www.youtube.com/watch?v=VVJldn_MmMY), customer data thefts are not new incidents!     

1988    
[Morris Worm](https://en.wikipedia.org/wiki/Morris_worm)    

----

## Cyber Threat Intelligence   

There are databases and organisations that provide a lot of data about cyber threats, incidents occurred, and models to analysis threats.     

MITRE, OWASP, etc, have some known databases that can provide ample cyber threat intelligence.    

[OWASP top ten](https://owasp.org/www-project-top-ten/)    

[MITRE ATT&CK matrix for enterprise](https://attack.mitre.org/matrices/enterprise/). Several other [ATT&CK matrices](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf)  are published on Windows, macOS, Linux, Cloud, Mobile, etc. for categorisation of adversary behaviour.     


---- 

## Hands-on    

At times, creating and fiddling with environment set up is fun, learning, and hell yes, time consumming. These days, you can try out online environemnt or playgrounds without a need to install and create complex set up. So, for all those who cannot afford to have an environment or are too lazy to set up one, there are browser-based online learning kits available.     

[Try Hack Me](https://tryhackme.com) - gives virtual rooms or environment accessible from within browser to try out a few things.    

[Online Code Editors - Playgrounds](https://github.com/rks101/webapps#online-editors-playgrounds)    

[Jupyter Labs](https://jupyter.org/try)     

Besides these, follow up articles that dissect recent incidents up to the minute details and try out for fun.   

[Null Byte](https://null-byte.wonderhowto.com/how-to/hack-like-pro-spy-anyone-part-1-hacking-computers-0156376/) on wonderhowto.com is a nice and scary read, at least to get a hang of what is possible in practice.     

This thread is incomeplete without the mention of Offensive Security (OffSec) from where [Kali Linux](https://www.kali.org/), [Exploit-DB](https://www.exploit-db.com/),etc. have come up.   
Kali linux has a long list of tools that can be used for OSINT and gathering details and working with tools of interest for checking on security and experiencing the joy of learning.   

[Damn Vulnerable Web Applications](https://github.com/digininja/DVWA)   


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
