# isdp
This repository is a compilation of topics and concerns related to Information Security and Data Privacy (ISDP). Every example mentioned below is accessible in the public domain. The content below can be structured better, and I am looking for assistance on this; for now, compiling self-notes for a course under construction 🙂    

The importance and relevance of cybersecurity and privacy practices are only increasing with automation around us. News headlines fill our screens, reporting yet another hack, data leak, or cyber fraud. How often do we pay attention before submitting data to websites or mobile apps?     

Cybersecurity is relevant to everyone in the modern world, including a strong password policy to protect individual accounts at workplaces. Organizations must protect personally identifiable information (PII) from accidental leakage and consider minimizing data collection with the Notify and Consent principle.    

Note:- You get to be aware of constant surveillance, not just web browsers, data trackers, and over-privileged apps, but even cameras around you. Good cameras can watch you and your screen activities! There is a term for this problem: Shoulder Surfing (Someone watching over your shoulder). Identify your personal space boundary. Speak up for data collection minimization.    


  * [ISDP](#isdp)  
     * [CIA and DAD](#cia-and-dad) 
     * [OSINT](#osint)  
     * [HTTP Response Headers](#http-response-headers)  
     * [SSL/TLS Certificates](#ssl-tls-certificates)
     * [Encode Decode](#encode-decode)
     * [Weak Links](#weak-links)
     * [Incidents or Examples](#incidents-or-examples)  
     * [Cyber Threat Intelligence](#cyber-threat-intelligence)
     * [Practice and Hands-on](#hands\-on) 
     * [URL Schemes](#url-schemes) 
     * [Data Privacy](#data-privacy)
     * [Compliance and Hardening requirements](#Compliance-and-Hardening-requirements)
     * [Ethics and Governance Beyond Compliance](#ethics-and-governance-beyond-compliance) 
     * [Windows App Permissions](#windows-app-permissions) 
     * [Android App Permissions](#android-app-permissions)
     * [Random Stats](#random-stats)
     * [Quiz](#quiz)
     * [VAPT](#vapt)

## Shannon's Maxim 
Shannon's Maxim => _We should always assume that the enemy will fully know how our system works._    

[//]: <> Can we make it explicit? to make better, break better, and defend better?    

---- 

## CIA and DAD    

CIA triad is a model that guides security policies for information security. CIA triad refers to an information system's confidentiality, integrity, and availability.      

The attackers or adversaries have a mindset of another countering approach - the DAD triad that refers to disclosure, alteration, and denial of information.    

[DAD](https://library.mosse-institute.com/articles/2022/05/the-attacker-mindset-the-dad-triad/the-attacker-mindset-the-dad-triad.html)     

One of the goals of the Information System is to protect the CIA (confidentiality, integrity, and availability) and constrain DAD (disclosure, alteration, and denial).    

---- 

## OSINT 
We hear about OSINT => _Open Source INTelligence_ often in the context of information security and data privacy to gather data stealthily or by knocking on the servers' doors.    

**Passive Reconnaissance** => Your queries or packets are going to umpteen resources available on the public internet to anyone willing to query, and they are not going to your target’s environment or network. e.g., using the whois database query or DNS query for a domain    

**OSINT** => Passive reconnaissance and intelligence gathered using your target’s resources explicitly meant for public use as to a potential user, role, or affiliate. e.g., sslscan or curl query for a domain.    

[A few sources of OSINT](https://www.crowdstrike.com/cybersecurity-101/osint-open-source-intelligence/) - published studies, research papers, news articles, public data repositories, survey data, data released by government agencies, voluntary disclosures, leaked data online, archives of historical data, etc.     

[OS Intelligence (OSINT) Tools](https://www.osinttechniques.com/osint-tools.html)   

[Information you share is valuable](https://teachingprivacy.org/information-is-valuable/) and [You are leaving your footprints](https://teachingprivacy.org/youre-leaving-footprints/), that makes [Teaching Privacy](https://teachingprivacy.org) important!    

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

[Helmet library for HTTP response headers](https://www.npmjs.com/package/helmet)     

Some suggestions for [Apache server hardening](https://www.tecmint.com/apache-security-tips/)    

[Check your browser's support for Subresource Integrity (SRI)](https://wpt.live/subresource-integrity/subresource-integrity.html), [what is Subresource Integrity(SRI)](https://www.srihash.org/) - It ensures your resources hosted on 3rd-party servers are not tampered with using libraries.     

---- 

## SSL TLS Certificates 

[TLS v1.3](https://sectigostore.com/blog/tls-version-1-3-what-to-know-about-the-latest-tls-version/), [TLS v1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446) released in August 2018    

[Browser support or compatibility matrix for TLS v1.3](https://caniuse.com/tls1-3). You can upgrade your web browser once, and you should be fine for SSL compatibility.   

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

**Publically searchable SSL/TLS databases** store Certificate Transparency (CT) logs for every SSL/TLS certificate created.    

```
https://crt.sh/?q=saral.iitjammu.ac.in

crt.sh ID	 Logged At  ⇧	Not Before	Not After	Common Name	Matching Identities	Issuer Name
12457506210	2024-03-21	2024-03-21	2025-03-21	saral.iitjammu.ac.in	saral.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2

https://crt.sh/?q=eg.iitjammu.ac.in

crt.sh ID	 Logged At  ⇧	Not Before	Not After	Common Name	Matching Identities	Issuer Name
12457516850	2024-03-21	2023-10-03	2024-10-27	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
10580537009	2023-10-03	2022-10-01	2023-10-27	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
10580367151	2023-10-03	2023-10-03	2024-10-27	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
7655110496	2022-10-01	2022-10-01	2023-10-27	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
5307822883	2021-09-29	2021-09-29	2022-10-31	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
3582841268	2020-10-31	2020-10-27	2021-10-27	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
3563761812	2020-10-27	2020-10-27	2021-10-27	eg.iitjammu.ac.in	eg.iitjammu.ac.in
www.eg.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2


https://crt.sh/?q=erp.iitjammu.ac.in

crt.sh ID	 Logged At  ⇧	Not Before	Not After	Common Name	Matching Identities	Issuer Name
2827528381	2020-05-19	2020-05-12	2022-06-22	erp.iitjammu.ac.in	erp.iitjammu.ac.in
www.erp.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
2797505830	2020-05-12	2020-05-12	2022-06-22	erp.iitjammu.ac.in	erp.iitjammu.ac.in
www.erp.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
1612288285	2019-06-25	2019-06-22	2020-06-22	erp.iitjammu.ac.in	erp.iitjammu.ac.in
www.erp.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
1603025694	2019-06-22	2019-06-22	2020-06-22	erp.iitjammu.ac.in	erp.iitjammu.ac.in
www.erp.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
576000286	2018-07-06	2018-06-22	2019-06-22	erp.iitjammu.ac.in	erp.iitjammu.ac.in
www.erp.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
542356038	2018-06-22	2018-06-22	2019-06-22	erp.iitjammu.ac.in	erp.iitjammu.ac.in
www.erp.iitjammu.ac.in	C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2
```

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

## Encode Decode    

Common encoding types are base32, which converts binary data to the string of characters A-Z and 2-7, and base64, which converts using the characters a-z, A-Z, 0-9, +, / and the equals sign used for padding.   
[Base64 Encoder](https://www.base64encode.org/)     

Encoding and encryption are two different things.    

**Rainbow tables**: Online tools can help retrieve an original message from a hash using rainbow tables of stored hashes and messages.    

[crackstation.net](https://crackstation.net/) to try Hash cracker/resolver.    

[AES encryption decryption online tools](https://devglan.com/online-tools/aes-encryption-decryption)    

[MD5 and many more hashes](https://md5hashing.net/) to decode the message.    

[hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes) provides example hashes.     

----

## Weak Links 

Web browsers and passwords remain a weak link in the overall security posture.    

One should avoid [common or weak passwords](https://www.ncsc.gov.uk/blog-post/passwords-passwords-everywhere) in personal accounts and accounts at organizations/workplaces. We are the same human or individuals while managing personal and organizational accounts. Also, we carry over the same habits from one place to another. Therefore, we need to safeguard both our personal and organizational accounts with caution.     

[How common is the password-reuse problem?](https://www.troyhunt.com/only-secure-password-is-one-you-cant/)    


**Philosophy of a good and secure password**    

A secure password is the one:     
- you cannot remember    
- you can retrieve it - with what you know and what you have     
- you never shared over wire/network, and the application never displays you back *^ 
- you never shared with anyone     
- you never wrote in email drafts/notebook/online accounts     
- you never reused it on multiple sites     
- you never reused it on other sites with varying one or two digits/characters
  
*^ (Be careful when you type your passwords/PINs because Cameras watch you at 3 meters in offices, ATMs, traveling stations, public places, etc.)    

----

## Incidents or Examples   

2025   
[Gmail passwords part of 183m account data breach](https://www.forbes.com/sites/daveywinder/2025/10/26/gmail-passwords-confirmed-as-part-of-183-million-account-data-breach/) - Should every country start building its own email servers for information security and data sovereignty?     

[Fake CAPTCHA scam](https://indianexpress.com/article/technology/tech-news-technology/fake-captcha-scams-how-im-not-a-robot-could-infect-your-device-10190466/) - if sites with captcha, prompt you to follow instructions on the device with running commands or giving permissions - be careful, avoid running commands or giving permissions, exit the website and do cleanup.     

2024    
Digital Arrest - [multiple incidents](https://economictimes.indiatimes.com/news/india/digital-arrest-scam-how-cybercriminals-use-fear-to-empty-your-bank-account/articleshow/114836839.cms), [prof duped](https://education.economictimes.indiatimes.com/news/industry/retired-patna-university-professor-duped-of-rs-3-07-crore-in-digital-arrest-fraud/115460525), [Karnataka multiple cases](https://timesofindia.indiatimes.com/city/bengaluru/ktaka-loses-109cr-to-641-digital-arrest-cases-in-2024/articleshow/116265734.cms)     

[Blue Dart Courier scam](https://www.youtube.com/watch?v=m1DT6tVWf1c) still active in 2025     
WhatsApp India contact Grievance Officer (Help Center) - remember - whatsapp.com/contact     
**Never dial codes on the mobile received from unknown callers**     
**Avoid calling unknown numbers from your mobile.**    
**Avoid clicking links received from unknown callers for courier**    

Courier fraud - [This is a repeat of FedEx courier fraud and its ugly fraud](https://timesofindia.indiatimes.com/city/bengaluru/fedex-fraud-woman-made-to-strip-on-cam-loses-15l/articleshow/109145771.cms) [link2](https://www.thenewsminute.com/karnataka/fedex-scam-bengaluru-woman-made-to-strip-on-cam-transfer-rs-15-lakh).    

October 2023     
[Some of the worst cyberattacks in 2023 including Okta, MOVEit, LastPass, and T-Mobile](https://www.wired.com/story/worst-hacks-2023/)     
Rethink about the online password managers and their promises. Do not store passwords in online password managers.     

[The State of Ransomware in the U.S.: Report and Statistics 2023](https://www.emsisoft.com/en/blog/44987/the-state-of-ransomware-in-the-u-s-report-and-statistics-2023/)     

[Qakbot malware botnet infrastructure taken down](https://www.europol.europa.eu/media-press/newsroom/news/qakbot-botnet-infrastructure-shattered-after-international-operation) after affecting 7,00,00 systems and EUR 54 million paid in ransom.     

October 2023   
[Google mitigated the largest DDoS attack to date, peaking above 398 million req/sec](https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps)    

April 2023    
[Atomic macOS stealer](https://thehackernews.com/2023/04/new-atomic-macos-stealer-can-steal-your.html)    

Oct 2022   
[Insecure Direct Object Reference (IDOR)](https://www.varonis.com/blog/what-is-idor-insecure-direct-object-reference)   

June 2022     
[Summer of software patches](https://web.archive.org/web/20220710092527/https://www.wired.com/story/you-need-to-update-windows-and-chrome-right-now)    

April 2022   
Android Apps [circumventing permission model](https://blog.appcensus.io/2022/04/06/the-curious-case-of-coulus-coelib/) using SDK copying phone numbers and leaking from the device.   
[WebEx monitors microphone from browsers even when muted](https://www.securityweek.com/webex-monitors-microphone-even-when-muted-researchers-say/)     

March 2022   
A seemingly illegitimate-looking Process Manager changes its avatar to malware and downloads another app to make money.    
[link1](https://www.androidpolice.com/malware-russian-hackers-tracks-you-records-audio/) app records audio and [link2](https://lab52.io/blog/complete-dissection-of-an-apk-with-a-suspicious-c2-server/) with dissection of the issue.  


Dec 2021   
[Location data leaked even app user opted-out](https://www.vice.com/en/article/5dgmqz/huq-location-data-opt-out-no-consent)   


October 2021    
[Facebook Papers](https://www.npr.org/2021/10/25/1049015366/the-facebook-papers-what-you-need-to-know)    

December 2020   
[SolarWinds - supply chain attack](https://www.fortinet.com/resources/cyberglossary/solarwinds-cyber-attack) and a rather [untold long story of SolarWinds supply chain attack](https://www.wired.com/story/the-untold-story-of-solarwinds-the-boldest-supply-chain-hack-ever/)     

[Zimperium blog - Dissecting Mobile Native Code](https://www.zimperium.com/blog/dissecting-mobile-native-code-packers-case-study/)   

Dec 2019    
[Researcher shows access to one frame at a time for private YouTube videos, receives bounty](https://bugs.xdavidhu.me/google/2021/01/11/stealing-your-private-videos-one-frame-at-a-time/)     

2017    
[Therac25 - radiation therapy machine delivers high dose due to race condition](https://smartbear.com/blog/bug-day-race-condition-therac-25/)    

May 2017   
[WannaCry ransomware](https://www.kaspersky.com/resource-center/threats/ransomware-wannacry), [how it was stopped](https://www.cloudflare.com/en-gb/learning/security/ransomware/wannacry-ransomware/) and [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue)     

March 2017   
[Equifax data breach](https://www.csoonline.com/article/567833/equifax-data-breach-faq-what-happened-who-was-affected-what-was-the-impact.html) personally identifying data of hundreds of millions of people was stolen from Equifax (credit reporting agency)    


September 2016    
[Mirai Botnet](https://www.cloudflare.com/en-gb/learning/ddos/glossary/mirai-botnet/)   

...     

2009    
[Stuxnet - malware to target centrifuges at Iran's uranium enrichment facility outside Natanz, Iran](https://web.archive.org/web/20220728015902/https://www.cyber.nj.gov/threat-center/threat-profiles/ics-malware-variants/stuxnet)     

1998    
[l0pht (group of 7 hackers) testified on many things, bringing down the internet in 30 minutes](https://www.youtube.com/watch?v=VVJldn_MmMY), [link-3](https://www.washingtonpost.com/sf/business/2015/06/22/net-of-insecurity-part-3/), customer data thefts by organization, and security loopholes in the knowledge of companies - this was in 1998!     

1988    
[Morris Worm](https://en.wikipedia.org/wiki/Morris_worm)    

1979, 1994   
[Kevin Mitnick](https://www.mitnicksecurity.com/about-kevin-mitnick-mitnick-security) - Hacked into DEC, Bell computers, and attempts on other networks.    

----

## Cyber Threat Intelligence   

There are databases and organizations that provide a lot of data about cyber threats, incidents that occurred, and models to analyze threats.     

MITRE, OWASP, etc, have some known databases that can provide ample cyber threat intelligence.    

[OWASP top ten](https://owasp.org/www-project-top-ten/)    

[MITRE ATT&CK matrix for enterprise](https://attack.mitre.org/matrices/enterprise/). Several other [ATT&CK matrices](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf)  are published on Windows, macOS, Linux, Cloud, Mobile, etc., for categorization of adversary behavior.     

[SAST v/s DAST](https://www.blackduck.com/blog/sast-vs-dast-difference.html)    
SAST: Static Application Security Testing    
DAST: Dynamic Application Security Testing    

---- 

## Hands-on    

At times, creating and fiddling with environment setup is fun, learning, and hell yes, time-consuming. These days, you can try out online environments or playgrounds without the need to install and create complex setups. So, for those who cannot afford an environment, or system or are too lazy to set up one, browser-based online learning kits are available.     

[SEED Labs](https://seedsecuritylabs.org/) - labs from Professor Wenliang Du, Syracuse University.   

[Try Hack Me](https://tryhackme.com) - gives virtual rooms or environments accessible from within the web browser to try out a few things.    

[Hack The Box](https://www.hackthebox.com)    

[ISAC Foundation](https://isacfoundation.org)     

[Mobile Hacking Lab](https://www.mobilehackinglab.com/tryout-android-userland)     

[8ksec](https://8ksec.io/case/)    

[Online Code Editors - Playgrounds](https://github.com/rks101/webapps#online-editors-playgrounds)    

[Jupyter Labs](https://jupyter.org/try)     

Besides these, follow-up articles that dissect recent incidents up to the minute details and try out for fun.   

[Null Byte](https://null-byte.wonderhowto.com/how-to/hack-like-pro-spy-anyone-part-1-hacking-computers-0156376/) on wonderhowto.com is a nice and scary read to get a hang of what is possible in practice.     

This thread is incomplete without the mention of Offensive Security (OffSec) from where [Kali Linux](https://www.kali.org/), [Exploit-DB](https://www.exploit-db.com/), etc. have come up.   
Kali Linux has a long list of tools that can be used for OSINT, gathering details, working with tools for security hands-on, and experiencing the joy of learning.   

[Damn Vulnerable Web Applications](https://github.com/digininja/DVWA)   

[Learn and teach to write secure code](https://cr.yp.to/qmail/guarantee.html)    

[Consider contributing to SEED labs](https://github.com/seed-labs/seed-labs/blob/master/CONTRIBUTING.md)    

[Consider contributing to Open Source projects]()    

Mailing lists: Take a plung into publicly available open-source software, utilities, and their (developer) mailing lists, e.g. Linux kernel, Git, Clang, GCC, shell built-ins, Postgresql, github repositories, OSR, stack-overflow, etc.    

[Handbook on Basics of Digital Hygiene for Higher Education](https://mgcub.ac.in/pdf/202411081824431ad590ed84.pdf) by UGC, India.     

[WebGoat](https://owasp.org/www-project-webgoat/) - a deliberately insecure application to test vulnerabilities     
[iGoat](https://owasp.org/www-project-igoat-tool/) - A Learning Tool for iOS App Pentesting and Security    

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

[Google Pays Apple 36% of search revenue from Safari on iPhones to keep it default search engine](https://www.msn.com/en-in/money/news/google-s-sundar-pichai-confirms-it-pays-apple-36-of-search-revenue-from-safari/ar-AA1jXP9e?ocid=msedgntp&pc=DCTS&cvid=833d703b64f141999ce33b9a089661bd&ei=42)     

[SPARK report to address journal's Data Privacy Practices](https://sparcopen.org/news/2023/sparc-report-urges-action-to-address-concerns-with-sciencedirect-data-privacy-practices/)    

[Elevation of Privacy](https://github.com/WithSecureOpenSource/elevation-of-privacy)     

[Elevation of Privileges](https://github.com/adamshostack/eop/tree/master) Card Game     

[DeepSeek AI Privacy Policy](https://chat.deepseek.com/downloads/DeepSeek%20Privacy%20Policy.html)       

### Data Brokers and Trackers    

A data broker can be defined as a business/entity that knowingly collects and sells to third parties the personal information of a consumer with whom the business does not have a direct relationship. The country-specific laws can exempt some of these entities. Exempted businesses/entities may include consumer reporting agencies - credit bureaus, certain financial institutions, and insurance companies. e.g., In India CIBIL, CCI, NeSL, etc. may be exempted.     

Tracker:    

[The state of Mobile App Security](https://licelus.com/resources/state-of-mobile-app-security) by Lecel     

Some [companies](https://unicourt.com/) collect data from public records to share on the internet, run analytics, offer APIs, and charge a fee. e.g., Court hearings, litigation data, etc. There are [compelling reasons](https://thehill.com/opinion/technology/4820294-ai-data-public-records-privacy/) why public records should be off-limits for AI systems.     

----

## Compliance and Hardening requirements     

This section compiles a few compliance and hardening requirements.    

[Compare Data Protection laws of the world](https://www.dlapiperdataprotection.com/index.html)    

[Right to Information (RTI) in India](https://rti.gov.in/)    

[Digital Personal Data Protection Bill, 2022, India](https://www.meity.gov.in/writereaddata/files/The%20Digital%20Personal%20Data%20Protection%20Bill%2C%202022.pdf) and [press release](https://prsindia.org/billtrack/draft-the-digital-personal-data-protection-bill-2022) and [another post on privacy bills](https://blog.ipleaders.in/different-aspects-of-right-to-privacy-under-article-21/)    

[Digital Personal Data Protection Act (DPDP Act), 2023](https://www.meity.gov.in/content/digital-personal-data-protection-act-2023)    

[Cyber-Crisis Management Plan from Meity, India](https://www.cert-in.org.in/Downloader?pageid=5&type=2&fileName=CIPS-2017-0121.pdf), [CCMP from ministry](https://mowr.nic.in/core/Circulars/2022/e-Gov_21-12-2022_18.pdf), 

[GDPR - Global Data Protection Regulation in EU](https://gdpr-info.eu/)    

[Health Insurance Portability and Accountability Act (HIPPA)](https://www.cdc.gov/phlp/publications/topic/hipaa.html)    

[Children's Online Privacy Protection Rule (COPPA)](https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa)    

[California Consumer Privacy Act (CCPA)](https://oag.ca.gov/privacy/ccpa) - protects the rights of California (USA) residents to access their personal information, ask for deletion, and request that their personal data not be collected or resold. e.g., right to know, right to delete, right to opt-out, right to non-discrimination, right to correct, and right to limit.    

[California Privacy Right Act (CPRA)](https://www.mineos.ai/glossary/cpra) is an amendment to CCPA.    

[Personal Information Protection Act(PIPA)] in Japan     

[PCI DSS - Payment Card Industry Data Security Standard](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Supporting%20Document/PCI_DSS-QRG-v4_0.pdf)     

[ISO27001] Client's Data Security Protection    

[FedRAMP](https://www.gsa.gov/technology/government-it-initiatives/fedramp)     
FedRAMP refers to Federal Risk and Authorization Management Program (FedRAMP) — a US program for security assessment, authorization, and continuous monitoring for cloud products and services.     

[FIPS 140-2](https://en.wikipedia.org/wiki/FIPS_140-2)    
FIPS or Federal Information Processing Standard Publication 140-2, is a US government computer security standard used to approve cryptographic modules.   

[DISA-STIG](https://www.perforce.com/blog/kw/what-is-DISA-STIG)   
DISA STIG refers to an organization DISA — Defense Information Systems Agency that provides technical guides STIG — Security Technical Implementation Guide.    

[STIG](https://public.cyber.mil/stigs/)   
STIG refers to Security Technical Implementation Guide    

[Family Educational Rights and Privacy Act(FERPA)]()    

[Viksit Bharat at 2047 - Cybersecurity and Privacy](https://swadeshishodh.org/viksit-bharat-2047-a-look-at-the-future-of-science-and-technology/)   

---- 

## Ethics and Governance Beyond Compliance 

With growing digital infrastructure across geographies, sectors, organizations, with people of different ages, there is a need to assess ethics and governance beyond compliance.   

[Dialogue at Institute for Accountability in the Digital Age](https://i4ada.org/dialogues/)     

----

## Windows App Permissions    

[Windows 11/10 App Permissions](https://support.microsoft.com/en-us/windows/app-permissions-aea98a7c-b61a-1930-6ed0-47f0ed2ee15c)    
- What comes as a surprise to us is why and when it became normal to give permissions like "Allow elevation" and "App diagnostics"!     
- While tech companies, collect and share data, are they alone going to control and dictate terms of privacy and security?     
- Data exfiltration at the cost of using the so-called free apps and implicit consent to "Terms and Conditions" users do not read or are not shown prominently!    

---- 

## Android App Permissions     

We have conducted three separate studies and we show apps are not transparent about permissions being asked from users and permissions being used in practice!     

These studies voice our growing concerns over what an app says (looking at its application description) and what discrepancies are found when we look at permissions available to the app and what is being used inside the binary code of the app. Digital Personal Data exfiltration happens at the cost of using the so-called free app and implicit/deemed consent to "Terms and Conditions" of users do not read them or these T&Cs are not shown prominently! It has become more difficult to locate permission details than before.     

TODO: add details of studies     

---- 

## Random stats    

[Teens Spend Average of 4.8 Hours on Social Media Per Day](https://news.gallup.com/poll/512576/teens-spend-average-hours-social-media-per-day.aspx) - Source Gallup, 2023    

[41 US States sue Meta in Oct 2023](https://www.washingtonpost.com/technology/2023/10/24/meta-lawsuit-facebook-instagram-children-mental-health/) alleging the company's platforms are addictive and detrimental to children's mental health. This is how Big Tech firms deploy algorithms to maximize user engagement and profits through advt.    

----

## Quiz   

Q1. In 1942, the US government passed the Victory Act, causing the top tax rate to skyrocket to 88 percent, which rose to 94 percent in 1944 due to various surtaxes. The top tax rate in Britain rose as high as 98 percent in the 1940s. In Germany, the top tax rate climbed to 64.99 percent in 1941. What was the top tax rate in Ukraine, which was engulfed in war for over two years during 2022-24? Why?     

Q2. In India, B. Tech. Undergraduate students take 60 to 70 courses (theory, labs, projects) over four years, amounting to 120 to 160 credits as per degree requirements. How many courses does one remember for the longest time? Count yours :) After working for ten years in one or two industries, what courses s/he misses the most that should have been taught in the first college degree?     


---- 
<!-- 
## Jargons    

Privacy    
PII: Personally Identifiable Information   
RTBF: Right to Be Forgotten   
ATT: App Tracking Transparency   
DP: Differential Privacy    
PHA: Potentially Harmful Applications   
RBAC: Role-Based Access Control    

Security    
SIEM: Security information and event management    
SOC: Security Operations Center    
NOC: Network Operations Center    
TAC: Technical Assistance Center   
RMA: Return Material Authorization    
EDR: End-point detection and response   
XDR: Extended detection and response    
IAM: Identity and Access Management   
-->

## VAPT    

Vulnerability assessment and penetration testing (VAPT)     

[OWASP top 10 vulnerabilities](https://github.com/payloadbox/command-injection-payload-list)   

[Cross Site Scripting (XSS) detection tool - XSStrike](https://github.com/s0md3v/XSStrike)    

[Command injection sample payloads](https://github.com/payloadbox/command-injection-payload-list)     

[API Scanner ZAP](https://www.jit.io/blog/api-scanner-with-owasp-zap)    

[GTFOBins](https://gtfobins.github.io/) is a curated list of Unix/Linux binaries that can be used to handle local security restrictions in misconfigured systems.    

[LOLBAS](https://lolbas-project.github.io/) - "Living Off The Land Binaries, Scripts and Libraries" is a collection of Windows binaries that can be used to handle security restrictions in misconfigured systems.     

[MobSF - Mobile-Security-Framework for Android, iOS mobile apps](https://github.com/MobSF/Mobile-Security-Framework-MobSF)    

[SonarQube - Static Analyzer](https://www.sonarsource.com/products/sonarqube/)    

[Reverse Engineering iOS apps](https://web.archive.org/web/20171222000837/https://www.owasp.org/images/b/b9/OWASP_Mobile_App_Hacking_%28AppSecUSA_2014%29_Workshop_Content.pdf)    

