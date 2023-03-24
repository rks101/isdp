# isdp
Information Security and Data Privacy concerns with some examples.   
Surely, the content below is unstructured and looking for assistance.   


## Shannon's Maxim 
Shannon's Maxim => _We should always assume that the enemy will have full knowledge of how our system works._   

## OSINT 
OSINT => _Open Source INTelligence_   

**Passive Reconnaissance** => your queries or packets are going to umpteen resources that are available on the public internet to anyone willing to query and they are not going to your target’s environment or network.    
**OSINT** => Passive reconnaissance and intellegence gathered using your target’s resources that are explicitly meant for public use as to a potential user or role or affiliate.   


Jan 2023   
[OS Intelligence (OSINT) Tools](https://www.osinttechniques.com/osint-tools.html)   

[Information you share is valuable](https://teachingprivacy.org/information-is-valuable/) and [You are leaving your footprints](https://teachingprivacy.org/youre-leaving-footprints/) at [Teaching Privacy](https://teachingprivacy.org)    

**HTTP Response Headers**  
Check your website's HTTP **security headers** at [securityheaders.com](https://securityheaders.com/)   
For a top graded website and W3C compliance, set HTTP headers to suitable values: 
Strict-Transport-Security   
X-Frame-Options   
X-Content-Type-Options   
Content-Security-Policy    
Referrer-Policy   
Permissions-Policy    


Oct 2022   
[Insecure Direct Object Reference (IDOR)](https://www.varonis.com/blog/what-is-idor-insecure-direct-object-reference)   

[TLS 1.3](https://sectigostore.com/blog/tls-version-1-3-what-to-know-about-the-latest-tls-version/)   
[TLS versions](https://www.covetus.com/blog/different-versions-of-transfer-layer-security-tls-its-working-and-benefits)   
[TLS versions comparison](https://thesecmaster.com/what-is-ssl-tls-how-ssl-tls-1-2-and-tls-1-3-differ-from-each-other/)   
[Enable/Disable TLS versions on popular servers](https://thesecmaster.com/how-to-enable-tls-1-3-on-popular-web-servers/) and [disable older TLS versions](https://www.ssl.com/guide/disable-tls-1-0-and-1-1-apache-nginx/)   
To disable obsolete versions of SSL/TLS supported by Apache on Ubuntu specify them as follows in /etc/apache2/mods-enabled/ssl.conf:
```
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```

April 2022   
Android Apps [circumventing permission model](https://blog.appcensus.io/2022/04/06/the-curious-case-of-coulus-coelib/) using SDK copying phone numbers and leaking from device.   


March 2022   
A seemingly-legitimate looking Process Manager changes its avatar to malware and downloads another app to make money. [link1](https://www.androidpolice.com/malware-russian-hackers-tracks-you-records-audio/) app records audio and [link2](https://lab52.io/blog/complete-dissection-of-an-apk-with-a-suspicious-c2-server/) with dissection of the issue.  


Dec 2021   
[Location data leaked even app user opted-out](https://www.vice.com/en/article/5dgmqz/huq-location-data-opt-out-no-consent)   


October 2021
[Facebook Papers](https://www.npr.org/2021/10/25/1049015366/the-facebook-papers-what-you-need-to-know)    


[Terms of Service didn't read](https://tosdr.org/): “I have read and agree to the Terms” is the biggest lie on the web. TOSDR aims to fix that.  


[Sharing information](https://consumer.ftc.gov/media/video-0022-sharing-information-day-your-life)   


[A day in the life of your data](https://www.apple.com/privacy/docs/A_Day_in_the_Life_of_Your_Data.pdf)   
