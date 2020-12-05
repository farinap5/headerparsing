<h1 align="center">Header Dump for Parsing</h1>
<p align="center">To help analyze web headers.</p>
<p align="center"> 
   <img src="https://img.shields.io/badge/language-python-blue.svg">
</p>

***
```
shell> python3 hdfp.py u=http://example.com

        Header Dump for Parsing
        -----------------------
            
Target: http://example.com
[!]The Server is Behind a CloudFlare Server.
[OK] No WAF Detected.

Code: 503
Uncommun headers found with contents:
server : cloudflare
connection : close
cache-control : private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
date : Sat, 05 Dec 2020 17:32:55 GMT
expires : Thu, 01 Jan 1970 00:00:01 GMT
set-cookie : __cfduid=d6741bd2d0ec6e42cc93e382d83f87cb41607189575; expires=Mon, 04-Jan-21 17:32:55 GMT; path=/; domain=.example.com; HttpOnly; SameSite=Lax
vary : Accept-Encoding
transfer-encoding : chunked
content-type : text/html; charset=UTF-8
x-frame-options : SAMEORIGIN

Missing Headers:
[Info] Missing 'X-XSS-Protection' - XSS Vulnerable.
[Info] Missing 'Content-Security-Policy' - Can be accessed over HTTP.
[Info] Missing 'Strict-Transport-Security' - Connection Might be Sniffed.
[Info] Missing 'X-Content-Type-Options' - MIME sniffing.
[Info] Missing 'Public-Key-Pins'.

Cookies:
Name: __cfduid
Value: d6741bd2d0ec6e42cc93e382d83f87cb41607189575
Port: None
Path: /
Secure: False
Expires: 1609781575
Domain: .example.com
Version: 0
Discard: False
RFC: False

```
