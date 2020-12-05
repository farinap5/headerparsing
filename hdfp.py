import requests
import sys
import re

args = sys.argv

def help():
    print("""
    Header Dump for Parsing
    -----------------------
    
    Usage Method:
    python3 hpars.py u=http://example.com
    
    u=   URL argument.
    """)

def ck(headers,req):
    try:
        ck = req.cookies
        if len(ck) == 0:
            pass
        else:
            print("\nCookies:")
            for coo in ck:
                print("Name:",coo.name)
                print("Value:",coo.value)
                print("Port:",coo.port)
                print("Path:",coo.path)
                print("Secure:",coo.secure)
                print("Expires:",coo.expires)
                print("Domain:",coo.domain)
                print("Version:",coo.version)
                print("Discard:",coo.discard)
                print("RFC:",coo.rfc2109)
    except:
        pass



def checkwaf(url,headers):
    r = requests.get(url,headers=headers)

    opt = ["Yes","yes","Y","y"]
    try:
        if r.headers["server"] == "cloudflare":
            print("[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare Server.")
        else:
            pass
    except:
        pass

    noise = "?=<script>alert('pwn')</script>"
    fuzz = url + noise
    waffd = requests.get(fuzz,headers=headers)
    if waffd.status_code == 406 or waffd.status_code == 501:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 999:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 419:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 403:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    else:
        print("[\033[1;32mOK\033[0;0m] No WAF Detected.\n")


def dvuln(header):
    print("\nMissing Headers:")
    if 'x-xss-protection' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'X-XSS-Protection' - XSS Vulnerable.")

    if 'content-type' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'Content-type' header.")

    if 'content-security-policy' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'Content-Security-Policy' - Can be accessed over HTTP.")

    if 'x-frame-options' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'X-Frame-Options' - Might there a Clickjacking Vulnerability.")

    if 'strict-transport-security' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'Strict-Transport-Security' - Connection Might be Sniffed.")

    if 'x-content-type-options' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'X-Content-Type-Options' - MIME sniffing.")

    if 'public-key-pins' not in header:
        print("[\033[1;34mInfo\033[0;0m] Missing 'Public-Key-Pins'.")

def ucm(header):
    common = ("host","server", "age", "cookie", "pragma", "accept", "allow",
                     "authorization", "connection", "cache-control", "date", "etag",
                     "expires", "expect", "from", "via", "location", "host", "keep-live",
                     "if-match", "p3p", "proxy-authenticate", "proxy-authorization", "range",
                     "referer", "set-cookie", "te", "trailer", "vary", "warning", "www-authenticate",
                     "x-powered-by", "powered-by", "x-pad", "mime-version", "proxy-connection", "status",
                     "public", "dav", "nncoection", "dasl", "x-aspbet-version", "whisker", "user-agent", "upgrade",
                     "transfer-encoding", "retry-after", "max-forwards", "last-modified", "if-range", "if-none-match",
                     "if-modified-since", "if-unmodified-since", "content-type", "content-range", "content-md5",
                     "content-location",
                     "content-language", "link", "content-encoding", "content-length", "accept-charset",
                     "accept-encoding", "accept-language", "accept-ranges","x-mod-pagespeed","x-frame-options",
                     "x-xss-protection","content-security-policy","strict-transport-security")

    print("Uncommun headers found with contents:")
    for uni in common:
        try:
            print(uni,":",header[uni])
        except:
            pass

def req(url):


    headers = {"User-Agent":"Venera 1.0/ linux"}
    checkwaf(url, headers)

    req = requests.get(url,headers=headers)
    print("Code:",req.status_code)
    header = req.headers

    ucm(header)
    dvuln(header)
    ck(headers,req)

def argp(args):
    #print(args)
    try:
        for ag in args:
            ag = ag.split("=")
            if ag[0] == "u":
                host = ag[1]

        if "http" not in host:
            url = "http://" + host
        else:
            url = host
        print("""
        Header Dump for Parsing
        -----------------------
            """)
        print("Target:",url)

        req(url)
    except:
        help()
argp(args)