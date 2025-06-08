#!/usr/bin/env python3
import cgi
import cgitb
import ipcalc  # dein ipcalc.py als Modul
import ipaddress

cgitb.enable()

def html_header():
    return """Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ipcalc CGI</title>
  <style>
    body { font-family: sans-serif; padding: 2em; }
    table { border-collapse: collapse; margin-top: 1em; }
    th, td { border: 1px solid #ccc; padding: 0.5em; }
    th { background: #eee; text-align: left; }
  </style>
</head>
<body>
<h1>ipcalc (Python CGI)</h1>
"""

def html_footer():
    return "</body></html>"

def main():
    form = cgi.FieldStorage()
    ip = form.getfirst("ip", "").strip()
    netmask = form.getfirst("netmask", "").strip()
    nobinary = "nobinary" in form

    # Kombiniere IP + Netmask falls notwendig
    if ip and netmask and "/" not in ip:
        try:
            # Akzeptiert auch z.B. "255.255.255.0"
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            ip = f"{ip}/{prefix}"
        except ValueError:
            ip = f"{ip}/32"  # Fallback
    elif "/" not in ip:
        ip = f"{ip}/32"

    print(html_header())

    if ip and ip != "/32":
        try:
            net = ipaddress.ip_network(ip, strict=False)
            data = ipcalc.build_data(net)
            if not nobinary:
                data = ipcalc.add_binary_fields(data)
            ipcalc.print_html_output(data, show_binary=not nobinary, lang='en')
        except Exception as e:
            print(f"<p style='color:red'>Error: {cgi.escape(str(e))}</p>")
    else:
        print("<p>Please provide an IP address using ?ip=192.168.0.1/24</p>")

    print(html_footer())

if __name__ == "__main__":
    main()

