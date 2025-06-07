#!/usr/bin/env python3
import argparse
import ipaddress
import sys
import json
import html

try:
    from colorama import Fore, Style, init
except ImportError:
    print("Please install colorama: pip install colorama", file=sys.stderr)
    sys.exit(1)

init(autoreset=True)

VERSION = "ipcalc.py 5.2 (IPv4/IPv6, Colors, HTML, JSON, Multilang, Usable IPs)"

LABELS = {
    'de': {
        'Address': 'Adresse',
        'Netmask': 'Netzmaske',
        'Wildcard': 'Wildcard',
        'Network': 'Netzwerk',
        'HostMin': 'HostMin',
        'HostMax': 'HostMax',
        'Broadcast': 'Broadcast',
        'Hosts/Net': 'Hosts/Net',
        'Usable': 'Nutzbare IPs',
        '=>': '=>'
    },
    'en': {
        'Address': 'Address',
        'Netmask': 'Netmask',
        'Wildcard': 'Wildcard',
        'Network': 'Network',
        'HostMin': 'HostMin',
        'HostMax': 'HostMax',
        'Broadcast': 'Broadcast',
        'Hosts/Net': 'Hosts/Net',
        'Usable': 'Usable IPs',
        '=>': '=>'
    }
}

def to_binary(ip):
    if isinstance(ip, ipaddress.IPv4Address):
        return '.'.join(f"{int(o):08b}" for o in str(ip).split('.'))
    elif isinstance(ip, ipaddress.IPv6Address):
        return bin(int(ip))[2:].zfill(128)
    return ""

def get_label(lang, key):
    return LABELS.get(lang, LABELS['en']).get(key, key)

def build_data(net):
    addr = net.network_address
    mask = net.netmask
    prefix = net.prefixlen
    broadcast = net.broadcast_address if isinstance(net, ipaddress.IPv4Network) else None
    wildcard = ipaddress.IPv4Address(int(mask) ^ 0xFFFFFFFF) if isinstance(mask, ipaddress.IPv4Address) else None
    hosts = list(net.hosts())
    hostmin = hosts[0] if hosts else addr
    hostmax = hosts[-1] if hosts else addr
    is_ipv4 = isinstance(net, ipaddress.IPv4Network)
    total_addresses = net.num_addresses
    usable_hosts = total_addresses - 2 if is_ipv4 and total_addresses >= 2 else total_addresses

    return {
        'address': str(addr),
        'prefix': prefix,
        'netmask': str(mask),
        'wildcard': str(wildcard) if wildcard else None,
        'network': str(net.network_address),
        'hostmin': str(hostmin),
        'hostmax': str(hostmax),
        'broadcast': str(broadcast) if broadcast else None,
        'hosts': total_addresses,
        'usable': usable_hosts if usable_hosts >= 0 else 0,
        'version': 4 if is_ipv4 else 6
    }

def add_binary_fields(data):
    for key in ['address', 'netmask', 'wildcard', 'network', 'broadcast']:
        val = data.get(key)
        if val:
            try:
                ip = ipaddress.ip_address(val)
                data[f"{key}_bin"] = to_binary(ip)
            except ValueError:
                continue
    return data

def colorize(label_key, value, binary=None, use_color=False, lang='en'):
    label = get_label(lang, label_key)
    if use_color:
        res = f"{Fore.CYAN}{label}:{Style.RESET_ALL}  {Fore.YELLOW}{value}{Style.RESET_ALL}"
        if binary:
            res += f"\n           {Fore.MAGENTA}{binary}{Style.RESET_ALL}"
    else:
        res = f"{label}:  {value}"
        if binary:
            res += f"\n           {binary}"
    return res

def print_text_output(data, show_binary, lang, use_color):
    print(colorize('Address', f"{data['address']}/{data['prefix']}", data.get("address_bin") if show_binary else None, use_color, lang))
    print(colorize('Netmask', f"{data['netmask']} = {data['prefix']}", data.get("netmask_bin") if show_binary else None, use_color, lang))
    if data['version'] == 4 and data.get('wildcard'):
        print(colorize('Wildcard', data['wildcard'], data.get("wildcard_bin") if show_binary else None, use_color, lang))
    print(f"{Fore.CYAN + get_label(lang, '=>') + Style.RESET_ALL if use_color else get_label(lang, '=>')}")
    print(colorize('Network', f"{data['network']}/{data['prefix']}", data.get("network_bin") if show_binary else None, use_color, lang))
    print(colorize('HostMin', data['hostmin'], None, use_color, lang))
    print(colorize('HostMax', data['hostmax'], None, use_color, lang))
    if data['version'] == 4 and data.get('broadcast'):
        print(colorize('Broadcast', data['broadcast'], data.get("broadcast_bin") if show_binary else None, use_color, lang))
    print(colorize('Hosts/Net', str(data['hosts']), None, use_color, lang))
    print(colorize('Usable', str(data['usable']), None, use_color, lang))

def print_html_output(data, show_binary, lang):
    def row(label_key, value, binary=None):
        label = html.escape(get_label(lang, label_key))
        safe_val = html.escape(value)
        safe_bin = html.escape(binary) if binary else ''
        return f"<tr><th>{label}</th><td>{safe_val}</td>" + \
               (f"<td><code>{safe_bin}</code></td>" if binary else "<td></td>") + "</tr>"

    html_out = [
        "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>ipcalc</title>",
        "<style>body{font-family:sans-serif;}table{border-collapse:collapse;}th,td{padding:4px;border:1px solid #ccc;}th{background:#eee;}</style>",
        "</head><body><table>"
    ]
    html_out.append(row("Address", f"{data['address']}/{data['prefix']}", data.get("address_bin") if show_binary else None))
    html_out.append(row("Netmask", f"{data['netmask']} = {data['prefix']}", data.get("netmask_bin") if show_binary else None))
    if data['version'] == 4 and data.get('wildcard'):
        html_out.append(row("Wildcard", data['wildcard'], data.get("wildcard_bin") if show_binary else None))
    html_out.append(row("Network", f"{data['network']}/{data['prefix']}", data.get("network_bin") if show_binary else None))
    html_out.append(row("HostMin", data['hostmin']))
    html_out.append(row("HostMax", data['hostmax']))
    if data['version'] == 4 and data.get('broadcast'):
        html_out.append(row("Broadcast", data['broadcast'], data.get("broadcast_bin") if show_binary else None))
    html_out.append(row("Hosts/Net", str(data['hosts'])))
    html_out.append(row("Usable", str(data['usable'])))
    html_out.append("</table></body></html>")
    print('\n'.join(html_out))

def print_json_output(data, show_binary):
    if show_binary:
        data = add_binary_fields(data)
    print(json.dumps(data, indent=2))

def ipcalc(addr_mask, show_binary=False, only_network=False, html_mode=False, json_mode=False, lang='en', use_color=False):
    try:
        net = ipaddress.ip_network(addr_mask, strict=False)
    except ValueError as e:
        err = e if lang == 'de' else f"Invalid input: {e}"
        print(f"{Fore.RED}{err}{Style.RESET_ALL}" if use_color else err, file=sys.stderr)
        sys.exit(1)

    if only_network:
        print(f"{net.network_address}/{net.prefixlen}")
        return

    data = build_data(net)
    if json_mode:
        print_json_output(data, show_binary)
    elif html_mode:
        if show_binary:
            data = add_binary_fields(data)
        print_html_output(data, show_binary, lang)
    else:
        if show_binary:
            data = add_binary_fields(data)
        print_text_output(data, show_binary, lang, use_color)

def main():
    parser = argparse.ArgumentParser(description="ipcalc.py – network tool (multilingual)")
    parser.add_argument("network", nargs="?", help="network address in IP/CIDR format")
    parser.add_argument("-n", action="store_true", help="only print network address")
    parser.add_argument("-b", action="store_true", help="show binary output")
    parser.add_argument("--html", action="store_true", help="HTML output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--lang", choices=['de','en'], default='en', help="output language (en or de)")
    parser.add_argument("--color", action="store_true", help="enable colored output (default off)")
    parser.add_argument("-v", action="store_true", help="show version")

    args = parser.parse_args()
    if args.v:
        print(VERSION)
        sys.exit(0)
    if not args.network:
        parser.print_help()
        sys.exit(1)

    ipcalc(
        args.network,
        show_binary=args.b,
        only_network=args.n,
        html_mode=args.html,
        json_mode=args.json,
        lang=args.lang,
        use_color=args.color
    )

if __name__ == '__main__':
    main()

