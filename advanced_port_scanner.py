#!/usr/bin/env python3
# advanced_port_scanner.py
# APScan — Advanced async TCP port scanner (educational)
# Usage examples:
#   python advanced_port_scanner.py scan --target 192.168.1.1 --top 100 --pretty
#   python advanced_port_scanner.py pocan ip --ip 192.168.1.5 --rich --top 50

from __future__ import annotations
import argparse
import asyncio
import ssl
import socket
import json
import csv
import re
from datetime import datetime
from typing import List, Dict, Optional, Any

import click

# optional rich
try:
    from rich.table import Table
    from rich.console import Console
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    console = None

# ---------------- Config ----------------
DEFAULT_CONCURRENCY = 200
DEFAULT_TIMEOUT = 1.0
DEFAULT_TOP = 100

# probes for banner grabbing (simple)
PROBES = {
    'http': b'GET / HTTP/1.0\r\nHost: %b\r\n\r\n',
    'smtp': b'HELO example.com\r\n',
    'ftp': b'\r\n',
    'ssh': b'\r\n',
    'mysql': b'\r\n',
}

# lightweight fingerprint rules: regex -> service name
FINGERPRINTS = [
    (re.compile(r'^HTTP/|Server:.*', re.I), 'http'),
    (re.compile(r'^220 .*SMTP|ESMTP', re.I), 'smtp'),
    (re.compile(r'SSH-'), 'ssh'),
    (re.compile(r'^220 .*FTP', re.I), 'ftp'),
    (re.compile(r'mysql_native_password|MySQL', re.I), 'mysql'),
]

# fallback common port -> service
COMMON_PORT_SERVICE = {
    80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 25: 'smtp', 110: 'pop3',
    143: 'imap', 3306: 'mysql', 3389: 'rdp', 53: 'dns'
}

# ---------------- Utilities ----------------
def parse_ports(spec: str) -> List[int]:
    """
    Parse port spec like "1-1024,3306,8080"
    """
    parts = spec.split(',')
    out = set()
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-', 1)
            a = int(a); b = int(b)
            for n in range(max(1, a), min(65535, b) + 1):
                out.add(n)
        else:
            out.add(int(p))
    return sorted(out)

def top_ports(n: int = 100) -> List[int]:
    common = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
    out = list(common)
    p = 1
    while len(out) < n:
        port = 1024 + p
        out.append(port)
        p += 1
    return out[:n]

def save_json(results: List[Dict[str,Any]], path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({'scanned_at': datetime.utcnow().isoformat(), 'results': results}, f, ensure_ascii=False, indent=2)

def save_csv(results: List[Dict[str,Any]], path: str):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['port','open','service','banner','protocol','ssl','time','notes'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

# ---------------- Scanner ----------------
class Scanner:
    def __init__(self, target: str, ports: List[int], concurrency: int = DEFAULT_CONCURRENCY, timeout: float = DEFAULT_TIMEOUT, ssl_ports: Optional[List[int]] = None):
        self.target = target
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.ssl_ports = set(ssl_ports or [443])
        self.results: List[Dict[str,Any]] = []
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        hostname_bytes = self.target.encode() if isinstance(self.target, str) else b''
        probes_to_try = []
        guess = COMMON_PORT_SERVICE.get(port)
        if guess and guess in PROBES:
            probes_to_try.append(PROBES[guess])
        probes_to_try.append(b'\r\n')  # generic probe

        banner = b''
        for p in probes_to_try:
            try:
                data = p.replace(b'%b', hostname_bytes)
                writer.write(data)
                await writer.drain()
                chunk = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                if chunk:
                    banner += chunk
                    break
            except Exception:
                # ignore probe errors
                pass
        # final best-effort read
        try:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=0.2)
            banner += chunk
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return banner.decode(errors='ignore').strip()

    def _fingerprint(self, banner: str, port: int) -> Optional[str]:
        if not banner:
            return COMMON_PORT_SERVICE.get(port)
        for regex, name in FINGERPRINTS:
            if regex.search(banner):
                return name
        if banner.startswith('HTTP') or 'Server:' in banner:
            return 'http'
        return None

    async def _scan_port(self, port: int):
        async with self.semaphore:
            result = {
                'port': port,
                'open': False,
                'service': None,
                'banner': '',
                'protocol': 'TCP',
                'ssl': False,
                'time': None,
                'notes': ''
            }
            start = datetime.utcnow()
            try:
                if port in self.ssl_ports:
                    ctx = ssl.create_default_context()
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(self.target, port, ssl=ctx), timeout=self.timeout)
                    result['ssl'] = True
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(self.target, port), timeout=self.timeout)
                # connected
                result['open'] = True
                banner = await self._grab_banner(reader, writer, port)
                result['banner'] = banner
                svc = self._fingerprint(banner, port)
                result['service'] = svc
            except asyncio.TimeoutError:
                result['notes'] = 'timeout/filtered'
            except (ConnectionRefusedError, OSError):
                result['notes'] = 'closed'
            except ssl.SSLError:
                # TLS handshake failed but port might be ssl
                result['open'] = True
                result['ssl'] = True
                result['notes'] = 'ssl-handshake-failed'
            except Exception as e:
                result['notes'] = f'error:{type(e).__name__}'
            end = datetime.utcnow()
            result['time'] = (end - start).total_seconds()
            # refine notes if open but no banner
            if result['open'] and not result['banner'] and not result['notes']:
                result['notes'] = 'open-no-banner'
            self.results.append(result)

    async def run(self) -> List[Dict[str,Any]]:
        tasks = [self._scan_port(p) for p in self.ports]
        await asyncio.gather(*tasks)
        self.results.sort(key=lambda x: x['port'])
        return self.results

# ---------------- Rich printing ----------------
def print_rich_detailed_results(ip: str, results: List[Dict[str,Any]]):
    if not RICH_AVAILABLE:
        print("rich not installed; fallback to plain output")
        for r in results:
            print(f"{ip} : {r['port']} | {'open' if r['open'] else 'closed'} | {r.get('service') or ''} | {r['notes']}")
        return

    table = Table(show_lines=False, title=f"ผลลัพท์ — {ip}")
    table.add_column("Ip", no_wrap=True)
    table.add_column("Port", justify="right")
    table.add_column("Open", justify="center")
    table.add_column("Service", no_wrap=True)
    table.add_column("Banner", overflow="fold")
    table.add_column("Proto", justify="center")
    table.add_column("SSL", justify="center")
    table.add_column("Time(s)", justify="right")
    table.add_column("Notes", overflow="fold")

    for r in results:
        table.add_row(
            ip,
            str(r['port']),
            "yes" if r['open'] else "no",
            str(r.get('service') or ''),
            (r.get('banner') or '')[:300],
            r.get('protocol') or 'TCP',
            "Yes" if r.get('ssl') else "No",
            f"{r.get('time',0):.3f}",
            r.get('notes') or ''
        )
    console.print(table)

# ---------------- CLI (click) ----------------
@click.group()
@click.version_option(version='0.2.0')
def cli():
    """APScan — Advanced Port Scanner CLI (educational)"""
    pass

@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname or IP')
@click.option('--ports', help='Ports spec, e.g. 1-1024,3306')
@click.option('--top', type=int, help='Scan top N ports')
@click.option('--concurrency', '-c', default=DEFAULT_CONCURRENCY, show_default=True, help='Max concurrent connections')
@click.option('--timeout', default=DEFAULT_TIMEOUT, show_default=True, help='Connection timeout seconds')
@click.option('--output', '-o', help='Write output to file (json or csv)')
@click.option('--pretty', is_flag=True, help='Pretty table output (uses rich if available)')
def scan(target, ports, top, concurrency, timeout, output, pretty):
    """Run a port scan (non-interactive)."""
    if not ports and not top:
        raise click.UsageError('Either --ports or --top must be provided')
    if ports:
        port_list = parse_ports(ports)
    else:
        port_list = top_ports(top)

    scanner = Scanner(target, port_list, concurrency=concurrency, timeout=timeout)
    click.echo(f"Scanning {target} ports {port_list[0]}-{port_list[-1]} (concurrency={concurrency}) — only on authorized targets")
    start = datetime.utcnow()
    results = asyncio.run(scanner.run())
    end = datetime.utcnow()
    open_ports = [r for r in results if r['open']]
    click.echo(f"Finished in {(end-start).total_seconds():.2f}s — open: {len(open_ports)} / {len(port_list)}")

    if pretty and RICH_AVAILABLE:
        print_rich_detailed_results(target, results)
    else:
        for r in results:
            click.echo(f"{r['port']:5d} | {'open' if r['open'] else 'closed'} | {r.get('service') or ''} | {r['notes']}")

    if output:
        if output.lower().endswith('.json'):
            save_json(results, output)
        elif output.lower().endswith('.csv'):
            save_csv(results, output)
        else:
            save_json(results, output)
        click.echo(f"Wrote output to {output}")

@cli.group()
def pocan():
    """Interactive helpers (greeting etc)"""
    pass

@pocan.command('ip')
@click.option('--ip', help='IP address to scan (if omitted, will prompt)')
@click.option('--rich', 'use_rich', is_flag=True, help='Show rich UI if available')
@click.option('--top', type=int, default=20, show_default=True, help='Scan top N ports in quick mode')
@click.option('--concurrency', '-c', default=200, show_default=True, help='Max concurrent connections')
@click.option('--timeout', default=0.6, show_default=True, help='Connection timeout seconds (quicker)')
def pocan_ip(ip, use_rich, top, concurrency, timeout):
    """Interactive greeting + quick IP scan"""
    click.echo("\nWelcome to port scanner")
    click.echo("By B dev\n")

    if not ip:
        ip = click.prompt('Ip', type=str)

    click.echo("\nScaning.......\n")

    port_list = top_ports(top)
    scanner = Scanner(ip, port_list, concurrency=concurrency, timeout=timeout)

    results = None
    if use_rich and RICH_AVAILABLE:
        with console.status("Scanning...", spinner="dots"):
            results = asyncio.run(scanner.run())
    else:
        click.echo("Scanning... (this may take a few seconds)")
        results = asyncio.run(scanner.run())

    open_ports = [r for r in results if r['open']]

    click.echo("\nผลลัพท์\n")
    if use_rich and RICH_AVAILABLE:
        print_rich_detailed_results(ip, results)
    else:
        click.echo("Ip :")
        for r in open_ports:
            click.echo(f"{ip} : {r['port']}  | service: {r.get('service') or ''} | notes: {r.get('notes') or ''}")

    if not open_ports:
        click.echo("No open ports found (within scanned range).")

if __name__ == '__main__':
    cli()
