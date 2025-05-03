from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Label, Input, Button, Select
import asyncio
import socket
import ipaddress
import netifaces
import dns.resolver
import whois
import requests
from wkp_updated import ports
from Wappalyzer import Wappalyzer, WebPage

# Ferramentas disponíveis
tools = [
    ("Port Scan", "Port Scan"),
    ("DNS Enumeration", "DNS Enumeration"),
    ("WHOIS Lookup", "WHOIS Lookup"),
    ("Wappalyzer", "Wappalyzer"),
    ("Subdomain Enumeration", "Subdomain Enumeration"),
]

class PortScannerApp(App):
    refresh_rate = 0.5  # redesenhando a tela a cada 0.5 s 

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Select a tool:", id="tool_label")
        yield Select(options=tools, id="tool_select", value="Port Scan")

        yield Label("Enter the target (host, domain, URL, or network):", id="host_label")
        yield Input(placeholder="e.g. example.com or https://example.com", id="host_input")

        yield Label("Enter ports (e.g., 22,80 or 1-1024):", id="ports_label")
        yield Input(placeholder="1-1024", id="ports_input")

        yield Button("Start", id="start_button")
        yield DataTable(id="result_table")
        yield Footer()

    def on_select_changed(self, event: Select.Changed) -> None:
        show_ports = (event.value == "Port Scan")
        self.query_one("#ports_label").display = show_ports
        self.query_one("#ports_input").display = show_ports
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_button":
            tool = self.query_one("#tool_select").value
            if tool == "Port Scan":
                await self.handle_portscan()
            elif tool == "DNS Enumeration":
                await self.handle_dnsenum()
            elif tool == "WHOIS Lookup":
                await self.handle_whois()
            elif tool == "Wappalyzer":
                await self.handle_wappalyzer()
            elif tool == "Subdomain Enumeration":
                await self.handle_subdomains()

    async def handle_portscan(self) -> None:
        host = self.query_one("#host_input").value
        ports_str = self.query_one("#ports_input").value
        rows = await self.run_portscan(host, ports_str)
        headers = ["Host/IP", "Port", "Status", "Service", "Protocol"]
        self.display_results(rows, headers)

    async def handle_dnsenum(self) -> None:
        target = self.query_one("#host_input").value
        rows = self.run_dnsenum(target)
        headers = ["Record", "Value"]
        self.display_results(rows, headers)

    async def handle_whois(self) -> None:
        target = self.query_one("#host_input").value
        rows = self.run_whois(target)
        headers = ["Field", "Value"]
        self.display_results(rows, headers)

    async def handle_wappalyzer(self) -> None:
        url = self.query_one("#host_input").value
        rows = await self.run_wappalyzer(url)
        headers = ["Technology"]
        self.display_results(rows, headers)

    async def handle_subdomains(self) -> None:
        domain = self.query_one("#host_input").value
        rows = await self.run_subdomains(domain)
        headers = ["Subdomain"]
        self.display_results(rows, headers)

    # Async Port Scan
    # Port scans usa asyncio para alta concorrência -> recomendaçao do chat para melhor performance (rodar mais rapido).
    async def run_portscan(self, host: str, ports_str: str) -> list[tuple]:
        ports_list = self.process_ports(ports_str)
        ip_list, is_v6 = self.get_ip_list(host)
        results = []
        sem = asyncio.Semaphore(500)

        async def scan_task(ip, port):
            async with sem:
                h, p, status = await self.async_scan(ip, port, is_v6)
                svc, proto = ports.get(str(p), ("Unknown", "TCP/UDP"))
                results.append((h, p, status, svc, proto))

        tasks = [scan_task(ip, p) for ip in ip_list for p in ports_list]
        await asyncio.gather(*tasks)
        return results

    async def async_scan(self, host: str, port: int, is_ipv6: bool) -> tuple:
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        addr = host
        if is_ipv6 and host.startswith("fe80::"):
            for iface in netifaces.interfaces():
                if netifaces.AF_INET6 in netifaces.ifaddresses(iface):
                    addr = f"{host}%{iface}"
                    break
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(addr, port, family=family), timeout=1
            )
            writer.close()
            await writer.wait_closed()
            return host, port, "🟢 Open"
        except asyncio.TimeoutError:
            return host, port, "🟡 Filtered"
        except ConnectionRefusedError:
            return host, port, "🔴 Closed"
        except OSError as e:
            return host, port, f"⚠️ Error: {e}"

    # DNS
    def run_dnsenum(self, target: str) -> list[tuple]:
        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        results = []
        for rtype in record_types:
            try:
                for rdata in dns.resolver.resolve(target, rtype):
                    results.append((rtype, str(rdata)))
            except Exception:
                continue
        return results

    # WHOIS
    def run_whois(self, target: str) -> list[tuple]:
        try:
            data = whois.whois(target)
        except Exception as e:
            return [("Error", str(e))]
        rows = []
        for field, value in (data.items() if isinstance(data, dict) else data.__dict__.items()):
            rows.append((field, str(value)))
        return rows

    # Wappalyzer
    async def run_wappalyzer(self, url: str) -> list[tuple]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_wappalyzer, url)

    def _sync_wappalyzer(self, url: str) -> list[tuple]:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        wapp = Wappalyzer.latest()
        page = WebPage.new_from_url(url)
        apps = wapp.analyze(page)
        return [(app,) for app in apps]

    # Subdomain Enumeration via crt.sh
    async def run_subdomains(self, domain: str) -> list[tuple]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_subdomains, domain)

    def _sync_subdomains(self, domain: str) -> list[tuple]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=30)
            data = resp.json()
        except Exception as e:
            return [("Error", str(e))]
        subs = set()
        for entry in data:
            nv = entry.get("name_value")
            if nv:
                for d in nv.split("\n"):
                    subs.add(d.strip())
        return [(sd,) for sd in sorted(subs)]

    # UI
    def display_results(self, rows: list[tuple], columns: list[str]) -> None:
        table = self.query_one("#result_table")
        table.clear()
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*[str(item) for item in row])

    # Helpers
    def process_ports(self, ports_str: str) -> list[int]:
        parts = ports_str.split(",")
        ports_list = []
        for part in parts:
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports_list.extend(range(start, end + 1))
            else:
                ports_list.append(int(part))
        return ports_list

    def get_ip_list(self, host_input: str) -> tuple[list[str], bool]:
        try:
            network = ipaddress.ip_network(host_input, strict=False)
            return [str(ip) for ip in network.hosts()], network.version == 6
        except ValueError:
            try:
                info = socket.getaddrinfo(host_input, None, socket.AF_INET6)
                return [info[0][4][0]], True
            except socket.gaierror:
                try:
                    return [socket.gethostbyname(host_input)], False
                except socket.gaierror:
                    return [], False

if __name__ == "__main__":
    app = PortScannerApp()
    app.run()
