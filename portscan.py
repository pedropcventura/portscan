from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Label, Input, Button
import socket
import ipaddress
from wkp_updated import ports  
import netifaces

class PortScannerApp(App):

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("TCP/UDP Port Scanner (IPv4 & IPv6)", id="title")
        yield Label("Enter the host or network to scan:")
        yield Input(placeholder="Example: wikipedia.org, 192.168.1.1, 2606:2800:220:1:248:1893:25c8:1946", id="host_input")
        yield Label("Enter ports (e.g., 22,80 or 1-1024):")
        yield Input(placeholder="1-1024", id="ports_input")
        yield Button("Start Scan", id="scan_button")
        yield DataTable()
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        host_input = self.query_one("#host_input", Input).value
        ports_str = self.query_one("#ports_input", Input).value
        table = self.query_one(DataTable)

        ports_list = self.process_ports(ports_str)

        ip_list, is_ipv6 = self.get_ip_list(host_input)

        table.clear()
        table.add_column("Host/IP")
        table.add_column("Port")
        table.add_column("Status")
        table.add_column("Service")  
        table.add_column("Protocol")  

        for ip in ip_list:
            for port in ports_list:
                status = self.scan_port(ip, port, is_ipv6)
                service_name, protocol = ports.get(str(port), ("Unknown", "TCP/UDP")) 
                table.add_row(host_input, str(port), status, service_name, protocol)

    def process_ports(self, ports_str):
        ports = []
        for part in ports_str.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports

    def get_ip_list(self, host_input):
        try:
            network = ipaddress.ip_network(host_input, strict=False)
            return [str(ip) for ip in network.hosts()], network.version == 6
        except ValueError:
            try:
                ipv6_info = socket.getaddrinfo(host_input, None, socket.AF_INET6)
                ipv6_ip = ipv6_info[0][4][0]
                return [ipv6_ip], True
            except socket.gaierror:
                try:
                    ipv4_ip = socket.gethostbyname(host_input)
                    return [ipv4_ip], False
                except socket.gaierror:
                    print(f"Error: Unable to resolve {host_input}")
                    return [], False

    def scan_port(self, host, port, is_ipv6):
        sock_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        sock = socket.socket(sock_family, socket.SOCK_STREAM)
        sock.settimeout(1)

        if is_ipv6 and host.startswith("fe80::"):
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if netifaces.AF_INET6 in netifaces.ifaddresses(iface):
                    host = f"{host}%{iface}"
                    break  

        try:
            sock.connect((host, port))
            return "🟢 Open"  
        except socket.timeout:
            return "🟡 Filtered"  
        except ConnectionRefusedError:
            return "🔴 Closed"  
        except OSError as e:
            return f"⚠️ Error: {e}" 
        finally:
            sock.close()


if __name__ == "__main__":
    app = PortScannerApp()
    app.run()
