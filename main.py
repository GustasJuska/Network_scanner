from scapy.all import ARP, Ether, srp, getmacbyip
import argparse
import ipaddress
from prettytable import PrettyTable
import threading
import time

def validate_ip_range(ip_range):
    """Validate the IP range format."""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def get_vendor(mac):
    """Attempt to get vendor information from MAC address."""
    try:
        from scapy.all import manuf
        vendor = manuf.manufdb._get_manuf(mac)
        return vendor if vendor else "Unknown"
    except:
        return "Unknown"

def scan_network(ip_range, timeout=2):
    """Scan the network to find live devices."""
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered, _ = srp(
        arp_request_broadcast,
        timeout=timeout,
        verbose=False,
        threaded=True  # Enable threading for faster scanning
    )

    devices = []
    for sent, received in answered:
        vendor = get_vendor(received.hwsrc)
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc.upper(),  # Standardize MAC format
            'vendor': vendor
        })
    
    return devices

def flag_suspicious(devices, suspicious_ips):
    """Flag devices matching suspicious IPs or subnets."""
    flagged = []
    for device in devices:
        ip = ipaddress.ip_address(device['ip'])
        for suspicious in suspicious_ips:
            try:
                network = ipaddress.ip_network(suspicious, strict=False)
                if ip in network:
                    flagged.append(device)
                    break
            except ValueError:
                if device['ip'] == suspicious:
                    flagged.append(device)
                    break
    return flagged

def print_results(devices, title="Network Devices"):
    """Print results in a formatted table."""
    table = PrettyTable()
    table.field_names = ["IP Address", "MAC Address", "Vendor", "Status"]
    for device in devices:
        status = "Suspicious" if 'suspicious' in device else "Normal"
        table.add_row([device['ip'], device['mac'], device['vendor'], status])
    
    print(f"\n{title}:")
    print(table)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python Network Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-r", "--range", required=True, 
                      help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-s", "--suspicious", nargs="+", default=[],
                      help="List of suspicious IPs/subnets to flag")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                      help="Scan timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output")

    args = parser.parse_args()

    if not validate_ip_range(args.range):
        print(f"Error: Invalid IP range format: {args.range}")
        return

    if args.verbose:
        print(f"Starting scan of {args.range} with timeout {args.timeout}s...")

    try:
        start_time = time.time()
        devices = scan_network(args.range, args.timeout)
        scan_time = time.time() - start_time

        if args.verbose:
            print(f"Scan completed in {scan_time:.2f} seconds")

        if devices:
            flagged = flag_suspicious(devices, args.suspicious)
            for device in flagged:
                device['suspicious'] = True
            
            print_results(devices)
            
            if flagged:
                print("\nSecurity Alert: Suspicious devices detected!")
                print_results(flagged, "Suspicious Devices")
        else:
            print("No devices found on the network.")

    except PermissionError:
        print("Error: Requires root privileges. Try running with sudo.")
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()