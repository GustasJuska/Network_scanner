from scapy.all import ARP, Ether, srp
import argparse

def scan_network(ip_range):
    """Scan the network to find live devices."""
    print(f"Scanning the network: {ip_range}")
    
    # Create an ARP request to broadcast
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and capture the responses
    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)

    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def flag_suspicious(devices, suspicious_ips):
    """Flag devices with suspicious IPs."""
    flagged_devices = [device for device in devices if device['ip'] in suspicious_ips]
    return flagged_devices

def main():
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="Python Network Scanner")
    parser.add_argument("-r", "--range", required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-s", "--suspicious", nargs="+", help="List of suspicious IPs to flag", default=[])
    args = parser.parse_args()

    # Scan the network
    devices = scan_network(args.range)
    print("\nDevices found on the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    # Check for suspicious IPs
    if args.suspicious:
        flagged = flag_suspicious(devices, args.suspicious)
        if flagged:
            print("\nSuspicious devices detected:")
            for device in flagged:
                print(f"⚠️  IP: {device['ip']}, MAC: {device['mac']}")
        else:
            print("\nNo suspicious devices detected.")
    else:
        print("\nNo suspicious IP list provided.")

if __name__ == "__main__":
    main()
