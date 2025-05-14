from scapy.all import *
from colorama import init, Fore, Style
import argparse
import time
from datetime import datetime
import sqlite3
import json
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
import maxminddb.errors

# Initialize colorama for colored output
init()

def get_ip_info(ip_address):
    """Get geolocation and ISP information for an IP address"""
    try:
        with Reader('GeoLite2-City.mmdb') as city_reader, Reader('GeoLite2-ASN.mmdb') as asn_reader:
            # Get city/country info
            city_response = city_reader.city(ip_address)
            # Get ASN info
            asn_response = asn_reader.asn(ip_address)
            
            return {
                'country': city_response.country.name,
                'region': city_response.subdivisions.most_specific.name if city_response.subdivisions else None,
                'city': city_response.city.name,
                'asn': asn_response.autonomous_system_number,
                'isp': asn_response.autonomous_system_organization
            }
    except (AddressNotFoundError, maxminddb.errors.InvalidDatabaseError):
        return {
            'country': None,
            'region': None,
            'city': None,
            'asn': None,
            'isp': None
        }
    except FileNotFoundError:
        print(f"{Fore.RED}Warning: GeoIP database files not found. Please download them from MaxMind.{Style.RESET_ALL}")
        return {
            'country': None,
            'region': None,
            'city': None,
            'asn': None,
            'isp': None
        }

def init_database():
    """Initialize SQLite database and create tables if they don't exist"""
    conn = sqlite3.connect('packet_capture.db')
    c = conn.cursor()
    
    # Create packets table with all columns
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol INTEGER,
            src_port INTEGER,
            dst_port INTEGER,
            tcp_flags TEXT,
            packet_length INTEGER,
            raw_packet TEXT,
            src_country TEXT,
            src_region TEXT,
            src_city TEXT,
            src_asn INTEGER,
            src_isp TEXT,
            dst_country TEXT,
            dst_region TEXT,
            dst_city TEXT,
            dst_asn INTEGER,
            dst_isp TEXT
        )
    ''')
    
    conn.commit()
    return conn

def packet_callback(packet, db_conn):
    """Callback function to process each captured packet"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Initialize packet data dictionary
    packet_data = {
        'timestamp': timestamp,
        'src_mac': None,
        'dst_mac': None,
        'src_ip': None,
        'dst_ip': None,
        'protocol': None,
        'src_port': None,
        'dst_port': None,
        'tcp_flags': None,
        'packet_length': len(packet),
        'src_country': None,
        'src_region': None,
        'src_city': None,
        'src_asn': None,
        'src_isp': None,
        'dst_country': None,
        'dst_region': None,
        'dst_city': None,
        'dst_asn': None,
        'dst_isp': None
    }
    
    # Layer 2 (Data Link Layer) information
    if packet.haslayer('Ether'):
        packet_data['src_mac'] = packet[Ether].src
        packet_data['dst_mac'] = packet[Ether].dst
        print(f"{Fore.GREEN}[Ethernet]{Style.RESET_ALL} "
              f"Src MAC: {packet_data['src_mac']} → Dst MAC: {packet_data['dst_mac']}")
    
    # Layer 3 (Network Layer) information
    if packet.haslayer('IP'):
        packet_data['src_ip'] = packet[IP].src
        packet_data['dst_ip'] = packet[IP].dst
        packet_data['protocol'] = packet[IP].proto
        
        # Get geolocation info for source IP
        src_ip_info = get_ip_info(packet_data['src_ip'])
        packet_data.update({
            'src_country': src_ip_info['country'],
            'src_region': src_ip_info['region'],
            'src_city': src_ip_info['city'],
            'src_asn': src_ip_info['asn'],
            'src_isp': src_ip_info['isp']
        })
        
        # Get geolocation info for destination IP
        dst_ip_info = get_ip_info(packet_data['dst_ip'])
        packet_data.update({
            'dst_country': dst_ip_info['country'],
            'dst_region': dst_ip_info['region'],
            'dst_city': dst_ip_info['city'],
            'dst_asn': dst_ip_info['asn'],
            'dst_isp': dst_ip_info['isp']
        })
        
        print(f"{Fore.BLUE}[IP]{Style.RESET_ALL} "
              f"Src IP: {packet_data['src_ip']} ({packet_data['src_country']}, {packet_data['src_isp']}) → "
              f"Dst IP: {packet_data['dst_ip']} ({packet_data['dst_country']}, {packet_data['dst_isp']})")
        print(f"Protocol: {packet_data['protocol']}")
    
    # Layer 4 (Transport Layer) information
    if packet.haslayer('TCP'):
        packet_data['src_port'] = int(packet[TCP].sport)
        packet_data['dst_port'] = int(packet[TCP].dport)
        packet_data['tcp_flags'] = packet[TCP].flags
        print(f"{Fore.RED}[TCP]{Style.RESET_ALL} "
              f"Src Port: {packet_data['src_port']} → Dst Port: {packet_data['dst_port']}")
        print(f"Flags: {packet_data['tcp_flags']}")
    elif packet.haslayer('UDP'):
        packet_data['src_port'] = int(packet[UDP].sport)
        packet_data['dst_port'] = int(packet[UDP].dport)
        print(f"{Fore.MAGENTA}[UDP]{Style.RESET_ALL} "
              f"Src Port: {packet_data['src_port']} → Dst Port: {packet_data['dst_port']}")
    
    # Print packet length
    print(f"Packet Length: {packet_data['packet_length']} bytes")
    print("-" * 80)
    
    # Store packet in database
    try:
        c = db_conn.cursor()
        c.execute('''
            INSERT INTO packets (
                timestamp, src_mac, dst_mac, src_ip, dst_ip, 
                protocol, src_port, dst_port, tcp_flags, 
                packet_length, raw_packet,
                src_country, src_region, src_city, src_asn, src_isp,
                dst_country, dst_region, dst_city, dst_asn, dst_isp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data['timestamp'],
            packet_data['src_mac'],
            packet_data['dst_mac'],
            packet_data['src_ip'],
            packet_data['dst_ip'],
            packet_data['protocol'],
            packet_data['src_port'],
            packet_data['dst_port'],
            str(packet_data['tcp_flags']),
            packet_data['packet_length'],
            str(packet),
            packet_data['src_country'],
            packet_data['src_region'],
            packet_data['src_city'],
            packet_data['src_asn'],
            packet_data['src_isp'],
            packet_data['dst_country'],
            packet_data['dst_region'],
            packet_data['dst_city'],
            packet_data['dst_asn'],
            packet_data['dst_isp']
        ))
        db_conn.commit()
    except sqlite3.Error as e:
        print(f"{Fore.RED}Database error: {e}{Style.RESET_ALL}")

def start_capture(interface=None, filter="", count=0):
    """Start capturing packets"""
    try:
        print(f"{Fore.GREEN}Starting packet capture...{Style.RESET_ALL}")
        print(f"Interface: {interface or 'default'}")
        print(f"Filter: {filter or 'none'}")
        print(f"Count: {count or 'infinite'}")
        print("-" * 80)
        
        # Initialize database connection
        db_conn = init_database()
        
        # Start sniffing with database connection passed to callback
        sniff(iface=interface,
              prn=lambda x: packet_callback(x, db_conn),
              filter=filter,
              count=count)
              
    except PermissionError:
        print(f"{Fore.RED}Error: This script requires administrator/root privileges{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Capture stopped by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
    finally:
        if 'db_conn' in locals():
            db_conn.close()

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Database Storage")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets")
    parser.add_argument("-f", "--filter", help="BPF filter string", default="")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 for infinite)", default=0)
    
    args = parser.parse_args()
    start_capture(args.interface, args.filter, args.count)

if __name__ == "__main__":
    main()

# Example usage:
# conn = sqlite3.connect('packet_capture.db')
# cursor = conn.cursor()
# cursor.execute('SELECT timestamp, src_ip, dst_ip FROM packets')
# for row in cursor.fetchall():
#     print(row) 