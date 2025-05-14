from flask import Flask, render_template, jsonify, request
import redis
from datetime import datetime
import os
import sys
from scapy.all import *
from colorama import init
import threading
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import geoip2.database
import maxminddb
import psycopg2
from psycopg2.extras import execute_batch
from geoip2.errors import AddressNotFoundError

init()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler('/app/data/packet_sniffer.log', maxBytes=10000000, backupCount=5)
    ]
)
logger = logging.getLogger(__name__)

# Constants
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
INTERFACE = os.getenv('CAPTURE_INTERFACE', None)
PORT = int(os.getenv('FLASK_PORT', 8080))
GEOIP_DB_PATH = '/app/data/GeoLite2-City.mmdb'
GEOIP_ASN_DB_PATH = '/app/data/GeoLite2-ASN.mmdb'
MAX_REDIS_RETRIES = 30
REDIS_RETRY_DELAY = 1
PACKET_BUFFER_SIZE = 100  # Number of packets to buffer before batch processing
PACKET_BUFFER_TIMEOUT = 2  # Seconds to wait before processing a non-full buffer

# Add PostgreSQL configuration
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5433))
POSTGRES_DB = os.getenv('POSTGRES_DB', 'postgres')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'postgres123')
ARCHIVE_INTERVAL = int(os.getenv('ARCHIVE_INTERVAL', 3600))  # Archive every hour
REDIS_DATA_TTL = int(os.getenv('REDIS_DATA_TTL', 7200))     # Keep data in Redis for 2 hours

# Port to Application mapping
PORT_APPLICATIONS = {
    # Web Services
    80: 'HTTP',
    443: 'HTTPS',
    8080: 'HTTP Alternate',
    8443: 'HTTPS Alternate',
    3000: 'Development Server',
    8000: 'Development Server',
    8888: 'Alternative HTTP',
    9090: 'Alternative HTTP',
    
    # Email Services
    25: 'SMTP',
    465: 'SMTPS',
    587: 'SMTP (Submission)',
    110: 'POP3',
    995: 'POP3S',
    143: 'IMAP',
    993: 'IMAPS',
    
    # File Transfer
    20: 'FTP (Data)',
    21: 'FTP (Control)',
    22: 'SSH/SFTP',
    69: 'TFTP',
    115: 'SFTP',
    989: 'FTPS (Data)',
    990: 'FTPS (Control)',
    
    # Database Services
    1433: 'MS SQL',
    1434: 'MS SQL Browser',
    3306: 'MySQL/MariaDB',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB',
    27018: 'MongoDB Shard',
    27019: 'MongoDB Config',
    28017: 'MongoDB Web',
    9042: 'Cassandra',
    7000: 'Cassandra Cluster',
    7001: 'Cassandra SSL',
    
    # Remote Access
    22: 'SSH',
    23: 'Telnet',
    3389: 'RDP',
    5900: 'VNC',
    5901: 'VNC-1',
    5902: 'VNC-2',
    5938: 'TeamViewer',
    3283: 'Apple Remote Desktop',
    
    # Network Services
    53: 'DNS',
    67: 'DHCP (Server)',
    68: 'DHCP (Client)',
    123: 'NTP',
    161: 'SNMP',
    162: 'SNMP Trap',
    389: 'LDAP',
    636: 'LDAPS',
    
    # Messaging & Communication
    1080: 'SOCKS Proxy',
    1194: 'OpenVPN',
    1701: 'L2TP',
    1723: 'PPTP',
    1812: 'RADIUS Auth',
    1813: 'RADIUS Accounting',
    5060: 'SIP',
    5061: 'SIP (TLS)',
    5222: 'XMPP/Jabber',
    5269: 'XMPP Server',
    6665: 'IRC',
    6666: 'IRC',
    6667: 'IRC',
    
    # Game Servers
    25565: 'Minecraft',
    27015: 'Source Engine',
    27016: 'Source Engine',
    3724: 'World of Warcraft',
    6112: 'Battle.net',
    6113: 'Battle.net',
    6114: 'Battle.net',
    
    # Media Streaming
    554: 'RTSP',
    1935: 'RTMP',
    8554: 'RTSP Alternate',
    1234: 'VLC Media',
    4713: 'PulseAudio',
    
    # Development & CI/CD
    4444: 'Jenkins',
    8080: 'Jenkins HTTP',
    9000: 'SonarQube',
    9418: 'Git',
    
    # Container & Orchestration
    2375: 'Docker',
    2376: 'Docker (SSL)',
    2377: 'Docker Swarm',
    6443: 'Kubernetes API',
    10250: 'Kubernetes Kubelet',
    10255: 'Kubernetes Read',
    
    # Monitoring & Logging
    514: 'Syslog',
    1514: 'Syslog (TCP)',
    9090: 'Prometheus',
    9100: 'Node Exporter',
    9200: 'Elasticsearch HTTP',
    9300: 'Elasticsearch Transport',
    5601: 'Kibana',
    8125: 'StatsD',
    
    # Storage Services
    111: 'NFS',
    2049: 'NFS',
    445: 'SMB',
    139: 'NetBIOS',
    
    # Security Services
    1812: 'RADIUS',
    1813: 'RADIUS Accounting',
    8443: 'HTTPS Security',
    9443: 'HTTPS Security Alt',
    
    # IoT & Home Automation
    1883: 'MQTT',
    8883: 'MQTT (SSL)',
    5683: 'CoAP',
    
    # Proxy Services
    3128: 'Squid Proxy',
    8080: 'HTTP Proxy',
    9090: 'HTTP Proxy Alt',
    
    # Time Services
    123: 'NTP',
    371: 'Chrony',
    
    # Miscellaneous
    5353: 'mDNS',
    5938: 'TeamViewer',
    1521: 'Oracle DB',
    1526: 'Oracle Alt',
    8086: 'InfluxDB',
    4222: 'NATS',
    4369: 'Erlang Port Mapper',
    11211: 'Memcached'
}

# Redis connection
redis_client = None
packet_list_key = 'packets:list'  # List to store packet IDs
packet_counter_key = 'packets:counter'  # Counter for packet IDs
stats_key = 'packets:stats'  # Hash to store statistics

# GeoIP readers
geo_reader = None
asn_reader = None

# Packet buffer and its lock
packet_buffer = []
buffer_lock = threading.Lock()
last_buffer_process = time.time()

# PostgreSQL connection
pg_conn = None
pg_lock = threading.Lock()

# Add flow tracking constants
FLOW_TIMEOUT = 60  # seconds before a flow is considered ended
BYTES_TO_MB = 1024 * 1024

# Add flow tracking data structures
active_flows = {}
flow_lock = threading.Lock()

app = Flask(__name__)

@app.errorhandler(500)
def handle_500_error(e):
    logger.error(f"Internal Server Error: {str(e)}")
    return jsonify(error="Internal Server Error", message=str(e)), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {str(e)}")
    return jsonify(error="Server Error", message=str(e)), 500

def init_redis():
    """Initialize Redis connection and data structures with retry logic"""
    global redis_client
    retries = 0
    while retries < MAX_REDIS_RETRIES:
        try:
            print(f"Attempting to connect to Redis at {REDIS_HOST}:{REDIS_PORT} (attempt {retries + 1}/{MAX_REDIS_RETRIES})")
            redis_client = redis.Redis(
                host=REDIS_HOST, 
                port=REDIS_PORT, 
                decode_responses=True,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            
            # Check if Redis is ready
            info = redis_client.info()
            if info.get('loading', 0) == 1:
                loading_eta = info.get('loading_eta_seconds', 0)
                print(f"Redis is loading the dataset in memory. ETA: {loading_eta} seconds")
                time.sleep(min(loading_eta + 1, REDIS_RETRY_DELAY))
                retries += 1
                continue
                
            redis_client.ping()
            redis_client.delete(stats_key)
            redis_client.hmset(stats_key, {
                'total': '0',
                'tcp': '0',
                'udp': '0',
                'other': '0'
            })
            # Initialize packet counter if it doesn't exist
            redis_client.setnx(packet_counter_key, 0)
            print("Successfully connected to Redis")
            return True
            
        except redis.BusyLoadingError:
            print("Redis is still loading the dataset. Waiting...")
            time.sleep(REDIS_RETRY_DELAY)
            retries += 1
            continue
            
        except redis.ConnectionError as e:
            print(f"Redis connection error: {e}")
            retries += 1
            if retries < MAX_REDIS_RETRIES:
                print(f"Retrying in {REDIS_RETRY_DELAY} seconds...")
                time.sleep(REDIS_RETRY_DELAY)
            else:
                print("Max retries reached. Could not connect to Redis.")
                return False
                
        except Exception as e:
            print(f"Unexpected error connecting to Redis: {e}")
            return False

def init_geoip():
    """Initialize GeoIP databases"""
    global geo_reader, asn_reader
    try:
        if os.path.exists(GEOIP_DB_PATH):
            geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        else:
            logger.warning(f"GeoIP City database not found at {GEOIP_DB_PATH}")
            
        if os.path.exists(GEOIP_ASN_DB_PATH):
            asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)
        else:
            logger.warning(f"GeoIP ASN database not found at {GEOIP_ASN_DB_PATH}")
            
    except Exception as e:
        logger.error(f"Error initializing GeoIP databases: {e}")

def get_ip_info(ip):
    """Get GeoIP information for an IP address"""
    try:
        info = {
            'country': None,
            'region': None,
            'city': None,
            'asn': None,
            'isp': None
        }
        
        if geo_reader:
            try:
                response = geo_reader.city(ip)
                info['country'] = response.country.name
                info['region'] = response.subdivisions.most_specific.name if response.subdivisions else None
                info['city'] = response.city.name
            except (AddressNotFoundError, AttributeError):
                pass
                
        if asn_reader:
            try:
                response = asn_reader.asn(ip)
                info['asn'] = response.autonomous_system_number
                info['isp'] = response.autonomous_system_organization
            except (AddressNotFoundError, AttributeError):
                pass
                
        return info
    except Exception as e:
        logger.error(f"Error getting IP info for {ip}: {e}")
        return None

def process_packet_buffer():
    """Process buffered packets in batch"""
    global packet_buffer, last_buffer_process
    
    if not packet_buffer:
        return
        
    try:
        pipe = redis_client.pipeline()
        processed_count = 0
        
        for packet_data in packet_buffer:
            try:
                packet_id = redis_client.incr(packet_counter_key)
                key = f'packet:{packet_id}'
                
                # Uses safe default values
                sanitized_data = {}
                for field, value in packet_data.items():
                    if value is None:
                        sanitized_data[field] = ''
                    elif isinstance(value, (int, float)):
                        sanitized_data[field] = str(value)
                    else:
                        sanitized_data[field] = str(value)
                
                # Update protocol statistics
                protocol = int(packet_data.get('protocol', 0))
                pipe.hincrby(stats_key, 'total', 1)
                if protocol == 6:  # TCP
                    pipe.hincrby(stats_key, 'tcp', 1)
                elif protocol == 17:  # UDP
                    pipe.hincrby(stats_key, 'udp', 1)
                else:
                    pipe.hincrby(stats_key, 'other', 1)
                
                # Store packet data
                pipe.hmset(key, sanitized_data)
                pipe.lpush(packet_list_key, packet_id)
                pipe.expire(key, REDIS_DATA_TTL)  # Set TTL for packet data
                
                # Update sets for filtering
                if sanitized_data.get('src_country'):
                    pipe.sadd('packets:countries', sanitized_data['src_country'])
                if sanitized_data.get('src_isp'):
                    pipe.sadd('packets:isps', sanitized_data['src_isp'])
                
                # Update size distribution
                packet_length = int(sanitized_data['length'])
                for start, end in [(0, 64), (65, 128), (129, 256), (257, 512), (513, 1024), (1024, float('inf'))]:
                    if start <= packet_length <= (end if end != float('inf') else packet_length):
                        range_key = f'size:{start}-{end if end != float("inf") else "inf"}'
                        pipe.incr(range_key)
                
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Error processing individual packet: {e}")
                continue
        
        # Execute all commands in single transaction
        pipe.execute()
        logger.info(f"Successfully processed {processed_count}/{len(packet_buffer)} packets in Redis")
        
        # Update stats in Redis
        current_stats = redis_client.hgetall(stats_key)
        logger.info(f"Current packet statistics: {current_stats}")
        
    except redis.RedisError as e:
        logger.error(f"Redis error while processing packet buffer: {e}")
    except Exception as e:
        logger.error(f"Error processing packet buffer: {e}")
    finally:
        packet_buffer.clear()
        last_buffer_process = time.time()

def update_flow(src_ip, dst_ip, bytes_count, timestamp):
    """Update flow statistics"""
    flow_key = f"{src_ip}->{dst_ip}"
    reverse_key = f"{dst_ip}->{src_ip}"
    current_time = datetime.utcnow()
    
    with flow_lock:
        # Check if there's an existing flow in either direction
        if flow_key in active_flows:
            flow = active_flows[flow_key]
            if (current_time - flow['last_seen']).total_seconds() <= FLOW_TIMEOUT:
                # Update existing flow
                flow['bytes'] += bytes_count
                flow['packets'] += 1
                flow['last_seen'] = current_time
            else:
                # Start new flow
                active_flows[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'bytes': bytes_count,
                    'packets': 1,
                    'start_time': current_time,
                    'last_seen': current_time
                }
        elif reverse_key in active_flows:
            flow = active_flows[reverse_key]
            if (current_time - flow['last_seen']).total_seconds() <= FLOW_TIMEOUT:
                # Update existing reverse flow
                flow['bytes'] += bytes_count
                flow['packets'] += 1
                flow['last_seen'] = current_time
            else:
                # Start new flow
                active_flows[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'bytes': bytes_count,
                    'packets': 1,
                    'start_time': current_time,
                    'last_seen': current_time
                }
        else:
            # Start new flow
            active_flows[flow_key] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'bytes': bytes_count,
                'packets': 1,
                'start_time': current_time,
                'last_seen': current_time
            }

def cleanup_flows():
    """Remove expired flows"""
    current_time = datetime.utcnow()
    with flow_lock:
        expired_flows = [
            key for key, flow in active_flows.items()
            if (current_time - flow['last_seen']).total_seconds() > FLOW_TIMEOUT
        ]
        for key in expired_flows:
            del active_flows[key]

def get_active_flows():
    """Get current active flows with IP aliases"""
    cleanup_flows()
    flows_data = []
    
    try:
        # Get IP aliases in one query
        ip_aliases = {}
        with pg_conn.cursor() as cur:
            cur.execute("SELECT ip_address, alias FROM ip_aliases")
            for row in cur.fetchall():
                ip_aliases[row[0]] = row[1]
    except Exception as e:
        logger.error(f"Error fetching IP aliases for flows: {e}")
        ip_aliases = {}
    
    with flow_lock:
        for flow in active_flows.values():
            src_alias = ip_aliases.get(flow['src_ip'])
            dst_alias = ip_aliases.get(flow['dst_ip'])
            duration = (flow['last_seen'] - flow['start_time']).total_seconds()
            
            flows_data.append({
                'src_ip': flow['src_ip'],
                'src_alias': src_alias,
                'dst_ip': flow['dst_ip'],
                'dst_alias': dst_alias,
                'bytes': flow['bytes'],
                'mb': round(flow['bytes'] / BYTES_TO_MB, 2),
                'packets': flow['packets'],
                'duration': int(duration),
                'bytes_per_sec': round(flow['bytes'] / max(duration, 1), 2)
            })
    
    return flows_data

def packet_callback(packet):
    """Process captured packets and store in Redis"""
    global redis_client, packet_buffer, last_buffer_process
    
    if redis_client is None:
        logger.warning("Redis client not initialized. Skipping packet processing.")
        return
        
    if not packet.haslayer('IP'):
        return
        
    try:
        # Use UTC timestamp
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Extract packet data
        src_mac = packet[Ether].src if packet.haslayer('Ether') else None
        dst_mac = packet[Ether].dst if packet.haslayer('Ether') else None
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        src_port = packet[TCP].sport if packet.haslayer('TCP') else (packet[UDP].sport if packet.haslayer('UDP') else 0)
        dst_port = packet[TCP].dport if packet.haslayer('TCP') else (packet[UDP].dport if packet.haslayer('UDP') else 0)
        tcp_flags = str(packet[TCP].flags) if packet.haslayer('TCP') else None
        packet_length = len(packet)

        # Get application names for ports
        src_app = PORT_APPLICATIONS.get(src_port, '')
        dst_app = PORT_APPLICATIONS.get(dst_port, '')

        # Get GeoIP information
        src_ip_info = get_ip_info(src_ip)
        
        # Create packet data dictionary
        packet_data = {
            'timestamp': timestamp,  # UTC timestamp
            'src_mac': src_mac or '',
            'dst_mac': dst_mac or '',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port if src_port is not None else '',
            'dst_port': dst_port if dst_port is not None else '',
            'src_app': src_app,
            'dst_app': dst_app,
            'tcp_flags': tcp_flags or '',
            'length': packet_length,
            'src_country': src_ip_info['country'] if src_ip_info else '',
            'src_region': src_ip_info['region'] if src_ip_info else '',
            'src_city': src_ip_info['city'] if src_ip_info else '',
            'src_asn': src_ip_info['asn'] if src_ip_info else '',
            'src_isp': src_ip_info['isp'] if src_ip_info else ''
        }
        
        logger.info(f"Processing packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
        
        # Add to buffer with thread safety
        with buffer_lock:
            packet_buffer.append(packet_data)
            current_time = time.time()
            
            # Process buffer if it's full or timeout reached
            if len(packet_buffer) >= PACKET_BUFFER_SIZE or \
               (current_time - last_buffer_process) >= PACKET_BUFFER_TIMEOUT:
                logger.info(f"Processing buffer of {len(packet_buffer)} packets")
                process_packet_buffer()
                
        # Update flow statistics
        update_flow(src_ip, dst_ip, packet_length, timestamp)
        
    except Exception as e:
        logger.error(f"Error in packet callback: {e}")

def verbose_callback(pkt):
    print(f"Captured packet: {pkt.summary()}")
    packet_callback(pkt)

def start_packet_capture():
    """Start packet capture in a separate thread"""
    def capture_thread():
        while True:
            try:
                logger.info(f"Starting packet capture thread on interface {INTERFACE}")
                interfaces = get_if_list()
                logger.info(f"Available interfaces: {interfaces}")
                
                def debug_callback(pkt):
                    if pkt.haslayer('IP'):
                        # Log detailed packet information
                        log_msg = []
                        log_msg.append(f"Packet captured at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
                        
                        # Layer 2 info
                        if pkt.haslayer('Ether'):
                            log_msg.append(f"Ethernet: {pkt[Ether].src} -> {pkt[Ether].dst}")
                        
                        # Layer 3 info
                        log_msg.append(f"IP: {pkt[IP].src} -> {pkt[IP].dst}")
                        log_msg.append(f"Protocol: {pkt[IP].proto}")
                        log_msg.append(f"Length: {len(pkt)} bytes")
                        
                        # Layer 4 info
                        if pkt.haslayer('TCP'):
                            log_msg.append(f"TCP: {pkt[TCP].sport} -> {pkt[TCP].dport}")
                            log_msg.append(f"Flags: {pkt[TCP].flags}")
                        elif pkt.haslayer('UDP'):
                            log_msg.append(f"UDP: {pkt[UDP].sport} -> {pkt[UDP].dport}")
                        
                        logger.info(" | ".join(log_msg))
                    
                    # Process the packet
                    packet_callback(pkt)
                
                # Start sniffing with verbose logging
                logger.info(f"Starting packet capture on interface {INTERFACE}")
                sniff(iface=INTERFACE, 
                      prn=debug_callback, 
                      store=0,
                      filter="ip and (tcp or udp)")
                      
            except Exception as e:
                logger.error(f"Capture error: {e}")
                time.sleep(5)  # Wait before retrying

    # Start capture thread
    thread = threading.Thread(target=capture_thread)
    thread.daemon = True
    thread.start()
    
    # Start buffer processing thread
    def buffer_process_thread():
        while True:
            try:
                time.sleep(PACKET_BUFFER_TIMEOUT)
                with buffer_lock:
                    if packet_buffer and (time.time() - last_buffer_process) >= PACKET_BUFFER_TIMEOUT:
                        logger.info(f"Processing buffered packets (buffer size: {len(packet_buffer)})")
                        process_packet_buffer()
            except Exception as e:
                logger.error(f"Buffer processing error: {e}")
    
    process_thread = threading.Thread(target=buffer_process_thread)
    process_thread.daemon = True
    process_thread.start()
    
    return thread

def init_postgres():
    """Initialize PostgreSQL connection and create tables with retry logic"""
    global pg_conn
    retries = 0
    max_retries = 30
    retry_delay = 1

    while retries < max_retries:
        try:
            logger.info(f"Attempting to connect to PostgreSQL at {POSTGRES_HOST}:{POSTGRES_PORT} (attempt {retries + 1}/{max_retries})")
            pg_conn = psycopg2.connect(
                host=os.getenv('POSTGRES_HOST', 'localhost'),
                port=int(os.getenv('POSTGRES_PORT', 5433)),
                database=os.getenv('POSTGRES_DB', 'postgres'),
                user=os.getenv('POSTGRES_USER', 'postgres'),
                password=os.getenv('POSTGRES_PASSWORD', 'postgres123'),
                connect_timeout=5
            )
            
            with pg_conn.cursor() as cur:
                # Create port mappings table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS port_mappings (
                        port INTEGER PRIMARY KEY,
                        application VARCHAR(100) NOT NULL,
                        description TEXT,
                        category VARCHAR(50),
                        is_custom BOOLEAN DEFAULT true,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create trigger for updating timestamp
                cur.execute("""
                    CREATE OR REPLACE FUNCTION update_updated_at_column()
                    RETURNS TRIGGER AS $$
                    BEGIN
                        NEW.updated_at = CURRENT_TIMESTAMP;
                        RETURN NEW;
                    END;
                    $$ language 'plpgsql';
                """)
                
                # Create trigger for port_mappings
                cur.execute("""
                    DROP TRIGGER IF EXISTS update_port_mappings_updated_at ON port_mappings;
                    CREATE TRIGGER update_port_mappings_updated_at
                        BEFORE UPDATE ON port_mappings
                        FOR EACH ROW
                        EXECUTE FUNCTION update_updated_at_column();
                """)
                
                # Insert default port mappings if they don't exist
                for port, app in PORT_APPLICATIONS.items():
                    cur.execute("""
                        INSERT INTO port_mappings (port, application, is_custom)
                        VALUES (%s, %s, false)
                        ON CONFLICT (port) DO NOTHING
                    """, (port, app))
                
                # Create packets table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMP,
                        src_mac VARCHAR(17),
                        dst_mac VARCHAR(17),
                        src_ip VARCHAR(39),
                        dst_ip VARCHAR(39),
                        protocol INTEGER,
                        src_port INTEGER,
                        dst_port INTEGER,
                        src_app VARCHAR(50),
                        dst_app VARCHAR(50),
                        tcp_flags VARCHAR(20),
                        length INTEGER,
                        src_country VARCHAR(100),
                        src_region VARCHAR(100),
                        src_city VARCHAR(100),
                        src_asn INTEGER,
                        src_isp VARCHAR(200)
                    )
                """)
                
                # Create IP aliases table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ip_aliases (
                        ip_address VARCHAR(39) PRIMARY KEY,
                        alias VARCHAR(100) NOT NULL,
                        notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create function to update timestamp
                cur.execute("""
                    CREATE OR REPLACE FUNCTION update_updated_at_column()
                    RETURNS TRIGGER AS $$
                    BEGIN
                        NEW.updated_at = CURRENT_TIMESTAMP;
                        RETURN NEW;
                    END;
                    $$ language 'plpgsql';
                """)
                
                # Create trigger for updating timestamp
                cur.execute("""
                    DROP TRIGGER IF EXISTS update_ip_aliases_updated_at ON ip_aliases;
                    CREATE TRIGGER update_ip_aliases_updated_at
                        BEFORE UPDATE ON ip_aliases
                        FOR EACH ROW
                        EXECUTE FUNCTION update_updated_at_column();
                """)
                
                # Create indexes
                cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)")
                
            pg_conn.commit()
            logger.info("PostgreSQL tables created successfully")
            return True
            
        except psycopg2.OperationalError as e:
            logger.warning(f"PostgreSQL connection attempt {retries + 1} failed: {e}")
            retries += 1
            if retries < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("Max retries reached. Could not connect to PostgreSQL.")
                return False
                
        except Exception as e:
            logger.error(f"Error initializing PostgreSQL: {e}")
            if pg_conn:
                pg_conn.rollback()
            return False

def archive_to_postgres():
    """Archive data from Redis to PostgreSQL"""
    global pg_conn
    
    try:
        # Get all packet IDs from Redis
        packet_ids = redis_client.lrange(packet_list_key, 0, -1)
        if not packet_ids:
            return
            
        # Prepare data for batch insert
        packets_data = []
        for packet_id in packet_ids:
            packet_data = redis_client.hgetall(f'packet:{packet_id}')
            if packet_data:
                # Parse UTC timestamp
                try:
                    timestamp = datetime.strptime(packet_data['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    timestamp = datetime.strptime(packet_data['timestamp'], "%Y-%m-%d %H:%M:%S")
                
                packets_data.append((
                    timestamp,  # Store as UTC in PostgreSQL
                    packet_data.get('src_mac', ''),
                    packet_data.get('dst_mac', ''),
                    packet_data.get('src_ip', ''),
                    packet_data.get('dst_ip', ''),
                    int(packet_data.get('protocol', 0)),
                    int(packet_data.get('src_port', 0)),
                    int(packet_data.get('dst_port', 0)),
                    packet_data.get('src_app', ''),
                    packet_data.get('dst_app', ''),
                    packet_data.get('tcp_flags', ''),
                    int(packet_data.get('length', 0)),
                    packet_data.get('src_country', ''),
                    packet_data.get('src_region', ''),
                    packet_data.get('src_city', ''),
                    int(packet_data.get('src_asn', 0) or 0),
                    packet_data.get('src_isp', '')
                ))
        
        # Batch insert into PostgreSQL
        with pg_lock:
            if pg_conn is None or pg_conn.closed:
                init_postgres()
                
            with pg_conn.cursor() as cur:
                execute_batch(cur, """
                    INSERT INTO packets (
                        timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol,
                        src_port, dst_port, src_app, dst_app, tcp_flags, length,
                        src_country, src_region, src_city, src_asn, src_isp
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, packets_data)
                
                # Update hourly statistics
                cur.execute("""
                    INSERT INTO hourly_stats (
                        hour,
                        total_packets,
                        tcp_packets,
                        udp_packets,
                        other_packets,
                        total_bytes,
                        unique_ips
                    )
                    SELECT
                        date_trunc('hour', timestamp),
                        COUNT(*),
                        COUNT(*) FILTER (WHERE protocol = 6),
                        COUNT(*) FILTER (WHERE protocol = 17),
                        COUNT(*) FILTER (WHERE protocol NOT IN (6, 17)),
                        SUM(length),
                        COUNT(DISTINCT src_ip)
                    FROM packets
                    WHERE timestamp >= NOW() - INTERVAL '1 hour'
                    GROUP BY date_trunc('hour', timestamp)
                    ON CONFLICT (hour) DO UPDATE
                    SET
                        total_packets = EXCLUDED.total_packets,
                        tcp_packets = EXCLUDED.tcp_packets,
                        udp_packets = EXCLUDED.udp_packets,
                        other_packets = EXCLUDED.other_packets,
                        total_bytes = EXCLUDED.total_bytes,
                        unique_ips = EXCLUDED.unique_ips
                """)
                
            pg_conn.commit()
            
            # After successful archive, remove old data from Redis
            pipe = redis_client.pipeline()
            for packet_id in packet_ids:
                pipe.delete(f'packet:{packet_id}')
            pipe.delete(packet_list_key)
            pipe.execute()
            
            logger.info(f"Archived {len(packets_data)} packets to PostgreSQL")
            
    except Exception as e:
        logger.error(f"Error archiving to PostgreSQL: {e}")
        if pg_conn:
            pg_conn.rollback()

def start_archival_thread():
    """Start the thread that archives data to PostgreSQL"""
    def archival_thread():
        while True:
            try:
                time.sleep(ARCHIVE_INTERVAL)
                archive_to_postgres()
            except Exception as e:
                logger.error(f"Error in archival thread: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    thread = threading.Thread(target=archival_thread)
    thread.daemon = True
    thread.start()
    return thread

def get_available_interfaces():
    """Get list of available network interfaces"""
    try:
        interfaces = get_if_list()
        print("Available network interfaces:")
        for iface in interfaces:
            try:
                if_addrs = get_if_addr(iface)
                if_hwaddr = get_if_hwaddr(iface)
                print(f"- {iface} (IP: {if_addrs}, MAC: {if_hwaddr})")
            except:
                print(f"- {iface} (No IP address)")
        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []

def initialize_app():
    """Initialize the application"""
    global INTERFACE  # Move global declaration to the beginning of the function
    
    # Initialize Redis with retries
    retry_count = 0
    max_startup_retries = 5
    redis_initialized = False
    
    while not redis_initialized and retry_count < max_startup_retries:
        if init_redis():
            redis_initialized = True
            break
        retry_count += 1
        if retry_count < max_startup_retries:
            logger.info(f"Retrying Redis initialization in 5 seconds... (attempt {retry_count + 1}/{max_startup_retries})")
            time.sleep(5)
    
    if not redis_initialized:
        logger.error("Failed to initialize Redis after multiple attempts. Exiting.")
        return None

    # Initialize PostgreSQL
    if not init_postgres():
        logger.error("Failed to initialize PostgreSQL. Exiting.")
        return None

    # Initialize GeoIP databases
    init_geoip()
    
    # Get available interfaces
    interfaces = get_available_interfaces()
    
    # Check specified interface
    if INTERFACE:
        if INTERFACE not in interfaces:
            logger.warning(f"Warning: Specified interface {INTERFACE} not found.")
            logger.info("Available interfaces: " + ", ".join(interfaces))
            
            # Try to find a suitable default interface
            default_interface = None
            for iface in interfaces:
                try:
                    # Skip loopback and virtual interfaces
                    if 'lo' in iface.lower() or 'virtual' in iface.lower():
                        continue
                    # Try to get IP address
                    if_addr = get_if_addr(iface)
                    if if_addr and not if_addr.startswith('127.'):
                        default_interface = iface
                        break
                except:
                    continue
            
            if default_interface:
                logger.info(f"Using default interface: {default_interface}")
                INTERFACE = default_interface
            else:
                logger.warning("No suitable interface found. Will capture on all interfaces.")
                return None
    
    # Start packet capture
    try:
        logger.info(f"\nStarting packet capture on {'all interfaces' if not INTERFACE else f'interface {INTERFACE}'}")
        capture_thread = start_packet_capture()
        
        # Start archival thread
        archival_thread = start_archival_thread()
        
        return capture_thread
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        return None

@app.route('/')
def index():
    try:
        # Get basic stats from Redis
        total_packets = int(redis_client.get(packet_counter_key) or 0)
        
        # Get unique countries and ISPs
        countries = sorted(list(redis_client.smembers('packets:countries') or set()))
        isps = sorted(list(redis_client.smembers('packets:isps') or set()))
        
        # Get top talkers
        top_talkers = []
        try:
            top_ips = redis_client.zrevrange('packets:ip_bytes', 0, 9, withscores=True)
            for ip, bytes_total in top_ips:
                ip_data = redis_client.hgetall(f'ip:data:{ip}')
                ip_info = get_ip_info(ip)
                top_talkers.append({
                    'src_ip': ip,
                    'src_country': ip_info['country'] if ip_info else 'Unknown',
                    'src_isp': ip_info['isp'] if ip_info else 'Unknown',
                    'total_packets': int(ip_data.get('packets', 0)),
                    'total_bytes': int(bytes_total)
                })
        except redis.RedisError as e:
            logger.error(f"Error getting top talkers: {e}")
            top_talkers = []

        return render_template('index.html',
                            filters=request.args,
                            countries=countries,
                            isps=isps,
                            total_packets=total_packets,
                            top_talkers=top_talkers)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return jsonify(error="Error loading dashboard", message=str(e)), 500

@app.route('/api/stats')
def get_stats():
    try:
        if redis_client is None:
            raise Exception("Redis client not initialized")

        # Apply filters
        country_filter = request.args.get('country')
        isp_filter = request.args.get('isp')
        ip_filter = request.args.get('ip')
        protocol_filter = request.args.get('protocol')
        port_filter = request.args.get('port')

        # Get packet counts
        print("Fetching stats from Redis...")
        stats = redis_client.hgetall(stats_key) or {}
        print(f"Raw stats from Redis: {stats}")
        total_packets = int(stats.get('total', 0))
        tcp_packets = int(stats.get('tcp', 0))
        udp_packets = int(stats.get('udp', 0))
        other_packets = int(stats.get('other', 0))

        # Get packet size distribution
        size_ranges = [(0, 64), (65, 128), (129, 256), (257, 512), (513, 1024), (1024, float('inf'))]
        size_distribution = []
        
        for start, end in size_ranges:
            range_key = f'size:{start}-{end if end != float("inf") else "inf"}'
            count = int(redis_client.get(range_key) or 0)
            size_distribution.append(count)

        # Get recent packets (last 100)
        recent_packet_ids = redis_client.lrange(packet_list_key, 0, 99) or []
        recent_packets = []
        
        # Get all IP aliases in one query
        ip_aliases = {}
        try:
            with pg_conn.cursor() as cur:
                cur.execute("SELECT ip_address, alias FROM ip_aliases")
                for row in cur.fetchall():
                    ip_aliases[row[0]] = row[1]
        except Exception as e:
            logger.error(f"Error fetching IP aliases: {e}")
        
        # Get custom port mappings
        port_mappings = {}
        try:
            with pg_conn.cursor() as cur:
                cur.execute("SELECT port, application FROM port_mappings")
                for row in cur.fetchall():
                    port_mappings[row[0]] = row[1]
        except Exception as e:
            logger.error(f"Error fetching port mappings: {e}")
        
        for packet_id in recent_packet_ids:
            try:
                packet_data = redis_client.hgetall(f'packet:{packet_id}')
                if packet_data:
                    # Apply filters
                    if country_filter and packet_data.get('src_country') != country_filter:
                        continue
                    if isp_filter and packet_data.get('src_isp') != isp_filter:
                        continue
                    if ip_filter and not (packet_data.get('src_ip').startswith(ip_filter) or 
                                        packet_data.get('dst_ip').startswith(ip_filter)):
                        continue
                    if protocol_filter:
                        protocol = int(packet_data.get('protocol', 0))
                        if str(protocol) != protocol_filter:
                            continue
                    if port_filter:
                        src_port = int(packet_data.get('src_port', 0))
                        dst_port = int(packet_data.get('dst_port', 0))
                        if str(src_port) != port_filter and str(dst_port) != port_filter:
                            continue

                    # Add IP aliases to packet data
                    src_ip = packet_data.get('src_ip')
                    dst_ip = packet_data.get('dst_ip')
                    packet_data['src_alias'] = ip_aliases.get(src_ip)
                    packet_data['dst_alias'] = ip_aliases.get(dst_ip)

                    # Update port mappings
                    src_port = int(packet_data.get('src_port', 0))
                    dst_port = int(packet_data.get('dst_port', 0))
                    packet_data['src_app'] = port_mappings.get(src_port, PORT_APPLICATIONS.get(src_port, ''))
                    packet_data['dst_app'] = port_mappings.get(dst_port, PORT_APPLICATIONS.get(dst_port, ''))

                    protocol = int(packet_data.get('protocol', 0))
                    recent_packets.append({
                        'timestamp': packet_data.get('timestamp'),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_alias': ip_aliases.get(src_ip),
                        'dst_alias': ip_aliases.get(dst_ip),
                        'protocol': 'TCP' if protocol == 6 else 'UDP' if protocol == 17 else str(protocol),
                        'length': int(packet_data.get('length', 0)),
                        'src_port': int(packet_data.get('src_port', 0)),
                        'dst_port': int(packet_data.get('dst_port', 0)),
                        'src_app': packet_data.get('src_app', ''),
                        'dst_app': packet_data.get('dst_app', ''),
                        'country': packet_data.get('src_country', 'Unknown'),
                        'region': packet_data.get('src_region', 'Unknown'),
                        'city': packet_data.get('src_city', 'Unknown'),
                        'isp': packet_data.get('src_isp', 'Unknown')
                    })
            except (ValueError, TypeError) as e:
                logger.error(f"Error processing packet {packet_id}: {e}")
                continue

        # Add active flows to the response
        flows = get_active_flows()
        
        return jsonify({
            'total_packets': total_packets,
            'tcp_packets': tcp_packets,
            'udp_packets': udp_packets,
            'other_packets': other_packets,
            'size_distribution': size_distribution,
            'recent_packets': recent_packets,
            'active_flows': sorted(flows, key=lambda x: x['bytes'], reverse=True)
        })
    except redis.RedisError as e:
        logger.error(f"Redis error in get_stats: {e}")
        return jsonify(error="Database error", message=str(e)), 500
    except Exception as e:
        logger.error(f"Error in get_stats: {e}")
        return jsonify(error="Server error", message=str(e)), 500

@app.route('/api/historical_stats')
def get_historical_stats():
    try:
        days = int(request.args.get('days', 7))
        with pg_lock:
            if pg_conn is None or pg_conn.closed:
                init_postgres()
                
            with pg_conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        hour,
                        total_packets,
                        tcp_packets,
                        udp_packets,
                        other_packets,
                        total_bytes,
                        unique_ips
                    FROM hourly_stats
                    WHERE hour >= NOW() - INTERVAL %s DAY
                    ORDER BY hour DESC
                """, (days,))
                
                results = cur.fetchall()
                
                stats = [{
                    'hour': row[0].strftime("%Y-%m-%d %H:%M:%S"),
                    'total_packets': row[1],
                    'tcp_packets': row[2],
                    'udp_packets': row[3],
                    'other_packets': row[4],
                    'total_bytes': row[5],
                    'unique_ips': row[6]
                } for row in results]
                
                return jsonify(stats)
                
    except Exception as e:
        logger.error(f"Error getting historical stats: {e}")
        return jsonify(error="Database error", message=str(e)), 500

@app.route('/api/ip_alias/<ip_address>', methods=['GET'])
def get_ip_alias(ip_address):
    try:
        with pg_conn.cursor() as cur:
            cur.execute("SELECT alias, notes FROM ip_aliases WHERE ip_address = %s", (ip_address,))
            result = cur.fetchone()
            if result:
                return jsonify({
                    'ip_address': ip_address,
                    'alias': result[0],
                    'notes': result[1]
                })
            return jsonify({'ip_address': ip_address, 'alias': None, 'notes': None})
    except Exception as e:
        logger.error(f"Error getting IP alias: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip_alias/<ip_address>', methods=['POST'])
def update_ip_alias(ip_address):
    try:
        data = request.get_json()
        alias = data.get('alias')
        notes = data.get('notes', '')
        
        with pg_conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ip_aliases (ip_address, alias, notes)
                VALUES (%s, %s, %s)
                ON CONFLICT (ip_address) DO UPDATE
                SET alias = EXCLUDED.alias,
                    notes = EXCLUDED.notes
            """, (ip_address, alias, notes))
            pg_conn.commit()
            
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating IP alias: {e}")
        pg_conn.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/port_mapping/<int:port>', methods=['GET'])
def get_port_mapping(port):
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                SELECT application, description, category, is_custom
                FROM port_mappings
                WHERE port = %s
            """, (port,))
            result = cur.fetchone()
            if result:
                return jsonify({
                    'port': port,
                    'application': result[0],
                    'description': result[1],
                    'category': result[2],
                    'is_custom': result[3]
                })
            return jsonify({
                'port': port,
                'application': PORT_APPLICATIONS.get(port, ''),
                'description': None,
                'category': None,
                'is_custom': False
            })
    except Exception as e:
        logger.error(f"Error getting port mapping: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/port_mapping/<int:port>', methods=['POST'])
def update_port_mapping(port):
    try:
        data = request.get_json()
        application = data.get('application')
        description = data.get('description', '')
        category = data.get('category', '')
        
        with pg_conn.cursor() as cur:
            cur.execute("""
                INSERT INTO port_mappings (port, application, description, category)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (port) DO UPDATE
                SET application = EXCLUDED.application,
                    description = EXCLUDED.description,
                    category = EXCLUDED.category,
                    is_custom = true
            """, (port, application, description, category))
            pg_conn.commit()
            
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating port mapping: {e}")
        pg_conn.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/port_mapping/<int:port>', methods=['DELETE'])
def delete_port_mapping(port):
    try:
        with pg_conn.cursor() as cur:
            cur.execute("DELETE FROM port_mappings WHERE port = %s AND is_custom = true", (port,))
            pg_conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting port mapping: {e}")
        pg_conn.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/flows')
def get_flows():
    try:
        flows = get_active_flows()
        return jsonify({
            'flows': sorted(flows, key=lambda x: x['bytes'], reverse=True)
        })
    except Exception as e:
        logger.error(f"Error getting flows: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for Docker"""
    health_status = {
        'status': 'healthy',
        'redis': False,
        'postgres': False,
        'packet_capture': False,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        # Check Redis connection
        if redis_client:
            redis_client.ping()
            health_status['redis'] = True
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        health_status['status'] = 'unhealthy'
        health_status['redis_error'] = str(e)
    
    try:
        # Check PostgreSQL connection
        if pg_conn and not pg_conn.closed:
            with pg_conn.cursor() as cur:
                cur.execute('SELECT 1')
                cur.fetchone()
            health_status['postgres'] = True
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {e}")
        health_status['status'] = 'unhealthy'
        health_status['postgres_error'] = str(e)
    
    try:
        # Check if packet capture thread is running
        if 'capture_thread' in globals() and capture_thread.is_alive():
            health_status['packet_capture'] = True
    except Exception as e:
        logger.error(f"Packet capture thread check failed: {e}")
        health_status['status'] = 'unhealthy'
        health_status['packet_capture_error'] = str(e)
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code

if __name__ == '__main__':
    capture_thread = initialize_app()
    if capture_thread is None:
        logger.error("Failed to start packet capture. Exiting.")
        sys.exit(1)
        
    logger.info(f"Web interface will be available on port {PORT}")
    
    # In development, use Flask's built-in server
    if os.getenv('FLASK_ENV') == 'development':
        app.run(host='0.0.0.0', port=PORT, debug=False)
    else:
        # In production, use Gunicorn
        import gunicorn.app.base

        class PacketSnifferApp(gunicorn.app.base.BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()

            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)

            def load(self):
                return self.application

        options = {
            'bind': f'0.0.0.0:{PORT}',
            'workers': 1,  # We only need one worker as we're using threads for capture
            'worker_class': 'sync',  # Use sync workers as we don't need async
            'timeout': 120,
            'accesslog': '-',  # Log to stdout
            'errorlog': '-',   # Log to stdout
        }
        
        PacketSnifferApp(app, options).run() 