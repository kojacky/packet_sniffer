# Network Packet Sniffer with Web Interface

A powerful network packet sniffer with real-time web interface, built with Python, Flask, Redis, and PostgreSQL. This tool captures network packets, analyzes them in real-time, and provides a beautiful web interface for monitoring and analysis.

## Features

- Real-time packet capture and analysis
- Web-based interface for monitoring network traffic
- GeoIP location tracking for source IPs
- Flow tracking and analysis
- Port-to-application mapping
- Custom IP aliases for better network visibility
- Historical data archival with PostgreSQL
- Docker support for easy deployment
- Redis-based caching for high performance
- Support for TCP and UDP traffic analysis

## Prerequisites

- Docker and Docker Compose
- Python 3.8 or higher (if running without Docker)
- GeoLite2 databases (City and ASN)
- Network interface with promiscuous mode support

## Quick Start with Docker

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   ```

2. Create a `.env` file with your configuration:
   ```bash
   CAPTURE_INTERFACE=eth0  # Your network interface
   FLASK_PORT=8080
   REDIS_HOST=redis
   REDIS_PORT=6379
   POSTGRES_HOST=postgres
   POSTGRES_PORT=5433
   POSTGRES_DB=postgres
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=your_secure_password
   ```

3. Download GeoLite2 databases:
   - Get GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind
   - Place them in the project root directory

4. Start the containers:
   ```bash
   docker-compose up -d
   ```

5. Access the web interface at `http://localhost:8080`

## Manual Installation

1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate  # Windows
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up Redis and PostgreSQL:
   - Install Redis and PostgreSQL
   - Create database and user
   - Update configuration in .env file

4. Run the application:
   ```bash
   sudo python packet_capture.py  # Requires sudo for packet capture
   python web_interface.py  # Web interface
   ```

## Configuration

The application can be configured through environment variables or .env file:

- `CAPTURE_INTERFACE`: Network interface to capture packets
- `FLASK_PORT`: Web interface port (default: 8080)
- `REDIS_HOST`: Redis host (default: localhost)
- `REDIS_PORT`: Redis port (default: 6379)
- `POSTGRES_*`: PostgreSQL connection settings
- `ARCHIVE_INTERVAL`: Data archival interval in seconds (default: 3600)
- `REDIS_DATA_TTL`: Time to live for Redis data in seconds (default: 7200)

## Security Considerations

- Run in a secure network environment
- Use strong passwords for databases
- Keep GeoIP databases up to date
- Regularly update dependencies
- Use HTTPS in production
- Implement proper access controls

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) for packet capture
- [Flask](https://flask.palletsprojects.com/) for web interface
- [Redis](https://redis.io/) for caching
- [PostgreSQL](https://www.postgresql.org/) for data storage
- [MaxMind](https://www.maxmind.com/) for GeoIP databases 