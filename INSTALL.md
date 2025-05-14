# Installation Guide

## GeoLite2 Databases

This application requires MaxMind's GeoLite2 databases for IP geolocation. Follow these steps to obtain them:

1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup

2. Generate a license key in your MaxMind account

3. Download the following databases:
   - GeoLite2-City.mmdb
   - GeoLite2-ASN.mmdb

4. Place both .mmdb files in the root directory of this project

Note: These databases are not included in the repository as they require a license from MaxMind.

## Environment Setup

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your configuration:
   - Set your network interface
   - Update database credentials
   - Configure other settings as needed

## Running the Application

Follow the instructions in README.md for running the application with Docker or manual installation. 