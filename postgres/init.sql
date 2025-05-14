-- Create user if not exists
DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'packet_user') THEN

      CREATE ROLE packet_user WITH LOGIN PASSWORD 'packet_password';
   END IF;
END
$do$;

-- Grant privileges
ALTER ROLE packet_user WITH SUPERUSER;
ALTER ROLE packet_user WITH CREATEDB;

-- Create database if not exists
CREATE DATABASE packet_data WITH OWNER = packet_user;

-- Connect to the new database
\c packet_data;

-- Create extensions and set up schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges on database
GRANT ALL PRIVILEGES ON DATABASE packet_data TO packet_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO packet_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO packet_user; 