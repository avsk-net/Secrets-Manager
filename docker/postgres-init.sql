-- PostgreSQL initialization script
-- Runs once when the container is first created

-- Enable UUID extension (for gen_random_uuid())
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create the API user with limited privileges
-- In production: this user should NOT have CREATE TABLE / DROP TABLE
-- Alembic migrations should run with a separate privileged user
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'smgr_api') THEN
        CREATE ROLE smgr_api LOGIN PASSWORD 'api_password';
    END IF;
END $$;

-- Grant permissions after tables are created by migrations
-- These GRANTs are applied after Alembic runs (see Makefile)
-- GRANT SELECT, INSERT ON audit_logs TO smgr_api;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL OTHER TABLES TO smgr_api;
