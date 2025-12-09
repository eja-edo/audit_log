-- ============================================================================
-- Migration: Add Admin Users Table for JWT Authentication
-- ============================================================================
-- Run this migration to add user authentication support
-- 
-- Usage:
--   docker exec -i audit_postgres psql -U audit_user -d audit_db < sql/add_admin_users.sql

-- Create admin_users table
CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255),
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'superadmin')),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login TIMESTAMPTZ
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role);
CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users(is_active);

-- Create trigger for updated_at
CREATE OR REPLACE FUNCTION update_admin_users_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_admin_users_timestamp ON admin_users;
CREATE TRIGGER trigger_update_admin_users_timestamp
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_admin_users_timestamp();

-- Insert default admin user
-- Password: admin123 (change this in production!)
-- BCrypt hash for 'admin123'
INSERT INTO admin_users (username, email, hashed_password, role)
VALUES (
    'admin',
    'admin@audit-service.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.i7eCsAH7mG8Bzy',  -- admin123
    'superadmin'
)
ON CONFLICT (username) DO NOTHING;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON admin_users TO audit_api_role;
GRANT USAGE, SELECT ON SEQUENCE admin_users_id_seq TO audit_api_role;

-- Add comment
COMMENT ON TABLE admin_users IS 'Admin users for JWT authentication';

SELECT 'Admin users table created successfully' as status;
