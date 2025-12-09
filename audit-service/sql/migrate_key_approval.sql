-- Migration: Add key approval workflow columns
-- Run this after updating to support pending/approved/rejected key states

-- Add status column with default 'approved' for existing keys
ALTER TABLE key_registry 
ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'approved' 
CHECK (status IN ('pending', 'approved', 'rejected'));

-- Add review columns
ALTER TABLE key_registry 
ADD COLUMN IF NOT EXISTS reviewed_by TEXT;

ALTER TABLE key_registry 
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

ALTER TABLE key_registry 
ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- Update algorithm constraint to include rsa-pkcs1v15
ALTER TABLE key_registry DROP CONSTRAINT IF EXISTS key_registry_algorithm_check;
ALTER TABLE key_registry ADD CONSTRAINT key_registry_algorithm_check 
CHECK (algorithm IN ('ed25519', 'rsa-pss', 'rsa-pkcs1v15'));

-- Update index to only include approved keys
DROP INDEX IF EXISTS idx_key_service_active;
CREATE INDEX IF NOT EXISTS idx_key_service_active 
    ON key_registry(service_id) 
    WHERE status = 'approved' AND disabled_at IS NULL AND rotated_to IS NULL;

-- Add index for pending key requests
CREATE INDEX IF NOT EXISTS idx_key_pending 
    ON key_registry(created_at DESC) 
    WHERE status = 'pending';

-- Update existing keys to approved status (they were already working)
UPDATE key_registry SET status = 'approved' WHERE status IS NULL OR status = '';

SELECT 'Migration completed: Key approval workflow enabled' as status;
