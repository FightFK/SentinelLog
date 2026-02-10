-- Convert embedding column from TEXT to vector(1536)
-- This migration requires the pgvector extension to be enabled

-- Step 1: Drop the old TEXT column
ALTER TABLE security_logs DROP COLUMN IF EXISTS embedding;

-- Step 2: Add new vector column
ALTER TABLE security_logs ADD COLUMN embedding vector(1536);

-- Step 3: Create index for fast similarity search using cosine distance
CREATE INDEX IF NOT EXISTS security_logs_embedding_idx 
ON security_logs 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- Optional: Add index for L2 distance if needed
-- CREATE INDEX security_logs_embedding_l2_idx 
-- ON security_logs 
-- USING ivfflat (embedding vector_l2_ops);
