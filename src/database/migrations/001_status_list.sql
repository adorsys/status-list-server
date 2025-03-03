-- Add migration script here
CREATE TABLE IF NOT EXISTS credentials (
  id SERIAL PRIMARY KEY,
  issuer TEXT NOT NULL UNIQUE,
  public_key JSONB NOT NULL,  -- Changed from BYTEA to JSONB
  alg TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS status_list_tokens (
  id SERIAL PRIMARY KEY,
  issuer TEXT NOT NULL UNIQUE REFERENCES credentials(issuer) ON DELETE CASCADE,
  status_list_token JSONB CHECK (status_list_token IS NULL OR jsonb_typeof(status_list_token) IS NOT NULL)  
    -- Changed from TEXT to JSONB and ensured valid JSONB
);
