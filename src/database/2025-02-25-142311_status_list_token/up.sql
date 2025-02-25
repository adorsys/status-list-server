CREATE TABLE IF NOT EXISTS credentials (
  id SERIAL PRIMARY KEY,
  issuer TEXT NOT NULL UNIQUE,
  public_key BYTEA NOT NULL,
  alg TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS status_list_tokens (
  id SERIAL PRIMARY KEY,
  issuer TEXT NOT NULL UNIQUE,
  status_list_token TEXT CHECK (status_list_token IS NULL OR status_list_token::jsonb IS NOT NULL) 
    -- Enforces that status_list_token can either be a valid JSONB or plain TEXT
);
