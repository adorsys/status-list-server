CREATE TABLE IF NOT EXISTS credentials (
  id SERIAL PRIMARY KEY,
  issuer TEXT NOT NULL UNIQUE,
  public_key JSONB NOT NULL,  
  alg TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS status_list_tokens (
  id SERIAL PRIMARY KEY,
  issuer TEXT NOT NULL REFERENCES credentials(issuer) ON DELETE CASCADE,
  status_list_id TEXT NOT NULL,
  status_list_token JSONB CHECK (status_list_token IS NULL OR jsonb_typeof(status_list_token) IS NOT NULL),
  UNIQUE (issuer, status_list_id)
);
