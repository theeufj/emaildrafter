CREATE TABLE users (
  id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  credentials JSONB NOT NULL,
  google_id VARCHAR(255) UNIQUE NOT NULL, -- Google's user ID
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_users_google_id ON users (google_id);

Alter TABLE users ADD COLUMN api_key VARCHAR(255) UNIQUE;
Alter TABLE users ADD COLUMN api_key_dev VARCHAR(255) UNIQUE;

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    data JSONB,
    expires TIMESTAMP WITH TIME ZONE NOT NULL
);


CREATE TABLE LOGS(
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id uuid REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    api_type VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

Alter TABLE LOGS ADD COLUMN Comments VARCHAR(255);