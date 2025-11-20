--Init separate database for each microservice
-- this script runs when PostgreSQL container starts for the first time

--Create database for each service
CREATE DATABASE notesverb_auth;
CREATE DATABASE notesverb_users;
CREATE DATABASE notesverb_notes;
CREATE DATABASE notesverb_tags;

GRANT ALL PRIVILEGES ON DATABASE notesverb_auth TO noeverb;
GRANT ALL PRIVILEGES ON DATABASE notesverb_users TO noeverb;
GRANT ALL PRIVILEGES ON DATABASE notesverb_notes TO noeverb;
GRANT ALL PRIVILEGES ON DATABASE notesverb_tags TO noeverb;
