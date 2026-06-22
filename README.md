# Secure File Transfer System - Proof of Concept
Version: 1.0 (PoC)
Status: In Development

## Important - Pending Items
- LDAP/SSO server details required from IT before authentication can be
  updated from users.json to SSO (requested by management)
- Classification levels need to be confirmed with management and updated
  in ingress_app.py (currently set to generic defaults)

## Overview
This is a proof-of-concept for a secure one-way file transfer system
designed to move files from a connected network (low side) to a
disconnected network (high side) via a one-way data diode.

The system consists of two independent web applications:
- **Ingress App** (`ingress_app.py`) - runs on the connected network (low side)
- **Egress App** (`egress_app.py`) - runs on the disconnected network (high side)

## How It Works
1. User logs into the Ingress app and uploads a file
2. File is saved to the staging folder with a UUID and metadata.json
3. Staging folder is transferred via data diode to the inbox folder
4. User logs into the Egress app and downloads their file
5. File integrity is verified via SHA-256 hash before download

Note: In production, step 3 is handled automatically by the physical data
diode hardware. For the PoC, manually copy files from staging/ to inbox/
to simulate this transfer.

## Project Structure
Secure-File-Transfer-System/
- ingress_app.py      - Low side web application
- egress_app.py       - High side web application
- audit_log.py        - Shared audit logging module
- create_users.py     - Admin script to create/reset users
- users.json          - Hashed user credentials (auto-generated)
- .env                - Environment configuration
- staging/            - Where ingress saves uploaded files
- inbox/              - Where egress reads files from
- audit_log.json      - System audit log (auto-generated)
- README.md           - This file
- requirements.txt    - Python package dependencies
- Dockerfile

## Development Environment
- Python 3.14
- Windows 10/11
- Tested on: Chrome, Edge

## Requirements
- Python 3.11+
- streamlit
- bcrypt
- python-dotenv

Install all dependencies:
pip install -r requirements.txt

## Production Infrastructure Requirements
- 2 CPU cores minimum per system
- 4GB RAM minimum per system
- Docker Engine v20.10+
- Docker Compose v2.0+
- SSL/TLS certificates for HTTPS
- Network storage mounts for staging/inbox folders

## Setup Instructions

### Step 1 - Configure environment variables
Generate a secret key:
python -c "import secrets; print(secrets.token_hex(32))"

Rename the env example.txt file to .env and paste the secret key output into APP_SECRET_KEY.

### Step 2 - Create users
python create_users.py

Follow the prompts to create users.
Passwords must be at least 12 characters with uppercase, number, and special character.

Note: Since the Ingress and Egress networks are disconnected, users must
be created independently on each system. See Section 10.2 of the spec
for the full user synchronization process.

### Step 3 - Run the Ingress App
streamlit run ingress_app.py
Access at http://127.0.0.1:8501

### Step 4 - Run the Egress App
Open a second terminal:
streamlit run egress_app.py --server.port 8502
Access at http://127.0.0.1:8502

### Step 5 - Test the workflow
1. Log into Ingress as User-1
2. Upload a file addressed to User-2
3. Copy the UUID folder from staging/ to inbox/ (simulates data diode transfer)

   Manually copy the UUID folder(s) from the staging/ directory into the inbox/ 
   directory using your file manager or preferred method. This simulates what 
   the data diode hardware does automatically in production.
4. Log into Egress as User-2
5. Download the file and verify integrity check passes

## Security Features
- Passwords hashed with bcrypt (industry standard)
- SHA-256 file integrity verification
- Input sanitization on all form fields
- Filename sanitization (prevents directory traversal)
- Audit logging for all security events
- Environment variables for sensitive configuration
- Password complexity requirements (12+ characters)

## Audit Logging
All security events are logged to audit_log.json:
- Login success/failure
- File uploads
- File downloads
- Logout events

## Testing Requirements
The following tests are required per Section 11 of the spec before
production deployment:

### Security Testing
- Authentication bypass attempts
- Path traversal testing
- Session hijacking attempts
- Rate limiting verification

### Performance Testing
- Large file upload (> 1 GB)
- Multiple concurrent uploads
- Inbox scanning with 1,000+ pending files

### Integration Testing
- End-to-end file upload to download workflow
- Multi-user concurrent operations

## Known Limitations (Future Iterations)
The following features are planned but not yet implemented:

### Authentication
- LDAP/SSO integration (in progress - pending server details from IT)
- Session timeout after 30 minutes of inactivity
- Rate limiting on login attempts
- HTTPS/TLS encryption

### User Management
- Admin portal UI
- Role based access control (File Submitter / Administrator)
- Disable/enable user accounts
- List all users

### File Transfer
- Multi-file upload support
- Upload progress indicator
- File move to /storage/{username}/ on Egress side
- Post-transfer cleanup strategy (see FR-XFER-004 for three options)
- Transfer status tracking (staged/transferred/archived)

### Reporting
- Transfer reports (CSV/JSON/PDF export)
- Receipt reports on Egress side
- 90-day audit log retention policy

### Infrastructure
- Docker containerization
- PostgreSQL database for metadata storage
- Nginx reverse proxy
- Automated backups

## Specification Reference
This PoC implements the following requirements from the
Technical Specification v1.0:
- FR-ING-001 to FR-ING-012 (partial)
- FR-EGR-001 to FR-EGR-006
- NFR-SEC-001, NFR-SEC-005
- NFR-REL-002
- NFR-MAINT-001, NFR-MAINT-002

## For the Next Developer
1. Get LDAP server details from IT and implement ldap3 authentication
   - Replace users.json with LDAP - see Section 8.1 of the spec
2. Confirm classification levels with management and update the
   selectbox in ingress_app.py accordingly
3. Set up PostgreSQL database using schema in Appendix B of spec
4. Implement Docker using docker-compose.yml in Section 9 of spec
5. Add Nginx as reverse proxy for HTTPS
6. Build admin portal for user management (both Ingress and Egress)
7. Implement audit log retention policy (90 days per spec)
8. Add session timeout (30 minutes per spec)
9. Add rate limiting on login attempts
10. Implement periodic inbox scanning on Egress (every 5 minutes per spec)
11. User synchronization - since networks are disconnected, users must be
    manually created on both systems independently.
    See Section 10.2 of the spec for the full process.
12. Decide and implement post-transfer cleanup strategy for staging folder
    - see FR-XFER-004 in the spec for the three options
13. Complete documentation deliverables per Section 12 of the spec:
    - API documentation (OpenAPI/Swagger recommended)
    - Docker deployment guide
    - User guides for Ingress and Egress
    - Administrator guide
    - Security incident response procedures
