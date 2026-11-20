# Star Investigator — License Control Center (Owner Server)

**CONFIDENTIAL — OWNER-ONLY APPLICATION. Host the code in a PRIVATE GitHub repository.**
Never distribute the private signing keys, session secret, SQLite licensing database, or admin password.

## Project structure
- `owner_app.py` — Flask owner dashboard + activation API
- `owner_services/` — Ed25519 signer and SQLite licensing logic
- `templates/` — owner control center screens
- `static/` — dashboard styling
- `requirements.txt`, `Procfile`, `run_owner_dashboard.bat` — launch files
- `data/` — automatically generated private runtime files; intentionally NOT in Git

## Local Windows setup
1. Download/extract the project, and open a terminal in this folder.
2. Install Python 3.10+ and packages: `python -m pip install -r requirements.txt`.
3. Run `run_owner_dashboard.bat`. On the first run it asks you to choose a strong owner password (minimum 12 characters).
4. Open `http://127.0.0.1:5050` and sign in with username `owner` and your chosen password.

Alternatively, set `OWNER_INITIAL_PASSWORD` in the environment and run `python owner_app.py`.

## Deploy / security
- **Make the GitHub repository PRIVATE before uploading this business-critical code.**
- Set `OWNER_INITIAL_PASSWORD` (first run), and optionally `OWNER_DATA_DIR` to a directory on permanent, private storage.
- Use HTTPS, application-level access controls, backups, and a persistent data volume.
- The default SQLite database is not appropriate for large, multi-instance deployments.
- The private Ed25519 key, session secret and database are created on the first run and must stay consistent across restarts. Back them up securely; loss of the signing key will invalidate signatures associated with the old key.
- Admin password is stored as a salted PBKDF2 hash. Do not publish even hashed admin databases because they contain sensitive customer and license information.
- The included API allows public client activation requests; use rate limiting, HTTPS, and protected infrastructure before production.
- If a previous live database was initialized with a known default password, rotate that admin password before exposing the service. Setting a new `OWNER_INITIAL_PASSWORD` does **not** update an existing admin password.

## GitHub folder upload
You cannot upload the ZIP as a source tree using GitHub's web **Upload files** button. Extract it first; easiest way to preserve nested folders is Git CLI:

```bash
git clone https://github.com/abhishekkumar009988/pannel.git
# copy all project files and directories into the cloned pannel folder (do not copy data/)
cd pannel
git add .
git commit -m "Add complete owner panel source"
git push origin main
```

Do not copy `data/` or `.env` into the repository. Verify `git status` before pushing.
