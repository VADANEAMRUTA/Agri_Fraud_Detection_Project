# AgriGuard GitHub Push Checklist

## 1. Verify project packaging files
- [ ] `.gitignore` exists and does not exclude `*.pkl`
- [ ] `.env.example` exists and contains all required variables
- [ ] `requirements.txt` exists with Flask, Flask-Session, mysql-connector-python, python-dotenv, scikit-learn, numpy, pandas, joblib, Pillow, pytesseract, opencv-python
- [ ] `setup_db.py` exists and creates MySQL databases, tables, and default admin user
- [ ] `INSTALL.md` and `README.md` exist
- [ ] `install.bat` and `install.sh` exist
- [ ] `verify_installation.py` exists
- [ ] `run.bat` and `run.sh` exist

## 2. Confirm ML model files are present
- [ ] `models/fraud_detector_v2.pkl` exists
- [ ] `models/vectorizer_v2.pkl` exists
- [ ] `.gitignore` does not ignore `.pkl` files
- [ ] Add model files to git using `git add -f models/fraud_detector_v2.pkl models/vectorizer_v2.pkl` if needed

## 3. Validate code and configuration
- [ ] All paths in project files are relative and not hard-coded to `D:\`
- [ ] `.env.example` includes:
  - `MYSQL_HOST`
  - `MYSQL_PORT`
  - `MYSQL_USER`
  - `MYSQL_PASSWORD`
  - `MYSQL_DB_USERS`
  - `MYSQL_DB_AGRIGUARD`
  - `SECRET_KEY`
  - `ADMIN_SECRET_KEY`
  - `DEBUG`
  - `PORT`
- [ ] `setup_db.py` has clear error handling for MySQL connection failures
- [ ] `verify_installation.py` checks Python, dependencies, MySQL, model files, Tesseract, and env vars

## 4. Local test run
- [ ] Create `.env` from `.env.example`
- [ ] Install dependencies in a virtual environment
- [ ] Run `setup_db.py` successfully
- [ ] Run `python app.py` and confirm the app starts

## 5. GitHub push readiness
- [ ] Repository initialized with `git init` if needed
- [ ] `.gitignore` tracked and correct
- [ ] ML `.pkl` files tracked
- [ ] All files committed with a clear commit message
- [ ] Remote repository configured
- [ ] Release tag created after successful test
