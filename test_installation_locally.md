# Test Installation Locally

## 1. Prepare a clean environment
- Open a fresh terminal.
- Navigate to the project folder: `cd D:\Social_Media_Fraud_Detection`
- Confirm `.env` is created from `.env.example`.

## 2. Create and activate a virtual environment
- Windows:
  ```bat
  python -m venv venv
  venv\Scripts\activate
  ```
- Linux/Mac:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

## 3. Install dependencies
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 4. Verify environment variables
- Confirm `.env` contains:
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

## 5. Run database setup
```bash
python setup_db.py
```
- Confirm it creates both databases.
- Confirm default admin user is created.

## 6. Confirm ML model files exist
- `models/fraud_detector_v2.pkl`
- `models/vectorizer_v2.pkl`

## 7. Run the app
```bash
python app.py
```
- Confirm the web app starts without fatal errors.

## 8. Quick app smoke test
- Open browser at `http://127.0.0.1:5000/admin`
- Login with default credentials:
  - `admin` / `admin123`
- Verify dashboard loads and user/fraud data sections render.

## 9. Run verification script
```bash
python verify_installation.py
```
- Confirm all checks pass.
