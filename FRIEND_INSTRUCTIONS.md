# Friend Instructions

## Download from GitHub
1. Open this GitHub link:
   `https://github.com/VADANEAMRUTA/Agri_Fraud_Detection_Project`
2. Click `Code` and select `Download ZIP`.
3. Extract the ZIP file to a folder on your computer.

## Install and run
### Windows
1. Open PowerShell in the extracted folder.
2. Run:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   copy .env.example .env
   python setup_db.py
   python app.py
   ```
3. Open your browser at `http://127.0.0.1:5000/admin`.
4. Login with:
   - Username: `admin`
   - Password: `admin123`

### Linux / Mac
1. Open Terminal in the extracted folder.
2. Run:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   cp .env.example .env
   python setup_db.py
   python app.py
   ```
3. Open `http://127.0.0.1:5000/admin` in a browser.

## If something doesn’t work
- If dependencies fail: run `python -m pip install -r requirements.txt` again.
- If MySQL connection fails: check `.env` values for `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, and `MYSQL_PASSWORD`.
- If Tesseract is missing: install Tesseract OCR and make sure `tesseract` is on your PATH.
- If the app fails to start: run `python verify_installation.py` and follow the output.

## Extra notes
- `.env` should never be committed.
- The `.pkl` model files are included so fraud detection works immediately.
