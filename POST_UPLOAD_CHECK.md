# Post Upload Check

## 1. Verify GitHub website contents
1. Open:
   `https://github.com/VADANEAMRUTA/Agri_Fraud_Detection_Project`
2. Confirm the repository contains:
   - `.gitignore`
   - `.env.example`
   - `requirements.txt`
   - `setup_db.py`
   - `README.md`
   - `INSTALL.md`
   - `verify_installation.py`
   - `run.bat`
   - `run.sh`
   - `CHECKLIST.md`
   - `FRIEND_INSTRUCTIONS.md`
   - `UPLOAD_NOW.md`
   - `POST_UPLOAD_CHECK.md`
   - `GITHUB_UPLOAD_GUIDE.md`
3. Confirm `models/fraud_detector_v2.pkl` and `models/vectorizer_v2.pkl` are visible in the GitHub file browser.

## 2. Verify release/tag
- Open the Releases page:
  `https://github.com/VADANEAMRUTA/Agri_Fraud_Detection_Project/releases`
- Confirm tag `v1.0.0` exists.
- Confirm release notes are present.

## 3. Test download and install in a different folder
1. Download the repository ZIP from GitHub.
2. Extract to a new folder.
3. Follow `FRIEND_INSTRUCTIONS.md` to install and run.
4. Confirm the app starts and the admin login works.

## 4. Confirm model files are inside the downloaded repo
- After extraction, verify:
  - `models/fraud_detector_v2.pkl`
  - `models/vectorizer_v2.pkl`
- If missing, the push failed to include them.

## 5. Common issues and fixes
- `.pkl` missing on GitHub: run `git add -f models/*.pkl` and push again.
- `.env` missing: copy `.env.example` to `.env`.
- Database setup failed: rerun `python setup_db.py`.
- App startup fail: inspect `app.py` output and run `python verify_installation.py`.
