# Upload Now

## Step 1: Verify required files exist
```bash
cd D:\Social_Media_Fraud_Detection
ls .gitignore .env.example requirements.txt setup_db.py README.md INSTALL.md install.bat install.sh verify_installation.py run.bat run.sh CHECKLIST.md test_installation_locally.md GITHUB_UPLOAD_GUIDE.md FINAL_CHECK_COMMANDS.txt
ls models/fraud_detector_v2.pkl models/vectorizer_v2.pkl
```

## Step 2: Confirm `.gitignore` does not ignore `.pkl`
```bash
grep -n "*.pkl" .gitignore
```

## Step 3: Initialize git if needed
```bash
cd D:\Social_Media_Fraud_Detection
git status || git init
git branch -M main
```

## Step 4: Add all files, including ML model files
```bash
cd D:\Social_Media_Fraud_Detection
git add .
git add -f models/fraud_detector_v2.pkl models/vectorizer_v2.pkl
```

## Step 5: Commit changes
```bash
git commit -m "chore: package AgriGuard for GitHub upload with ML model artifacts"
```

## Step 6: Add GitHub remote and push
```bash
git remote add origin https://github.com/VADANEAMRUTA/Agri_Fraud_Detection_Project.git
git push -u origin main
```

## Step 7: Create GitHub release
```bash
git tag -a v1.0.0 -m "Release AgriGuard v1.0.0"
git push origin v1.0.0
```

## Step 8: Share link with friend
Your repository URL is:

`https://github.com/VADANEAMRUTA/Agri_Fraud_Detection_Project`

If you created a release, share:

`https://github.com/VADANEAMRUTA/Agri_Fraud_Detection_Project/releases/tag/v1.0.0`
