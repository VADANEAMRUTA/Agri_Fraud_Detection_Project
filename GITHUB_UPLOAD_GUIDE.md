# GitHub Upload Guide for AgriGuard

## 1. Initialize Git repository (if not already)
```bash
cd D:\Social_Media_Fraud_Detection
git init
```

## 2. Check `.gitignore`
- Confirm `.gitignore` exists.
- Confirm it does not exclude `*.pkl` files.

## 3. Add all files and force-add models
```bash
git add .
git add -f models/fraud_detector_v2.pkl models/vectorizer_v2.pkl
```

## 4. Commit changes
```bash
git commit -m "chore: add GitHub packaging files, installation guides, and include ML model artifacts"
```

## 5. Create GitHub repository
### Option A: GitHub CLI
```bash
gh repo create AgriGuard --public --source=. --remote=origin --push
```

### Option B: GitHub website
- Create a new repository named `AgriGuard`.
- Follow the instructions to add the remote.

## 6. Push to GitHub
```bash
git branch -M main
git remote add origin https://github.com/<your-username>/AgriGuard.git
git push -u origin main
```

## 7. Create a release/tag
### Create annotated tag
```bash
git tag -a v1.0.0 -m "Release AgriGuard v1.0.0"
```

### Push tag
```bash
git push origin v1.0.0
```

### Or use GitHub CLI
```bash
gh release create v1.0.0 --title "AgriGuard v1.0.0" --notes "Initial stable release with fraud detection models included."
```

## 8. Confirm release assets
- Verify the GitHub release page shows tag `v1.0.0`.
- Confirm release notes are visible.
- Confirm repository files include `models/fraud_detector_v2.pkl` and `models/vectorizer_v2.pkl`.

## 9. Important notes
- `.gitignore` must not ignore `.pkl` files.
- Use `git add -f` if model files are skipped by git.
- Keep `.env` local and never commit it.
