@echo off
echo Installing Tesseract OCR on Windows...
echo.

echo Step 1: Please manually install Tesseract OCR:
echo 1. Download from: https://github.com/UB-Mannheim/tesseract/wiki
echo 2. Run the installer
echo 3. Install to: C:\Program Files\Tesseract-OCR
echo 4. Select English, Hindi, Marathi languages
echo 5. Check "Add to PATH"
echo.
pause

echo Step 2: Installing Python packages...
pip install Pillow pytesseract opencv-python numpy
echo.
echo Installation complete!
pause