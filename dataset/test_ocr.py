import pytesseract
from PIL import Image

# Path to one of your fraud images
img_path = "dataset/fraud/fraud_1.png"

# Extract text using Tesseract OCR
text = pytesseract.image_to_string(Image.open(img_path))

print("Extracted Text:\n")
print(text)
