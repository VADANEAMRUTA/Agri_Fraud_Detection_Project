import os
from PIL import Image
import pytesseract
import pandas as pd

# Check Tesseract path (Windows only)
# Uncomment and set if needed:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# List to store extracted data
data = []

# Function to extract text from images in a folder
def extract_text_from_folder(folder_path, label):
    for file in os.listdir(folder_path):
        if file.endswith(".png") or file.endswith(".jpg"):
            path = os.path.join(folder_path, file)
            try:
                # Extract text using pytesseract
                text = pytesseract.image_to_string(Image.open(path), lang='eng')
                text = text.strip()
                if text:  # Only add if text is not empty
                    data.append([text, label])
            except Exception as e:
                print(f"Error reading {file}: {e}")

# Extract text from fraud images
extract_text_from_folder("dataset/fraud", "Fraud")

# Extract text from genuine images
extract_text_from_folder("dataset/genuine", "Genuine")

# Save to CSV
df = pd.DataFrame(data, columns=["text", "label"])
csv_path = "dataset/data.csv"
df.to_csv(csv_path, index=False)

print(f"✅ OCR completed. CSV saved at: {csv_path}")
print(f"Total records: {len(df)}")
