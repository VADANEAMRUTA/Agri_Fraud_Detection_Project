import pytesseract
import cv2

def extract_text(image_path):
    img = cv2.imread(image_path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return pytesseract.image_to_string(gray)
