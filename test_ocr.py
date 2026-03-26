from PIL import Image, ImageEnhance
import pytesseract

def test_image_ocr(image_path):
    print(f"Testing OCR on: {image_path}")
    
    # Open image
    img = Image.open(image_path)
    print(f"Original size: {img.size}")
    print(f"Mode: {img.mode}")
    
    # Convert to grayscale
    gray = img.convert('L')
    
    # Increase contrast
    enhancer = ImageEnhance.Contrast(gray)
    enhanced = enhancer.enhance(2.0)
    
    # Save processed image
    enhanced.save('test_processed.png')
    
    # Try different PSM modes
    psm_modes = [3, 6, 7, 8, 11]
    
    for psm in psm_modes:
        config = f'--oem 3 --psm {psm} -l eng'
        text = pytesseract.image_to_string(enhanced, config=config)
        print(f"\nPSM {psm}:")
        print(f"  Text: '{text.strip()}'")
        print(f"  Length: {len(text.strip())}")

# Run test
test_image_ocr('path_to_your_image.png')