import re
import pytesseract
from PIL import Image
import os

class ContentValidator:
    """Validate if content is related to agriculture before processing"""
    
    # Agriculture-related keywords (English, Hindi, Marathi)
    AGRICULTURE_KEYWORDS = {
        'english': [
            'agriculture', 'farmer', 'farm', 'crop', 'fertilizer', 'seed', 'pesticide',
            'irrigation', 'harvest', 'tractor', 'soil', 'cultivation', 'yield',
            'subsidy', 'mandi', 'krishi', 'kisan', 'sowing', 'planting',
            'dap', 'urea', 'npk', 'compost', 'manure', 'organic',
            'wheat', 'rice', 'corn', 'maize', 'paddy', 'sugarcane',
            'vegetable', 'fruit', 'horticulture', 'floriculture'
        ],
        'hindi': [
            'कृषि', 'किसान', 'खेत', 'फसल', 'बीज', 'उर्वरक', 'खाद',
            'सिंचाई', 'फसल', 'ट्रैक्टर', 'मृदा', 'खेती', 'उपज',
            'सब्सिडी', 'मंडी', 'बुवाई', 'रोपण', 'कटाई',
            'डीएपी', 'यूरिया', 'एनपीके', 'कम्पोस्ट', 'खाद',
            'गेहूं', 'चावल', 'मक्का', 'गन्ना', 'सब्जी', 'फल'
        ],
        'marathi': [
            'शेती', 'शेतकरी', 'पीक', 'बियाणे', 'खत', 'सिंचन',
            'कापणी', 'ट्रॅक्टर', 'माती', 'लागवड', 'उत्पन्न',
            'सब्सिडी', 'मंडी', 'पेरणी', 'रोपण', 'कापणी',
            'गहू', 'तांदूळ', 'मका', 'ऊस', 'भाजीपाला', 'फळ'
        ]
    }
    
    # Common non-agriculture content indicators
    NON_AGRI_INDICATORS = [
        'copyright', 'microsoft', 'google', 'chrome', 'firefox', 'facebook',
        'instagram', 'whatsapp', 'twitter', 'youtube', 'zoom', 'meeting',
        'antivirus', 'desktop', 'windows', 'linux', 'macos', 'android',
        'ios', 'code', 'programming', 'python', 'java', 'javascript',
        'database', 'ide', 'editor', 'browser', 'email', 'chat',
        'document', 'pdf', 'word', 'excel', 'powerpoint', 'presentation'
    ]
    
    @staticmethod
    def is_agriculture_related(text, min_keywords=3):
        """
        Check if text contains enough agriculture-related keywords
        Returns: (is_agriculture, confidence_percentage, detected_keywords)
        """
        text_lower = text.lower()
        
        # Count agriculture keywords
        agri_count = 0
        detected_keywords = []
        
        for lang, keywords in ContentValidator.AGRICULTURE_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    agri_count += 1
                    detected_keywords.append(keyword)
        
        # Count non-agriculture indicators
        non_agri_count = 0
        for indicator in ContentValidator.NON_AGRI_INDICATORS:
            if indicator in text_lower:
                non_agri_count += 1
        
        # Decision logic
        if agri_count >= min_keywords and non_agri_count < 2:
            confidence = min(100, (agri_count * 20))  # Up to 100%
            return True, confidence, detected_keywords
        elif agri_count == 0 and non_agri_count > 3:
            return False, 10, []  # Clearly non-agriculture
        elif agri_count > 0:
            # Some agriculture keywords found
            confidence = min(80, (agri_count * 15))
            return True, confidence, detected_keywords
        else:
            # Insufficient agriculture content
            return False, 30, []
    
    @staticmethod
    def validate_image(image_path):
        """
        Validate if image contains agriculture-related content
        Returns: (is_valid, message, extracted_text)
        """
        try:
            # Extract text from image
            text = ContentValidator.extract_text(image_path)
            
            if not text or len(text.strip()) < 20:
                return False, "Image doesn't contain enough text for analysis.", text
            
            # Check if agriculture-related
            is_agri, confidence, keywords = ContentValidator.is_agriculture_related(text)
            
            if is_agri:
                message = f"✅ Agriculture content detected ({confidence}% confidence)"
                if keywords:
                    message += f"\nKeywords found: {', '.join(keywords[:5])}"
                return True, message, text
            else:
                message = "❌ This image doesn't appear to contain agricultural content."
                message += "\nPlease upload images related to: fertilizers, seeds, crops, farming, etc."
                return False, message, text
                
        except Exception as e:
            return False, f"Error validating image: {str(e)}", ""
    
    @staticmethod
    def extract_text(image_path):
        """Extract text from image with basic preprocessing"""
        try:
            # Simple text extraction
            text = pytesseract.image_to_string(Image.open(image_path))
            return text
        except:
            return ""