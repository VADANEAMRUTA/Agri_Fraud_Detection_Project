# Save as enhanced_detector.py in your project root
import re
import numpy as np
from ml_model import ml_model

class EnhancedFraudDetector:
    def __init__(self):
        self.ml_model = ml_model
        self.initialize_keyword_lists()
        
        # Load ML model on startup
        if not self.ml_model.is_trained:
            self.ml_model.load_model()
            if not self.ml_model.is_trained:
                print("Training initial ML model...")
                self.ml_model.train()
    
    def initialize_keyword_lists(self):
        """Initialize comprehensive keyword lists"""
        self.genuine_brands = [
            'green gate', 'watermarket', 'greengold', 'clarus', 'mahindra',
            'tata', 'bayer', 'syngenta', 'dupont', 'monsanto', 'cipla',
            'upl', 'coromandel', 'nagarjuna', 'sinochem', 'adama',
            'basf', 'dow', 'sumitomo', 'nu farm'
        ]
        
        self.agri_keywords = [
            # English
            'seed', 'fertilizer', 'pesticide', 'insecticide', 'herbicide',
            'crop', 'harvest', 'yield', 'irrigation', 'drip', 'sprinkler',
            'tractor', 'plough', 'harvester', 'cultivator', 'soil',
            'organic', 'compost', 'manure', 'mulch', 'greenhouse',
            'nursery', 'sapling', 'grafting', 'pruning', 'spray',
            'weed', 'pest', 'disease', 'fungus', 'bacteria',
            'agriculture', 'farming', 'farmer', 'farmland', 'plantation',
            'horticulture', 'floriculture', 'arboriculture', 'sericulture',
            'apiculture', 'aquaculture', 'hydroponics', 'aeroponics',
            
            # Hindi
            'बीज', 'खाद', 'उर्वरक', 'कीटनाशक', 'फसल',
            'सिंचाई', 'ट्रैक्टर', 'मिट्टी', 'जैविक', 'कम्पोस्ट',
            'खेती', 'किसान', 'खेत', 'बागवानी',
            
            # Marathi
            'बी', 'खत', 'कीटकनाशक', 'पीक', 'सिंचन',
            'ट्रॅक्टर', 'माती', 'सेंद्रिय', 'शेती', 'शेतकरी'
        ]
        
        self.fraud_keywords = [
            # English fraud indicators
            'free', 'guaranteed', '100%', 'profit', 'cash',
            'prize', 'lottery', 'winner', 'urgent', 'limited',
            'offer', 'secret', 'miracle', 'magic', 'overnight',
            'double', 'triple', 'instant', 'quick', 'easy',
            'risk-free', 'no investment', 'earn money', 'get rich',
            'exclusive', 'selected', 'lucky', 'congratulations',
            'claim now', 'call now', 'whatsapp', 'contact',
            'scheme', 'scam', 'fraud', 'fake', 'counterfeit',
            
            # Hindi fraud indicators
            'मुफ्त', 'गारंटी', 'लाभ', 'नकद', 'पुरस्कार',
            'लॉटरी', 'विजेता', 'तत्काल', 'सीमित', 'ऑफर',
            'रहस्य', 'चमत्कार', 'जादू', 'रातोंरात', 'दोगुना',
            'त्वरित', 'आसान', 'जोखिम मुक्त', 'निवेश नहीं',
            'पैसे कमाएँ', 'अमीर बनें', 'विशेष', 'चयनित',
            'भाग्यशाली', 'बधाई', 'अभी दावा करें', 'अभी कॉल करें',
            
            # Marathi fraud indicators
            'मोफत', 'हमी', 'नफा', 'रोख', 'बक्षीस',
            'लॉटरी', 'विजेता', 'तातडीचे', 'मर्यादित', 'ऑफर',
            'गुपित', 'चमत्कार', 'जादू', 'रातोरात', 'दुप्पट',
            'त्वरित', 'सोपे', 'धोका मुक्त', 'गुंतवणूक नाही',
            'पैसे कमवा', 'श्रीमंत व्हा', 'विशेष', 'निवडलेले',
            'नशीबवान', 'अभिनंदन', 'आत्ताच दावा करा', 'आत्ताच कॉल करा'
        ]
    
    def extract_suspicious_elements(self, text):
        """Extract URLs, phone numbers, and emails from text"""
        elements = {
            'urls': re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text),
            'phones': re.findall(r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]', text),
            'emails': re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text),
            'whatsapp_links': re.findall(r'wa\.me/[\w\+]+|whatsapp\.com/[\w\+]+', text, re.IGNORECASE)
        }
        return elements
    
    def calculate_rule_based_score(self, text):
        """Calculate fraud score using rule-based system"""
        text_lower = text.lower()
        score = 50  # Start with neutral score
        
        # Check for genuine brands
        for brand in self.genuine_brands:
            if brand in text_lower:
                score += 20
                break
        
        # Check agriculture keywords
        agri_count = sum(1 for keyword in self.agri_keywords if keyword in text_lower)
        score += min(agri_count * 5, 30)  # Max 30 points for agriculture terms
        
        # Check fraud keywords
        fraud_count = sum(1 for keyword in self.fraud_keywords if keyword in text_lower)
        score -= min(fraud_count * 10, 40)  # Max -40 points for fraud terms
        
        # Check for suspicious elements
        elements = self.extract_suspicious_elements(text)
        if elements['urls']:
            score -= 15
        if elements['phones']:
            score -= 10
        if elements['emails']:
            score -= 5
        if elements['whatsapp_links']:
            score -= 20
        
        # Normalize score to 0-100
        score = max(0, min(100, score))
        
        return score
    
    def enhanced_detect(self, text):
        """Enhanced detection combining ML and rule-based systems"""
        if not text or len(text.strip()) < 10:
            return {
                'status': 'error',
                'message': 'Text too short for analysis',
                'confidence': 0,
                'method': 'none'
            }
        
        # Get ML prediction
        ml_label, ml_confidences = self.ml_model.predict(text)
        
        # Get rule-based score
        rule_score = self.calculate_rule_based_score(text)
        
        # Extract suspicious elements
        suspicious_elements = self.extract_suspicious_elements(text)
        
        # Combine results (ensemble approach)
        final_result = self.combine_predictions(ml_label, ml_confidences, rule_score)
        
        # Calculate confidence
        ml_confidence = ml_confidences.get(ml_label, 0.5) * 100
        rule_confidence = abs(rule_score - 50) * 2  # Convert to 0-100
        
        # Weighted confidence (60% ML, 40% rules)
        final_confidence = (ml_confidence * 0.6) + (rule_confidence * 0.4)
        
        # Prepare detailed analysis
        analysis = {
            'ml_prediction': ml_label,
            'ml_confidence': round(ml_confidence, 2),
            'rule_based_score': rule_score,
            'rule_confidence': round(rule_confidence, 2),
            'final_confidence': round(final_confidence, 2),
            'suspicious_elements': suspicious_elements,
            'keyword_analysis': {
                'agriculture_terms': sum(1 for kw in self.agri_keywords if kw in text.lower()),
                'fraud_indicators': sum(1 for kw in self.fraud_keywords if kw in text.lower()),
                'brand_mentions': sum(1 for brand in self.genuine_brands if brand in text.lower())
            }
        }
        
        return {
            'status': 'success',
            'result': final_result['label'],
            'confidence': final_confidence,
            'message': final_result['message'],
            'detailed_analysis': analysis,
            'recommendation': self.get_recommendation(final_result['label'], final_confidence),
            'method': 'hybrid_ml_rules'
        }
    
    def combine_predictions(self, ml_label, ml_confidences, rule_score):
        """Combine ML and rule-based predictions"""
        # Convert rule score to label
        if rule_score >= 70:
            rule_label = 'genuine'
        elif rule_score <= 30:
            rule_label = 'fraud'
        else:
            rule_label = 'suspicious'
        
        # If both agree, use that label
        if ml_label == rule_label:
            final_label = ml_label
            message = self.get_message_for_label(final_label, 'both_methods_agree')
        else:
            # If ML confidence is high, trust ML more
            ml_confidence = ml_confidences.get(ml_label, 0)
            if ml_confidence > 0.7:
                final_label = ml_label
                message = f"ML model prediction (high confidence: {ml_confidence:.0%})"
            else:
                # Otherwise, use the more conservative (suspicious) label
                labels = [ml_label, rule_label]
                if 'fraud' in labels:
                    final_label = 'fraud'
                elif 'suspicious' in labels:
                    final_label = 'suspicious'
                else:
                    final_label = 'genuine'
                message = "Conservative prediction (methods disagree)"
        
        return {
            'label': final_label,
            'message': message
        }
    
    def get_message_for_label(self, label, context='default'):
        """Get appropriate message for the detection label"""
        messages = {
            'genuine': {
                'default': "✅ Likely Genuine - Appears to be legitimate agriculture content",
                'both_methods_agree': "✅ Both ML and rule-based systems agree: Genuine content",
                'high_confidence': "✅ High Confidence: Genuine agriculture advertisement"
            },
            'suspicious': {
                'default': "⚠️ Needs Review - Some suspicious elements detected",
                'both_methods_agree': "⚠️ Both systems flag this as suspicious",
                'high_confidence': "⚠️ Exercise Caution: Multiple fraud indicators detected"
            },
            'fraud': {
                'default': "🚨 High Fraud Risk - Strong indicators of scam/fraud",
                'both_methods_agree': "🚨 ALERT: Both ML and rules indicate fraud",
                'high_confidence': "🚨 CRITICAL: Very high probability of fraud"
            }
        }
        return messages.get(label, {}).get(context, "Analysis complete")
    
    def get_recommendation(self, label, confidence):
        """Get actionable recommendation based on detection result"""
        recommendations = {
            'genuine': {
                'high': "Proceed with confidence. This appears to be a legitimate agriculture advertisement.",
                'medium': "Likely safe, but verify contact details before proceeding.",
                'low': "Exercise normal caution as with any business transaction."
            },
            'suspicious': {
                'high': "Avoid engagement. Verify through official channels before proceeding.",
                'medium': "Request more information and verify credentials.",
                'low': "Proceed with caution and verify all claims independently."
            },
            'fraud': {
                'high': "DO NOT ENGAGE. Report this advertisement to authorities immediately.",
                'medium': "Highly likely to be fraudulent. Avoid any contact or payment.",
                'low': "Strong indicators of fraud. Seek alternatives from verified sources."
            }
        }
        
        if confidence >= 80:
            confidence_level = 'high'
        elif confidence >= 60:
            confidence_level = 'medium'
        else:
            confidence_level = 'low'
        
        return recommendations.get(label, {}).get(confidence_level, "Use your best judgment.")

# Global instance
enhanced_detector = EnhancedFraudDetector()