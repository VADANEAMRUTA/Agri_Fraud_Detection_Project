// script.js - Professional Interactions

document.addEventListener('DOMContentLoaded', function() {
    
    // ========== LOGOUT CONFIRMATION ==========
    const logoutBtn = document.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
            }
        });
    }
    
    // ========== TAB SYSTEM FOR DETECT PAGE ==========
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            // Update active tab button
            tabBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Show active tab content
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tabId + '-tab') {
                    content.classList.add('active');
                }
            });
        });
    });
    
    // ========== FILE UPLOAD PREVIEW ==========
    const fileInput = document.getElementById('image-upload');
    const uploadArea = document.querySelector('.upload-area');
    const previewText = document.getElementById('preview-text');
    
    if (fileInput && uploadArea) {
        // Click upload area to trigger file input
        uploadArea.addEventListener('click', () => fileInput.click());
        
        // File selection handler
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                if (previewText) {
                    previewText.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
                    previewText.style.color = '#2e7d32';
                }
                
                // Preview image if it's an image file
                if (file.type.startsWith('image/')) {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        // Remove existing preview
                        const oldPreview = uploadArea.querySelector('.image-preview');
                        if (oldPreview) oldPreview.remove();
                        
                        // Create new preview
                        const imgPreview = document.createElement('img');
                        imgPreview.src = e.target.result;
                        imgPreview.className = 'image-preview';
                        imgPreview.style.maxWidth = '200px';
                        imgPreview.style.maxHeight = '200px';
                        imgPreview.style.marginTop = '1rem';
                        imgPreview.style.borderRadius = '8px';
                        uploadArea.appendChild(imgPreview);
                    };
                    reader.readAsDataURL(file);
                }
            }
        });
        
        // Drag and drop support
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, unhighlight, false);
        });
        
        function highlight() {
            uploadArea.style.borderColor = '#2e7d32';
            uploadArea.style.background = 'rgba(46, 125, 50, 0.1)';
        }
        
        function unhighlight() {
            uploadArea.style.borderColor = '#cbd5e1';
            uploadArea.style.background = '#f8fafc';
        }
        
        uploadArea.addEventListener('drop', function(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            fileInput.files = files;
            fileInput.dispatchEvent(new Event('change'));
        });
    }
    
    // ========== FORM VALIDATION ==========
    // TEMPORARY: Disable all validation to test form submission
console.log('Form validation disabled for testing');

// Remove any existing form validation
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        console.log('Form submitting:', this.id);
        
        // Only for detect form
        if (this.id === 'detectForm') {
            const activeTab = document.querySelector('.tab-content.active');
            console.log('Active tab:', activeTab ? activeTab.id : 'none');
            
            // Check what input we have
            if (activeTab.id === 'link-tab') {
                const linkInput = document.querySelector('#link-tab input[type="url"]');
                console.log('Link input value:', linkInput ? linkInput.value : 'no input');
                
                if (linkInput && !linkInput.value.trim()) {
                    e.preventDefault();
                    alert('Please enter a website URL');
                    linkInput.focus();
                    return;
                }
            }
            
            console.log('Form will submit...');
        }
    }, true); // Use capture phase to run before other handlers
});
    
    // ========== TOAST NOTIFICATIONS ==========
    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 2rem;
            background: ${type === 'error' ? '#ef4444' : type === 'success' ? '#10b981' : '#3b82f6'};
            color: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 9999;
            animation: slideInRight 0.3s ease;
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
    
    // ========== RESULT COLOR CODING ==========
    const resultElement = document.querySelector('.result-card');
    if (resultElement) {
        const resultText = resultElement.textContent.toLowerCase();
        if (resultText.includes('genuine') || resultText.includes('safe')) {
            resultElement.classList.add('safe');
        } else if (resultText.includes('fraud')) {
            resultElement.classList.add('fraud');
        } else if (resultText.includes('suspicious') || resultText.includes('no content')) {
            resultElement.classList.add('suspicious');
        }
    }
    
    // ========== AUTO-HIDE SUCCESS MESSAGES ==========
    const successMessages = document.querySelectorAll('.alert-success');
    successMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            setTimeout(() => msg.remove(), 300);
        }, 5000);
    });
});

// ========== ANIMATIONS ==========
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .fade-in {
        animation: fadeIn 0.5s ease;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);
// Update the detectFraud function
function detectFraud() {
    const text = document.getElementById('textInput').value;
    
    if (!text.trim()) {
        alert('Please enter text to analyze');
        return;
    }
    
    // Show loading
    document.getElementById('results').innerHTML = `
        <div class="text-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Analyzing with AI model...</p>
        </div>
    `;
    
    // Make AJAX request
    fetch('/check_fraud', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'text': text
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'error') {
            document.getElementById('results').innerHTML = `
                <div class="alert alert-danger">
                    ${data.message}
                </div>
            `;
            return;
        }
        
        // Display main result
        let resultClass = 'warning';
        if (data.result === 'genuine') resultClass = 'success';
        if (data.result === 'fraud') resultClass = 'danger';
        
        document.getElementById('results').innerHTML = `
            <div class="alert alert-${resultClass}">
                <h5>${data.message}</h5>
                <p class="mb-1">Confidence: ${data.confidence.toFixed(1)}%</p>
                <div class="progress mt-2" style="height: 20px;">
                    <div class="progress-bar bg-${resultClass}" 
                         style="width: ${data.confidence}%">
                        ${data.confidence.toFixed(1)}%
                    </div>
                </div>
                <p class="mt-2 small">Method: ${data.method}</p>
            </div>
        `;
        
        // Show enhanced results if available
        if (data.detailed_analysis) {
            displayEnhancedAnalysis(data);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('results').innerHTML = `
            <div class="alert alert-danger">
                Error analyzing text. Please try again.
            </div>
        `;
    });
}

function displayEnhancedAnalysis(data) {
    // Show enhanced results section
    document.getElementById('enhancedResults').style.display = 'block';
    
    const analysis = data.detailed_analysis;
    
    // Update ML prediction
    const mlLabel = document.getElementById('mlLabel');
    mlLabel.textContent = analysis.ml_prediction;
    mlLabel.className = `badge ${getLabelClass(analysis.ml_prediction)} me-2`;
    document.getElementById('mlConfidence').textContent = 
        `Confidence: ${analysis.ml_confidence}%`;
    document.getElementById('mlBar').style.width = `${analysis.ml_confidence}%`;
    
    // Update rule-based score
    document.getElementById('ruleScore').textContent = analysis.rule_based_score;
    document.getElementById('ruleBar').style.width = `${analysis.rule_based_score}%`;
    
    // Update keyword analysis
    document.getElementById('agriTerms').textContent = 
        analysis.keyword_analysis.agriculture_terms;
    document.getElementById('fraudIndicators').textContent = 
        analysis.keyword_analysis.fraud_indicators;
    document.getElementById('brandMentions').textContent = 
        analysis.keyword_analysis.brand_mentions;
    
    // Show detailed analysis
    document.getElementById('detailedAnalysis').style.display = 'block';
    
    // Show suspicious elements if any
    const elements = analysis.suspicious_elements;
    let hasSuspicious = false;
    let elementsHtml = '';
    
    if (elements.urls && elements.urls.length > 0) {
        hasSuspicious = true;
        elementsHtml += `<li>URLs found: ${elements.urls.length}</li>`;
    }
    if (elements.phones && elements.phones.length > 0) {
        hasSuspicious = true;
        elementsHtml += `<li>Phone numbers: ${elements.phones.length}</li>`;
    }
    if (elements.emails && elements.emails.length > 0) {
        hasSuspicious = true;
        elementsHtml += `<li>Email addresses: ${elements.emails.length}</li>`;
    }
    
    if (hasSuspicious) {
        document.getElementById('suspiciousElements').style.display = 'block';
        document.getElementById('elementsList').innerHTML = elementsHtml;
    }
    
    // Show recommendation
    const recAlert = document.getElementById('recommendationAlert');
    recAlert.textContent = data.recommendation;
    recAlert.className = `alert alert-${getLabelClass(data.result)}`;
    
    // Show feedback section
    document.getElementById('feedbackSection').style.display = 'block';
}

function getLabelClass(label) {
    switch(label) {
        case 'genuine': return 'success';
        case 'suspicious': return 'warning';
        case 'fraud': return 'danger';
        default: return 'secondary';
    }
}

function submitFeedback(accuracy) {
    const text = document.getElementById('textInput').value;
    const actualLabel = accuracy === 'correct' ? 
        document.getElementById('mlLabel').textContent : 
        prompt('
            