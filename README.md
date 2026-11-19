# 🛡️ PhishGuard — Real-Time Phishing Website Detection

A professional-grade Chrome Extension + FastAPI backend that detects phishing websites in **real-time** using **Machine Learning (LSVC)** and **Natural Language Processing (DistilBERT)**.

> **Privacy-First**: No browsing history is stored. All analysis is stateless and in-memory only.

---

## 📋 Tech Stack

| Component | Technology |
|-----------|-----------|
| **ML Model** | Linear SVC (91% accuracy on 500K+ URLs) |
| **NLP Model** | DistilBERT (Hugging Face Transformers) |
| **Backend** | FastAPI (Python) |
| **Extension** | Chrome Manifest V3 |
| **Feature Engineering** | 27 URL-based numerical features |
| **Domain Analysis** | SSL certificate + DNS resolution checks |

---

## 🏗️ Project Structure

```
phishing project/
├── backend/                        # FastAPI Backend Server
│   ├── main.py                     # API endpoints
│   ├── config.py                   # Configuration & thresholds
│   ├── train.py                    # Model training script
│   ├── requirements.txt            # Python dependencies
│   ├── models/
│   │   ├── url_features.py         # 27-feature URL extractor
│   │   ├── ml_classifier.py        # LSVC classifier + heuristic fallback
│   │   └── nlp_analyzer.py         # DistilBERT content analyzer
│   ├── utils/
│   │   ├── preprocessor.py         # URL/text cleaning & tokenization
│   │   └── domain_checker.py       # SSL & DNS metadata
│   └── trained_models/             # Saved model files (after training)
├── extension/                      # Chrome Extension (Manifest V3)
│   ├── manifest.json               # Extension manifest
│   ├── background.js               # Service worker
│   ├── content.js                  # Page content extractor
│   ├── popup/
│   │   ├── popup.html              # Extension popup UI
│   │   ├── popup.css               # Dark-themed professional styles
│   │   └── popup.js                # Popup controller logic
│   └── icons/                      # Extension icons (16/48/128)
└── README.md
```

---

## 🚀 Setup & Installation

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Start the API server
python main.py
```

The server starts at `http://127.0.0.1:8000`.

### 2. Train the ML Model (Optional)

The extension works immediately with heuristic analysis. To enable ML-powered detection:

```bash
cd backend
python train.py --dataset path/to/urls.csv
```

**Expected CSV format:**
```csv
url,label
https://google.com,legitimate
http://phish-login.tk/verify,phishing
```

### 3. Install the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. The PhishGuard icon appears in your toolbar

---

## 🔍 How It Works

```
User visits a webpage
        │
        ▼
Chrome Extension captures URL + page content
        │
        ▼
FastAPI Backend receives analysis request
        │
        ├──► URL Feature Extraction (27 features)
        │         │
        │         ▼
        │    ML Classifier (LSVC or Heuristic)
        │
        ├──► Domain Metadata Check (SSL, DNS)
        │
        └──► NLP Content Analysis (DistilBERT / Keyword)
                  │
                  ▼
        Combined risk score → Response to extension
        │
        ▼
Popup displays verdict with confidence score
```

### Detection Layers

1. **URL Feature Analysis** — Extracts 27 numerical features (length, entropy, special characters, suspicious TLDs, keywords, IP detection, etc.)
2. **ML Classification** — Linear SVC model trained on 500K+ URLs (falls back to weighted heuristic scoring when no trained model exists)
3. **Domain Metadata** — SSL certificate validity, DNS resolution, IP-based URL detection
4. **NLP Content Analysis** — DistilBERT transformer (or keyword pattern matching) to detect phishing language in page content

---

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze a URL for phishing |
| `GET`  | `/api/health` | Server health check |
| `POST` | `/api/reload-model` | Hot-reload ML model |

### Example Request

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-login.suspicious-site.tk/verify", "check_domain": true}'
```

---

## 🧪 ML Model Performance (from evaluation)

| Model | Accuracy | Best At |
|-------|----------|---------|
| **LSVC** | **91%** | Best balanced (accuracy + precision + recall) |
| Naive Bayes | 91% | Speed + precision |
| Random Forest | ~90% | General classification |
| Logistic Regression | ~90% | Baseline |
| KNN | ~74% | Not recommended for URL analysis |

---

## 👨‍💻 Authors

- Jayant Kondekar
- Sakshi Jalit
- Ujjwal Jamaiwar
- Mayur Ingole
- Chandan Singh
- Vaishnavi Shukla

**Guide:** Prof. Ashish Trivedi | **Co-Guide:** Prof. Amol Dhankar  
**G H Raisoni University, Amravati** — Department of CSE, Session 2024-25

---

## 📄 License

This project is developed for academic purposes as part of the B.Tech CSE program.
