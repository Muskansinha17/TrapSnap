# Trapsnap - Phishing URL Detection Web App
CHECK ON WEBSITE (https://trapsnap.onrender.com)
Startup time can be slow when waking up as App may go to sleep after 15 mins of inactivity. 

**Trapsnap** is a Flask-based web application that detects phishing URLs using a combination of **machine learning** and **pattern-based analysis**. Users can check individual URLs. The system also includes a whitelist of trusted domains and advanced checks for suspicious patterns, domain spoofing, and character substitutions.

---

## **Features**

- ✅ Detects phishing URLs using a trained machine learning model  
- ✅ Pattern-based checks for obvious phishing attempts  
- ✅ Whitelist of trusted domains to reduce false positives  
- ✅ Batch URL checking  
- ✅ Detailed confidence scores and analysis of key features  
- ✅ Simple and responsive web interface using HTML/CSS  

---

## **Tech Stack**

- **Backend:** Python, Flask  
- **Frontend:** HTML, CSS  
- **ML Libraries:** scikit-learn, pandas, numpy  
- **Other Libraries:** tldextract, beautifulsoup4, requests  
- **Deployment:** Render (or any cloud platform)  

---

## **Installation & Setup**

1. **Clone the repository**

```bash
git clone https://github.com/<Muskansinha17>/trapsnap.git
cd trapsnap


2 **Create and activate a virtual environment**
python -m venv venv
# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

3 **install dependencies**
pip install -r requirements.txt

4 **Run the app locally**
python app.py

open your browser at http://localhost:5000

5 **Deployment**
Deployed on Railway or any Python-compatible cloud service.

Requires Procfile with the following content:

web: python app.py

This project is licensed under the MIT License – see LICENSE
for details.

