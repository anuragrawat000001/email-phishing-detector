# Phishing Email Detection Using Machine Learning

This project detects phishing emails using NLP and Machine Learning.

**Author:** Anurag Rawat

---

## 📌 Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Results](#results)
- [Examples](#examples)
- [License](#license)

---

## 📖 Project Overview
This system classifies emails as:
- ⚠️ Phishing
- ✅ Legitimate

---

## 🚀 Features
- Rule-based keyword detection  
- TF-IDF vectorization  
- ML classification  
- Fast execution  

---

## 🛠 Technologies Used
- Python  
- Pandas  
- NumPy  
- Scikit-learn  

---

## 📂 Project Structure

    ## 📂 Project Structure

    phishing-detector/
    ├── data/                # Dataset folder
    ├── .gitignore           # Git ignored files
    ├── LICENSE              # License file
    ├── README.md            # Documentation
    ├── demo.py              # Demo script to test model
    ├── detector.py          # Phishing detection logic
    ├── train.py             # Model training script
    └── requirements.txt     # Dependencies

---

## ⚙️ Installation

    git clone https://github.com/yourusername/phishing-detector.git
    cd phishing-detector
    pip install -r requirements.txt

---

## ▶️ Usage

    python train.py
    python app.py

---

## 📊 Results

| Metric     | Value |
|------------|------|
| Accuracy   | 96%  |
| Precision  | 95%  |
| Recall     | 94%  |

---

## 📧 Examples

**Phishing:**
Subject: Urgent! Verify your account now  
→ ⚠️ Phishing  

**Safe:**
Subject: Meeting at 3 PM  
→ ✅ Safe  

---

## 📜 License
All Rights Reserved. Unauthorized use is prohibited.
