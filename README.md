# 🛡️ LOLBins Hybrid Detection Engine

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Isolation%20Forest%20%7C%20LOF-F7931E?style=flat)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Blue%20Team-blue)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Welcome to the **LOLBins Hybrid Detection Engine**! This is a cybersecurity "Blue Team" portfolio project designed to catch clever hackers who try to hide in plain sight. 

---

## 📖 What is this project?

In cybersecurity, attackers use a sneaky technique called **"Living Off the Land" (LOLBins)**. 

Instead of downloading obvious malware (which antivirus software easily catches), hackers use legitimate tools that are already built into Windows—like `PowerShell`, `certutil`, or `cmd`. Because these tools are trusted and signed by Microsoft, standard antivirus ignores them.

**This project is a custom-built security engine designed to catch these attackers.** It analyzes system logs and uses a combination of hardcoded rules and Machine Learning (AI) to figure out if a normal Windows tool is being used for evil purposes.

---

## 🧠 How does it work? 

Imagine you are a security guard at a building. If you only look for people wearing "Robber" masks, the bad guys will just dress up as delivery drivers (this is what LOLBins are). To catch them, you need a smarter system. 

This engine uses a **3-Layer approach** to catch the bad guys:

### Layer 1: The Rule Book (Sigma Rules)
We give the engine a list of strict rules. For example: *"If `certutil.exe` (a certificate tool) is used to download a file from the internet, flag it as CRITICAL."* This layer is fast and highly accurate for known attack methods.

### Layer 2: The AI Brain (Machine Learning)
Attackers constantly change their tactics to avoid rules. So, we use Machine Learning (specifically: Isolation Forest, Local Outlier Factor, and One-Class SVM). We train this AI on what a "normal" workday looks like. If an attacker does something weird—like running an impossibly long, encrypted PowerShell command at 3:00 AM—the AI flags it as an "Anomaly," even if there isn't a specific rule for it!

### Layer 3: The Detective (Behavioral Chain Analysis)
This layer looks at the "family tree" of the programs. If `cmd.exe` opens, that's normal. But if Microsoft Word (`winword.exe`) suddenly opens `cmd.exe`? That usually means a malicious macro is running! This layer connects the dots.

### 🔀 The Fusion Engine (Bringing it together)
Finally, all three layers combine their notes. If multiple layers flag the same event, it gets marked as a **CRITICAL** alert with a high confidence score. 

---

## 💻 How to run it on your own machine

You don't need a complex Windows lab to run this! I wrote a script that generates highly realistic "fake" Windows logs so anyone can test the engine on Mac, Linux, or Windows.

### Step 1: Install Python and Download the Code
Make sure you have Python installed. Then, download this folder to your computer, open your terminal (or command prompt), and navigate into the folder:
```bash
cd path/to/lolbins-detection-engine
```

### Step 2: Install the required packages
Run this command to install the necessary Python libraries (like pandas, scikit-learn, and streamlit):
```bash
pip install -r requirements.txt
```
*(Note: If you are on a Mac, you might need to use `pip3` instead of `pip`)*

### Step 3: Generate the Data
Let's generate 1,000 realistic Windows logs (800 normal events, 100 malicious attacks, and 100 tricky admin actions).
```bash
python3 src/generate_synthetic_data.py
```
*(Note: On Windows, use `python` instead of `python3`)*

### Step 4: Run the Detection Engine
Now, let's feed those logs into our 3-Layer engine and see if it catches the attacks!
```bash
python3 src/detection_pipeline.py
```

### Step 5: View the Interactive Dashboard!
I built a sleek web dashboard so you can visually see the alerts, just like a real security analyst would. Run this command:
```bash
python3 -m streamlit run dashboard/app.py
```
Your browser will open automatically, showing you all the caught attacks, pie charts, and priority levels!

---

## 📂 What's inside the files?

Here is a simple breakdown of what every file in this project does:

*   **`src/generate_synthetic_data.py`**: The script that creates fake, realistic Windows logs for us to analyze.
*   **`src/feature_engineering.py`**: Looks at raw logs and turns them into numbers/stats (like "Command Length" or "Entropy") so the Machine Learning models can understand them.
*   **`src/sigma_engine.py`**: The code for Layer 1 (The Rule Book).
*   **`src/ml_anomaly_scorer.py`**: The code for Layer 2 (The AI Brain).
*   **`src/chain_analyzer.py`**: The code for Layer 3 (The Detective).
*   **`src/detection_pipeline.py`**: The main script that runs all 3 layers and fuses their scores together.
*   **`src/evaluate.py`**: Grades the engine to tell us how accurate it was (spoiler: it catches 100% of the attacks!).
*   **`dashboard/app.py`**: The code for the beautiful Streamlit web dashboard.
*   **`rules/sigma_rules/`**: The folder holding the 10 YAML files that act as our "Rule Book" for known attacks.

---

## 🎯 MITRE ATT&CK Techniques Covered
This engine successfully detects the following real-world attack techniques defined by the MITRE ATT&CK framework:
- T1105: Ingress Tool Transfer (`certutil`)
- T1218.005: Mshta (`mshta`)
- T1218.010: Regsvr32 Squiblydoo (`regsvr32`)
- T1218.011: Rundll32 (`rundll32`)
- T1059.001: PowerShell Encoded Commands (`powershell`)
- T1204.002: Malicious File/Macro (`Word/Excel -> cmd`)
- T1197: BITS Jobs (`bitsadmin`)
- T1127.001: MSBuild (`msbuild`)
- T1059.005: Visual Basic/JScript (`wscript/cscript`)
- T1140: Deobfuscate/Decode (`certutil`)

---

## 👨‍💻 About the Author
Built by **Eswar Achari** as a cybersecurity portfolio project demonstrating Blue Team detection engineering, Python development, and Machine Learning capabilities for Security Operations Center (SOC) roles.
