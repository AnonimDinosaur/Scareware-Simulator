# 🚨 Scareware Simulator – Fake Virus Alert Educational Tool

> This is an educational simulation of scam-based social engineering attacks that use fake virus alerts and urgency tactics to manipulate users.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Demo](https://img.shields.io/badge/Mode-DEMO-red)

---

## ⚠️ About This Project

This tool mimics a **fake "virus scanner" scareware popup**, similar to what scammers use in real-world frauds.  
Its purpose is **to educate people on how social engineering works** in the context of tech support scams.

---

## 🎯 Educational Goals

- Show how fear-based UIs manipulate people.
- Simulate fake scanning, virus alerts, popups, and fake countdowns.
- Raise awareness about common scam tactics like:
  - 🚨 "Call tech support now!"
  - 🕒 "System will be locked in 5 minutes"
  - 🧨 "Remote access detected from Russia"

---

## 🧪 Demo Mode (Default)

Run this tool normally and it will simulate a full scareware attack:

```bash
python detector_svchost.py
```
You’ll see:

Fake file scanning progress bar

Simulated virus names and file locations

Fake IP addresses from malicious sources

Alarming popup windows

Countdown that threatens to lock your system

Sound alerts (Windows only)

🔊 Sounds and popups are for demonstration only.

🛠️ Normal Mode (Legitimate svchost Detector)
You can also run this tool in normal mode, where it acts as a real svchost.exe process detector:

```bash
python detector_svchost.py --normal
```
Scans running processes.

Identifies fake svchost.exe outside of legitimate system folders.

Useful to demonstrate basic malware detection.

📜 Legal & Ethical Notice
This project is:

🔒 Safe: No real malware is involved.

🎓 Educational: Created for awareness and demonstration.

❌ NOT for misuse: Don’t run this on someone’s computer without their knowledge.

⚠️ DISCLAIMER
This project simulates scam behaviors to educate users.
The author is not responsible for misuse or harm caused by unauthorized use.
Always use responsibly and ethically.

📂 File List
```bash
detector_svchost.py     → Main Python file (demo + real detector)
README.md               → This file
LICENSE                 → MIT License
```
🧠 Topics
Social Engineering

Scareware

Cybersecurity Awareness

Phishing Simulation

Red Team Education

⭐ Like this project?
If you found this project interesting or useful:

Star it ⭐

Share it 🔁

Learn from it 🎓

Stay safe online! 🛡️



## 📄 LICENSE (fitxer `LICENSE`)

```text
MIT License

Copyright (c) 2025 Oriol

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     
copies of the Software, and to permit persons to whom the Software is         
furnished to do so, subject to the following conditions:                      

The above copyright notice and this permission notice shall be included in    
all copies or substantial portions of the Software.                           

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR   
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,     
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER       
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING      
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
IN THE SOFTWARE.
```
