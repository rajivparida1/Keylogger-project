# 🔐 Python Keylogger with GUI (Educational Purpose Only)

This is an educational keylogger application built using Python. It includes a secure Tkinter-based GUI, clipboard tracking, screenshot capturing (via shortcut), and remote log viewing through HTTP and WebSocket servers.

> ⚠️ **LEGAL NOTICE**: This software is strictly for **educational and ethical** use only. Do not use it without **explicit permission**. Unauthorized use may violate laws.

---

## 💻 Features

- ✅ GUI built with Tkinter
- ✅ Keylogging with active window tracking
- ✅ Clipboard monitoring
- ✅ Screenshot capture using `Ctrl + Alt + S`
- ✅ Live log streaming via WebSocket
- ✅ HTTP dashboard to view logs remotely
- ✅ Secure login for GUI and remote access
- ✅ Auto-save logs to timestamped files
- ✅ Remote server setup with password protection

---

## 🚀 How to Run

1. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

2. Start the GUI:

   ```bash
   python gui.py
   ```

3. Enter the GUI password (`admin123` by default) and start logging.

---

## 🌐 Remote Monitoring

- Web interface: `http://<your-ip>:8080`
- WebSocket stream: `ws://<your-ip>:8081`
- Default remote access password: `monitor123`

> Ensure both systems are on the **same network**.

---

## 🗃️ Log & Screenshot Files

- Logs are saved as `keylog_<timestamp>.txt`
- Screenshots are saved as `screenshot_<timestamp>.png`

---

## 📁 File Structure

```
project-folder/
├── gui.py
├── keylogger.py
├── requirements.txt
└── README.md
```

---

## 🔒 Disclaimer

This tool is for **ethical hacking practice**, **education**, and **defensive cybersecurity training**. Misuse is not supported or condoned.

---

## 👨‍💻 Author

Rajiv Devendra Parida  
Cybersecurity Enthusiast  
📧 rajivparida12@gmail.com  
📍 Badlapur, India

---
