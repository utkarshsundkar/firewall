# Aegis Security Suite 🛡️

Aegis is a high-performance, real-time network security and firewall application designed for deep traffic inspection, DDoS mitigation, and advanced phishing detection. Built for both individual security enthusiasts and enterprise fleet management.

## 🚀 Key Features

### 1. Advanced DDoS Mitigation Hub
*   **Deep Packet Inspection (DPI)**: Utilizes `tcpdump` to capture raw wire data, seeing through the most aggressive low-level floods that skip standard socket tables.
*   **Real-Time Thresholding**: Automatically identifies high-velocity packet bursts (SYN/UDP/ICMP) and triggers instant mitigation.
*   **Autonomous Blocking**: Seamlessly integrates with system firewalls (`pf` on macOS / `netsh` on Windows) to blacklist attacking IPs in milliseconds.
*   **Forensic Reports**: Generates automated mitigation reports for every blocked attack, detailing the threat category, source, and action taken.

### 2. Intelligent Phishing Detection Engine
*   **Heuristic Analysis**: Detects lookalike domains (Homograph attacks), high-risk TLDs (.zip, .top, .click), and keyword stuffing.
*   **Manual Verification**: A dedicated tool for users to verify suspicious links before clicking them.
*   **Live Browser Sync**: An AppleScript-based bridge for Chrome and Safari that provides human-readable domain insights for active traffic.

### 3. WAF & Network Protection
*   **External Traffic Sniffer**: A high-speed, `netstat`-based monitor that visualizes every connection on your machine.
*   **WAF Coverage**: Protects against SQL Injection (SQLi), Cross-Site Scripting (XSS), and Remote Code Execution (RCE) patterns in live traffic.
*   **IP & Website Blocking**: Comprehensive policy enforcement for both individual IPs and entire domains.

### 4. Enterprise Fleet Management
*   **Centralized Control**: A built-in WebSocket server allowing Aegis to act as a hub for managing multiple security endpoints.
*   **System Health Monitoring**: Real-time KPIs for traffic load, threat levels, and firewall status.

## 🛠️ Security Tests Support
Aegis is designed to detect and mitigate the following live attack vectors:
*   **hping3 Floods**: (SYN, UDP, RAW) - Detected via DPI.
*   **Ping Floods**: High-frequency ICMP saturation.
*   **Port Scanning**: Sequential and stealth scanning.
*   **Typosquatting/Phishing**: Malicious lookalike domains.

## 🚦 Getting Started

### Prerequisites
*   Node.js & NPM
*   Electron
*   `tcpdump` (for Deep Packet Inspection)

### Installation
```bash
npm install
```

### Running the App
For standard monitoring:
```bash
npm start
```

For **Deep Packet Inspection (DDoS Mitigation)**, run with administrative privileges:
```bash
sudo npm start
```

## 🏗️ Architecture
*   **Frontend**: Professional White/Slate Theme with CSS Grid layouts and real-time WebSocket updates.
*   **Main Process**: Multi-threaded Node.js engine handling raw system-level utilities (`tcpdump`, `netstat`, `pf`, `lsof`).
*   **Security Layer**: Custom-built `AttackDetector` and `WafManager` for pattern matching and heuristic analysis.

---
**Disclaimer**: This project is for security research and personal protection. Always use raw packet capture responsibly.
