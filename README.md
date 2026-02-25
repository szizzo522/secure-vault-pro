# SecureVault — Password Vault (SQLite + Fernet Encryption)

SecureVault is a desktop password manager built using **Python**, **Tkinter**, **SQLite**, and **Fernet encryption** from the `cryptography` library.

The application securely stores credentials locally using encryption derived from a master password.

> This project was developed as a **Capstone Project** for the Programming program at **Palm Beach State College** and is intended for educational and portfolio purposes.  
> It has not undergone professional security auditing.

---
## Demo

**Check out my other projects on [YouTube](https://www.youtube.com/@Research-Farm/videos)**

[![Watch the Demo](https://img.youtube.com/vi/JtksPubIFsk/0.jpg)](https://www.youtube.com/watch?v=JtksPubIFsk)

---

## Features

- Master password authentication
- Encrypted credential storage
- Local SQLite database
- Secure password generation
- Clipboard password copy
- Recovery key + QR code backup
- Cross-platform desktop GUI

---

## Quick Setup
### 1. Install Python

Download and install Python 3:

https://www.python.org/downloads/

During installation, enable **Add Python to PATH** (Windows).

Verify installation:

```bash
python --version
```
(macOS/Linux may use python3)

### 2. Download the Project

Using Git:
```bash
git clone https://github.com/szizzo522/secure-vault-pro.git
```

```bash
cd YOUR_REPO
```
### 3. Create Virtual Environment (Recommended)

```bash
python -m venv .venv
```

Activate environment:

Windows:
```bash
.venv\Scripts\activate
```
macOS / Linux
```bash
source .venv/bin/activate
```
### 4. Install Dependencies
```bash
pip install -r requirements.txt
```
5. Run SecureVault
```bash
python main.py
```
The SecureVault application window should launch.

## First Launch

On first startup:

1. Create a Master Password

2. Save the generated Recovery Key

3. Enter the vault interface

4. Add encrypted credential entries

## Data Storage

Encrypted credentials are stored locally in:

```bash
securevault.db
```
