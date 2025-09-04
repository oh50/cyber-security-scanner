#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 TURKI'S ADVANCED CYBER SECURITY SCANNER - ENCRYPTION TOOL
🛡️ Advanced encryption for project protection
👨‍💻 Developed by: Turki Alsalem
📧 Contact: turki.alsalem1@outlook.sa
"""

import os
import base64
import zlib
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

class ProjectEncryptor:
    def __init__(self, password="TurkiAlsalem2024"):
        self.password = password.encode()
        self.salt = b'turki_cyber_security_scanner_salt_2024'
        self.key = self._generate_key()
        self.cipher = Fernet(self.key)
        
    def _generate_key(self):
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt_file(self, file_path):
        """Encrypt a single file"""
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
            
            # Compress content
            compressed = zlib.compress(content)
            
            # Encrypt content
            encrypted = self.cipher.encrypt(compressed)
            
            # Encode to base64
            encoded = base64.b64encode(encrypted)
            
            # Create encrypted file
            encrypted_path = file_path + '.encrypted'
            with open(encrypted_path, 'wb') as enc_file:
                enc_file.write(encoded)
            
            print(f"✅ Encrypted: {file_path} -> {encrypted_path}")
            return encrypted_path
            
        except Exception as e:
            print(f"❌ Error encrypting {file_path}: {e}")
            return None
    
    def encrypt_project(self):
        """Encrypt the entire project"""
        print("🔐 Starting Advanced Project Encryption...")
        print("👨‍💻 Developed by: Turki Alsalem")
        print("=" * 60)
        
        # Files to encrypt
        files_to_encrypt = [
            'cyber_security_scanner.py',
            'telegram_bot.py',
            'run_bot.py'
        ]
        
        encrypted_files = []
        
        for file_path in files_to_encrypt:
            if os.path.exists(file_path):
                encrypted_file = self.encrypt_file(file_path)
                if encrypted_file:
                    encrypted_files.append(encrypted_file)
            else:
                print(f"⚠️ File not found: {file_path}")
        
        # Create decryption script
        self._create_decryption_script()
        
        # Create encrypted README
        self._create_encrypted_readme()
        
        print("\n🎉 Project Encryption Completed!")
        print(f"📁 Encrypted {len(encrypted_files)} files")
        print("🔐 All files are now protected with advanced encryption")
        
        return encrypted_files
    
    def _create_decryption_script(self):
        """Create decryption script"""
        decryption_script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔓 TURKI'S ADVANCED CYBER SECURITY SCANNER - DECRYPTION TOOL
🛡️ Decrypt encrypted project files
👨‍💻 Developed by: Turki Alsalem
📧 Contact: turki.alsalem1@outlook.sa
"""

import os
import base64
import zlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ProjectDecryptor:
    def __init__(self, password="TurkiAlsalem2024"):
        self.password = password.encode()
        self.salt = b'turki_cyber_security_scanner_salt_2024'
        self.key = self._generate_key()
        self.cipher = Fernet(self.key)
        
    def _generate_key(self):
        """Generate decryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def decrypt_file(self, encrypted_file):
        """Decrypt a single file"""
        try:
            with open(encrypted_file, 'rb') as file:
                encoded_content = file.read()
            
            # Decode from base64
            encrypted_content = base64.b64decode(encoded_content)
            
            # Decrypt content
            compressed_content = self.cipher.decrypt(encrypted_content)
            
            # Decompress content
            original_content = zlib.decompress(compressed_content)
            
            # Create decrypted file
            decrypted_file = encrypted_file.replace('.encrypted', '')
            with open(decrypted_file, 'wb') as dec_file:
                dec_file.write(original_content)
            
            print(f"✅ Decrypted: {encrypted_file} -> {decrypted_file}")
            return decrypted_file
            
        except Exception as e:
            print(f"❌ Error decrypting {encrypted_file}: {e}")
            return None
    
    def decrypt_project(self):
        """Decrypt the entire project"""
        print("🔓 Starting Project Decryption...")
        print("👨‍💻 Developed by: Turki Alsalem")
        print("=" * 60)
        
        # Find all encrypted files
        encrypted_files = [f for f in os.listdir('.') if f.endswith('.encrypted')]
        
        if not encrypted_files:
            print("❌ No encrypted files found!")
            return
        
        decrypted_files = []
        
        for encrypted_file in encrypted_files:
            decrypted_file = self.decrypt_file(encrypted_file)
            if decrypted_file:
                decrypted_files.append(decrypted_file)
        
        print(f"\\n🎉 Project Decryption Completed!")
        print(f"📁 Decrypted {len(decrypted_files)} files")
        print("🚀 Project is now ready to use!")
        
        return decrypted_files

def main():
    """Main function"""
    print("🔓 TURKI'S CYBER SECURITY SCANNER - DECRYPTION TOOL")
    print("🛡️ Decrypt encrypted project files")
    print("👨‍💻 Developed by: Turki Alsalem")
    print("=" * 60)
    
    try:
        decryptor = ProjectDecryptor()
        decryptor.decrypt_project()
        
    except Exception as e:
        print(f"❌ Error during decryption: {e}")

if __name__ == "__main__":
    main()
'''
        
        with open('decrypt_project.py', 'w', encoding='utf-8') as f:
            f.write(decryption_script)
        
        print("✅ Created decryption script: decrypt_project.py")
    
    def _create_encrypted_readme(self):
        """Create encrypted README"""
        encrypted_readme = '''# 🔒 TURKI'S ADVANCED CYBER SECURITY SCANNER - ENCRYPTED VERSION

🛡️ **Ultimate Website Vulnerability Assessment Tool - Encrypted Edition**

👨‍💻 **Developed by:** Turki Alsalem  
🚀 **Project:** Advanced Cyber Security Scanner v3.0 - Encrypted  
📧 **Contact:** turki.alsalem1@outlook.sa  

---

## 🔐 **ENCRYPTED PROJECT**

This project is protected with advanced encryption to prevent unauthorized access and modification.

### **🔓 How to Decrypt:**

1. **Install required dependencies:**
```bash
pip install cryptography
```

2. **Run the decryption script:**
```bash
python decrypt_project.py
```

3. **Enter the decryption password when prompted**

4. **Project will be decrypted and ready to use**

---

## 🤖 **EASY ACCESS - TELEGRAM BOT**

**Don't want to decrypt? Use our Telegram Bot instead!**

### **📱 Telegram Bot: @CyberScan3bot**

**Features:**
- ✅ No installation required
- ✅ Easy to use interface
- ✅ All 20+ security scanners
- ✅ PDF and JSON reports
- ✅ Real-time results
- ✅ Mobile friendly

### **🚀 How to Use the Bot:**

1. **Open Telegram**
2. **Search for:** `@CyberScan3bot`
3. **Send:** `/start`
4. **Send:** `/scan https://example.com`
5. **Get instant results!**

---

## 🔒 **SECURITY FEATURES**

### **🔍 Advanced Security Scanners (20+ Scanners):**
- 🔐 **SSL/TLS Security** - Certificate validation and cryptographic analysis
- 🛡️ **Security Headers** - HTTP security headers analysis
- 🔍 **Port Scanner** - Network port and service detection
- 🌐 **Subdomain Discovery** - Subdomain enumeration and analysis
- 💉 **SQL Injection** - Advanced SQL injection testing
- 🕷️ **XSS Scanner** - Cross-site scripting vulnerability detection
- 🔄 **CSRF Scanner** - Cross-site request forgery testing
- 🌐 **SSRF Scanner** - Server-side request forgery testing
- 📄 **XXE Scanner** - XML external entity testing
- 💻 **Command Injection** - Command injection vulnerability testing
- 🔌 **API Security** - API endpoint security analysis
- 🔐 **JWT Security** - JSON Web Token security testing
- 🔑 **API Key Detection** - Exposed API keys and secrets detection
- 🔍 **GraphQL Security** - GraphQL endpoint security testing
- 📡 **WebSocket Security** - WebSocket connection security
- 🔓 **Authentication Bypass** - Authentication bypass testing
- 📊 **Business Logic** - Business logic vulnerability testing
- 🌐 **CORS Security** - Cross-origin resource sharing analysis
- 🕷️ **DOM XSS** - DOM-based XSS testing
- 💉 **Advanced SQL Injection** - Enhanced SQL injection testing

### **📊 Reporting Features:**
- 📄 **Professional PDF Reports** - Comprehensive security assessment reports
- 📈 **Detailed Statistics** - Scan metrics and vulnerability breakdown
- 🎯 **Risk Assessment** - Severity-based vulnerability classification
- 💡 **Security Recommendations** - Actionable security improvement suggestions
- 📱 **Telegram Bot Integration** - Real-time scanning via Telegram bot

---

## 🚀 **QUICK START**

### **Option 1: Use Telegram Bot (Recommended)**
```
1. Open Telegram
2. Search: @CyberScan3bot
3. Send: /start
4. Send: /scan https://example.com
5. Get results instantly!
```

### **Option 2: Decrypt and Run Locally**
```
1. pip install cryptography
2. python decrypt_project.py
3. python cyber_security_scanner.py
```

---

## ⚠️ **LEGAL NOTICE**

**IMPORTANT:** This tool is for educational and authorized testing purposes only. Always ensure you have explicit permission before scanning any website.

### **Authorized Use:**
- ✅ Your own websites
- ✅ Websites you have explicit permission to test
- ✅ Educational and research purposes
- ✅ Penetration testing with proper authorization

### **Unauthorized Use:**
- ❌ Scanning websites without permission
- ❌ Malicious activities
- ❌ Unauthorized penetration testing
- ❌ Any illegal activities

---

## 📞 **SUPPORT**

### **Contact Information:**
- **Developer:** Turki Alsalem
- **Email:** turki.alsalem1@outlook.sa
- **GitHub:** https://github.com/turki-alsalem/cyber-security-scanner
- **Telegram Bot:** @CyberScan3bot

### **Issues and Bugs:**
- Report issues on GitHub
- Include detailed error messages
- Provide steps to reproduce
- Include system information

---

## 📄 **LICENSE**

**All Rights Reserved © 2024 Turki Alsalem**

This project is proprietary software. Unauthorized copying, distribution, or modification is strictly prohibited.

---

## 🎯 **RECOMMENDED USAGE**

**For most users, we recommend using the Telegram Bot:**
- 🤖 **@CyberScan3bot** - Easy, fast, and secure
- 📱 **Mobile friendly** - Use from anywhere
- 🔒 **No installation** - Just open Telegram
- 📊 **Full features** - All scanners available
- 📄 **Instant reports** - PDF and JSON formats

**For developers and advanced users:**
- 🔓 **Decrypt the project** - Full source code access
- 🛠️ **Customize** - Modify and extend functionality
- 🔧 **Integrate** - Use in your own projects

---

**🔒 TURKI'S ADVANCED CYBER SECURITY SCANNER v3.0 - ENCRYPTED EDITION**  
**🛡️ Ultimate Edition - All Rights Reserved © 2024**  
**👨‍💻 Developed by: Turki Alsalem**

*Empowering cybersecurity professionals with advanced vulnerability assessment tools.*
'''
        
        with open('README_ENCRYPTED.md', 'w', encoding='utf-8') as f:
            f.write(encrypted_readme)
        
        print("✅ Created encrypted README: README_ENCRYPTED.md")

def main():
    """Main function"""
    print("🔐 TURKI'S ADVANCED CYBER SECURITY SCANNER - ENCRYPTION TOOL")
    print("🛡️ Advanced encryption for project protection")
    print("👨‍💻 Developed by: Turki Alsalem")
    print("=" * 60)
    
    try:
        encryptor = ProjectEncryptor()
        encryptor.encrypt_project()
        
    except Exception as e:
        print(f"❌ Error during encryption: {e}")

if __name__ == "__main__":
    main()
