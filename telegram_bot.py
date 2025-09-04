#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🤖 TURKI'S CYBER SECURITY SCANNER - TELEGRAM BOT
🛡️ Advanced Security Assessment Bot
👨‍💻 Developed by: Turki Alsalem
🚀 Project: Advanced Cyber Security Scanner v3.0
📧 Contact: turki.alsalem1@outlook.sa
"""

import logging
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from cyber_security_scanner import scan_website_api, get_scan_summary, get_vulnerability_details
import json
import os

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot configuration
BOT_TOKEN = "# Your bot token"  # Your bot token
DEVELOPER_ID = "# Your bot token"  # Your bot token

class CyberSecurityBot:
    def __init__(self):
        self.active_scans = {}
        
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        welcome_message = """
🔒 **Welcome to TURKI'S CYBER SECURITY SCANNER!** 🛡️

👨‍💻 **Developed by:** Turki Alsalem
🛡️ **Tool:** Advanced Cyber Security Scanner v3.0
🚀 **Version:** Ultimate Edition

**Available Commands:**
/start - Show this welcome message
/scan <website> - Scan a website for vulnerabilities
/help - Show help information
/about - About the developer and tool
/status - Check bot status

**Example:**
/scan https://example.com

**Features:**
• 🔍 Comprehensive vulnerability scanning
• 🛡️ Advanced security assessment
• 📊 Detailed PDF reports
• ⚡ Real-time results
• 🔐 Multiple attack vectors

**⚠️ Important:** Only use this tool on websites you own or have permission to test!
        """
        
        keyboard = [
            [InlineKeyboardButton("🔍 Scan Website", callback_data="scan_menu")],
            [InlineKeyboardButton("ℹ️ About", callback_data="about")],
            [InlineKeyboardButton("❓ Help", callback_data="help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(welcome_message, parse_mode='Markdown', reply_markup=reply_markup)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_message = """
❓ **HELP - TURKI'S CYBER SECURITY SCANNER**

**How to use:**
1. Send `/scan <website_url>` to start scanning
2. Wait for the scan to complete
3. Receive detailed vulnerability report

**Commands:**
• `/scan <url>` - Scan website for vulnerabilities
• `/start` - Show welcome message
• `/help` - Show this help
• `/about` - About developer and tool
• `/status` - Check bot status

**Examples:**
```
/scan https://example.com
/scan example.com
/scan http://test.com
```

**Scan Types:**
• 🔐 SSL/TLS Security
• 🛡️ Security Headers
• 🔍 Port Scanning
• 🌐 Subdomain Discovery
• 💉 SQL Injection
• 🕷️ XSS Testing
• 🔄 CSRF Protection
• 🌐 SSRF Testing
• 📄 XXE Testing
• 💻 Command Injection
• 🔌 API Security
• 🔐 JWT Security
• 🔑 API Key Detection
• 🔍 GraphQL Security
• 📡 WebSocket Security
• 🔓 Authentication Bypass
• 📊 Business Logic
• 🌐 CORS Security
• 🕷️ DOM XSS
• 💉 Advanced SQL Injection

**⚠️ Legal Notice:**
Only use this tool on websites you own or have explicit permission to test. Unauthorized scanning may be illegal.

👨‍💻 **Developer:** Turki Alsalem
🛡️ **Tool:** Advanced Cyber Security Scanner v3.0
        """
        
        await update.message.reply_text(help_message, parse_mode='Markdown')
    
    async def about_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /about command"""
        about_message = """
👨‍💻 **ABOUT TURKI'S CYBER SECURITY SCANNER**

**Developer Information:**
• **Name:** Turki Alsalem
• **Role:** Cybersecurity Expert & Developer
• **Email:** turki.alsalem1@outlook.sa
• **GitHub:** https://github.com/turki-alsalem/cyber-security-scanner

**Tool Information:**
• **Name:** Turki's Advanced Cyber Security Scanner
• **Version:** v3.0 - Ultimate Edition
• **Type:** Comprehensive Vulnerability Assessment Tool
• **Language:** Python 3.x
• **License:** All Rights Reserved © 2024

**Features:**
• 🔍 20+ Advanced Security Scanners
• 🛡️ Comprehensive Vulnerability Detection
• 📊 Professional PDF Reports
• ⚡ Real-time Scanning
• 🤖 Telegram Bot Integration
• 🔐 Multiple Attack Vectors
• 📱 Cross-platform Support

**Technologies Used:**
• Python 3.x
• Requests Library
• SSL/TLS Analysis
• DNS Resolution
• WebSocket Testing
• GraphQL Security
• JWT Analysis
• API Security Testing
• PDF Report Generation

**Security Standards:**
• OWASP Top 10 Coverage
• Industry Best Practices
• Professional Security Assessment
• Comprehensive Testing Methodology

**⚠️ Disclaimer:**
This tool is for educational and authorized testing purposes only. Always ensure you have permission before scanning any website.

🚀 **Ultimate Edition - All Rights Reserved © 2024**
        """
        
        await update.message.reply_text(about_message, parse_mode='Markdown')
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        status_message = """
🟢 **BOT STATUS - ONLINE**

**System Information:**
• **Bot Status:** ✅ Active
• **Scanner Status:** ✅ Ready
• **Version:** v3.0 - Ultimate Edition
• **Developer:** Turki Alsalem

**Active Scans:** {active_scans}
**Uptime:** {uptime}

**Available Scanners:**
• 🔐 SSL/TLS Security Scanner
• 🛡️ Security Headers Scanner
• 🔍 Port Scanner
• 🌐 Subdomain Discovery
• 💉 SQL Injection Scanner
• 🕷️ XSS Scanner
• 🔄 CSRF Scanner
• 🌐 SSRF Scanner
• 📄 XXE Scanner
• 💻 Command Injection Scanner
• 🔌 API Security Scanner
• 🔐 JWT Security Scanner
• 🔑 API Key Detection
• 🔍 GraphQL Security Scanner
• 📡 WebSocket Security Scanner
• 🔓 Authentication Bypass Scanner
• 📊 Business Logic Scanner
• 🌐 CORS Security Scanner
• 🕷️ DOM XSS Scanner
• 💉 Advanced SQL Injection Scanner

**Ready to scan!** Send `/scan <website>` to start.
        """.format(
            active_scans=len(self.active_scans),
            uptime="Running"
        )
        
        await update.message.reply_text(status_message, parse_mode='Markdown')
    
    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/scan <website_url>`\n\n**Example:** `/scan https://example.com`",
                parse_mode='Markdown'
            )
            return
        
        target_url = context.args[0].strip()
        
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Check if user is already scanning
        user_id = update.effective_user.id
        if user_id in self.active_scans:
            await update.message.reply_text(
                "⏳ You already have an active scan running. Please wait for it to complete.",
                parse_mode='Markdown'
            )
            return
        
        # Start scan
        self.active_scans[user_id] = target_url
        
        # Send initial message
        scan_message = f"""
🔍 **Starting Security Scan...**

**Target:** {target_url}
**Scanner:** Turki's Advanced Cyber Security Scanner v3.0
**Developer:** Turki Alsalem

⏳ **Scanning in progress...**
This may take a few minutes depending on the website size.

**Scanners Running:**
• 🔐 SSL/TLS Security
• 🛡️ Security Headers
• 🔍 Port Scanning
• 🌐 Subdomain Discovery
• 💉 SQL Injection
• 🕷️ XSS Testing
• 🔄 CSRF Protection
• 🌐 SSRF Testing
• 📄 XXE Testing
• 💻 Command Injection
• 🔌 API Security
• 🔐 JWT Security
• 🔑 API Key Detection
• 🔍 GraphQL Security
• 📡 WebSocket Security
• 🔓 Authentication Bypass
• 📊 Business Logic
• 🌐 CORS Security
• 🕷️ DOM XSS
• 💉 Advanced SQL Injection

Please wait...
        """
        
        status_message = await update.message.reply_text(scan_message, parse_mode='Markdown')
        
        try:
            # Run scan
            result = scan_website_api(target_url)
            
            if result['success']:
                # Remove from active scans
                if user_id in self.active_scans:
                    del self.active_scans[user_id]
                
                # Get summary
                summary = get_scan_summary(result['results'])
                
                # Send summary
                await status_message.edit_text(summary, parse_mode='Markdown')
                
                # Send detailed vulnerabilities
                details = get_vulnerability_details(result['results'])
                await update.message.reply_text(details, parse_mode='Markdown')
                
                # Send completion message
                completion_message = f"""
✅ **Scan Completed Successfully!**

**Target:** {target_url}
**Scanner:** Turki's Advanced Cyber Security Scanner v3.0
**Developer:** Turki Alsalem

📊 **Results:**
• Total Vulnerabilities: {len(result['results'].get('vulnerabilities', []))}
• Scan Time: {result['results'].get('scan_time', 'Unknown')}

📄 **PDF Report:** Generated and ready to send
🛡️ **All vulnerabilities documented and analyzed**

**⚠️ Important:** Review all findings and implement security recommendations.

👨‍💻 **Report generated by:** Turki Alsalem
🛡️ **Tool:** Advanced Cyber Security Scanner v3.0
                """
                
                await update.message.reply_text(completion_message, parse_mode='Markdown')
                
                # Send PDF report to user
                try:
                    # Get the generated PDF file
                    import glob
                    import os
                    
                    # Find the latest PDF report
                    pdf_files = glob.glob("security_scan_report_*.pdf")
                    if pdf_files:
                        # Get the most recent file
                        latest_pdf = max(pdf_files, key=os.path.getctime)
                        
                        # Send PDF to user
                        with open(latest_pdf, 'rb') as pdf_file:
                            await update.message.reply_document(
                                document=pdf_file,
                                filename=f"Security_Report_{target_url.replace('https://', '').replace('http://', '')}.pdf",
                                caption=f"""
📄 **Comprehensive Security Report**

**Target:** {target_url}
**Generated by:** Turki's Advanced Cyber Security Scanner v3.0
**Developer:** Turki Alsalem
**Date:** {result['results'].get('scan_time', 'Unknown')}

**Report Contents:**
• Executive Summary
• Detailed Vulnerability Analysis
• Security Recommendations
• SSL/TLS Analysis
• Network Security Assessment
• Subdomain Discovery Results
• Scan Statistics & Metrics

🛡️ **All vulnerabilities documented and analyzed**
👨‍💻 **Report generated by:** Turki Alsalem
                                """,
                                parse_mode='Markdown'
                            )
                    else:
                        await update.message.reply_text(
                            "❌ PDF report not found. Please check the scan results above.",
                            parse_mode='Markdown'
                        )
                        
                except Exception as e:
                    await update.message.reply_text(
                        f"❌ Error sending PDF report: {str(e)}\n\nPlease check the scan results above.",
                        parse_mode='Markdown'
                    )
                
                # Also send JSON report for developers
                try:
                    import json
                    from datetime import datetime
                    
                    # Create JSON report
                    json_filename = f"security_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(json_filename, 'w', encoding='utf-8') as json_file:
                        json.dump(result['results'], json_file, indent=2, ensure_ascii=False)
                    
                    # Send JSON report
                    with open(json_filename, 'rb') as json_file:
                        await update.message.reply_document(
                            document=json_file,
                            filename=f"Security_Report_{target_url.replace('https://', '').replace('http://', '')}.json",
                            caption=f"""
📊 **JSON Report for Developers**

**Target:** {target_url}
**Format:** JSON (Machine-readable)
**Generated by:** Turki's Advanced Cyber Security Scanner v3.0
**Developer:** Turki Alsalem

**Use this file for:**
• Integration with other tools
• Automated processing
• Detailed analysis
• Custom reporting

🛡️ **All scan data in structured format**
👨‍💻 **Report generated by:** Turki Alsalem
                            """,
                            parse_mode='Markdown'
                        )
                    
                    # Clean up JSON file
                    os.remove(json_filename)
                    
                except Exception as e:
                    # JSON report is optional, don't show error to user
                    pass
                
                # Send final summary message
                final_summary = f"""
🎯 **SCAN COMPLETED - FINAL SUMMARY**

**Target Website:** {target_url}
**Scan Date:** {result['results'].get('scan_time', 'Unknown')}
**Scanner:** Turki's Advanced Cyber Security Scanner v3.0
**Developer:** Turki Alsalem

📊 **Vulnerability Summary:**
• 🔴 Critical: {len([v for v in result['results'].get('vulnerabilities', []) if v.get('severity') == 'CRITICAL'])}
• 🟠 High: {len([v for v in result['results'].get('vulnerabilities', []) if v.get('severity') == 'HIGH'])}
• 🟡 Medium: {len([v for v in result['results'].get('vulnerabilities', []) if v.get('severity') == 'MEDIUM'])}
• 🟢 Low: {len([v for v in result['results'].get('vulnerabilities', []) if v.get('severity') == 'LOW'])}

📄 **Reports Sent:**
• PDF Report (Human-readable)
• JSON Report (Machine-readable)
• Detailed Analysis (Above)

🛡️ **Next Steps:**
1. Review all vulnerabilities
2. Implement security recommendations
3. Re-scan after fixes
4. Monitor for new threats

**⚠️ Remember:** Only use this tool on websites you own or have permission to test!

👨‍💻 **Report generated by:** Turki Alsalem
🛡️ **Tool:** Advanced Cyber Security Scanner v3.0
📧 **Contact:** turki.alsalem1@outlook.sa
                """
                
                await update.message.reply_text(final_summary, parse_mode='Markdown')
                
            else:
                # Remove from active scans
                if user_id in self.active_scans:
                    del self.active_scans[user_id]
                
                error_message = f"""
❌ **Scan Failed**

**Target:** {target_url}
**Error:** {result.get('error', 'Unknown error')}

**Possible reasons:**
• Website is down or unreachable
• Invalid URL format
• Network connectivity issues
• Website blocking automated requests

**Please try again or contact support.**
                """
                
                await status_message.edit_text(error_message, parse_mode='Markdown')
                
        except Exception as e:
            # Remove from active scans
            if user_id in self.active_scans:
                del self.active_scans[user_id]
            
            error_message = f"""
❌ **Scan Error**

**Target:** {target_url}
**Error:** {str(e)}

**Please try again or contact support.**
            """
            
            await status_message.edit_text(error_message, parse_mode='Markdown')
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        await query.answer()
        
        if query.data == "scan_menu":
            await query.edit_message_text(
                "🔍 **Scan Menu**\n\nSend `/scan <website_url>` to start scanning.\n\n**Example:** `/scan https://example.com`",
                parse_mode='Markdown'
            )
        elif query.data == "about":
            await self.about_command(update, context)
        elif query.data == "help":
            await self.help_command(update, context)
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle regular messages"""
        message_text = update.message.text.lower()
        
        if any(keyword in message_text for keyword in ['scan', 'security', 'vulnerability', 'hack']):
            await update.message.reply_text(
                "🔍 To scan a website, use: `/scan <website_url>`\n\n**Example:** `/scan https://example.com`",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "👋 Hi! I'm Turki's Cyber Security Scanner Bot.\n\nUse `/help` to see available commands or `/scan <website>` to start scanning.",
                parse_mode='Markdown'
            )

def main():
    """Main function to run the bot"""
    print("🤖 Starting TURKI'S CYBER SECURITY SCANNER BOT...")
    print("👨‍💻 Developed by: Turki Alsalem")
    print("🛡️ Tool: Advanced Cyber Security Scanner v3.0")
    print("=" * 60)
    
    # Check if bot token is set
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ Error: Please set your bot token in the BOT_TOKEN variable")
        print("📝 Get your bot token from @BotFather on Telegram")
        return
    
    # Create bot instance
    bot = CyberSecurityBot()
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", bot.start_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("about", bot.about_command))
    application.add_handler(CommandHandler("status", bot.status_command))
    application.add_handler(CommandHandler("scan", bot.scan_command))
    application.add_handler(CallbackQueryHandler(bot.button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Start bot
    print("🚀 Bot is starting...")
    print("✅ Bot is ready to receive commands!")
    print("🔒 TURKI'S CYBER SECURITY SCANNER BOT IS ONLINE!")
    
    application.run_polling()

if __name__ == "__main__":
    main()
