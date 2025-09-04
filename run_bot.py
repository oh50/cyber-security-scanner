#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🤖 TURKI'S CYBER SECURITY SCANNER BOT - QUICK RUNNER
👨‍💻 Developed by: Turki Alsalem
📧 Contact: turki.alsalem1@outlook.sa
"""

def main():
    """Quick runner for the Telegram bot"""
    print("🤖 TURKI'S CYBER SECURITY SCANNER BOT")
    print("🛡️ Quick Runner v3.0")
    print("👨‍💻 Developed by: Turki Alsalem")
    print("=" * 60)
    
    try:
        # Import and run the bot
        from telegram_bot import main as bot_main
        bot_main()
        
    except ImportError as e:
        print(f"❌ Error importing bot: {e}")
        print("📝 Make sure you have installed all requirements:")
        print("   pip install -r requirements_bot.txt")
        
    except Exception as e:
        print(f"❌ Error running bot: {e}")

if __name__ == "__main__":
    main()