import subprocess
import pytz
from datetime import datetime, timedelta
from datetime import time
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, JobQueue
import asyncio
            
# Fungsi untuk mengeksekusi file virustotal.py dengan IP yang dikirimkan oleh pengguna
async def execute_script_22(update: Update, context):
    try:
        # Mengambil alamat IP yang dikirim oleh pengguna
        ip_address = context.args[0]  # Mengambil argumen pertama dari perintah /VirusTotal <ip_address>
        
        # Menjalankan analisis VirusTotal dengan IP tersebut
        result = subprocess.run(
            ['python3', 'virustotal.py', ip_address],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            if update.message:
                await update.message.reply_text(f"Data API berhasil di retrieve \n {result.stdout}")
        else:
            if update.message:
                await update.message.reply_text(f"Terjadi kesalahan saat eksekusi script 22: \n{result.stderr}")
    except Exception as e:
        if update.message:
            await update.message.reply_text(f"Error saat mengeksekusi script 22: {e}")


# Fungsi untuk menyapa pengguna dengan perintah /start
async def start(update: Update, context):
    if update.message:
        await update.message.reply_text(
            "Halo \U0001F60A! Saya adalah Punggawa Bot yang terintegrasi dengan VirusTotal.\n Gunakan perintah:\n"
            "- /start untuk menampilkan pesan ini\n"
            "- /IPreputation <spasi> <IP_address> untuk analisis IP Reputation \n"
            "- /MoodBooster untuk itu iya itu tau ga lu jan iya iya aja"
        )
        
# Fungsi untuk menambahkan job otomatis pada JobQueue
async def job_callback(context):
    context.job_queue.run_daily(scheduled_job, time=datetime.time(11, 0, 0), days=(0, 1, 2, 3, 4, 5, 6), context=context)
        
# Fungsi untuk moodbooster /MoodBooster
async def moodbooster(update: Update, context):
    if update.message:
        await update.message.reply_text(
            "Semangat kerjanya kakak, jangan lupa makan \U0001F60A \n"
            "Ikan sepat ikan tongkol"
        )

if __name__ == '__main__':
    TOKEN = '<your telegram token'

    # Membuat aplikasi bot
    application = ApplicationBuilder().token(TOKEN).build()

    # Menambahkan handler untuk perintah /start
    application.add_handler(CommandHandler("start", start))
    
    # Menambahkan handler untuk perintah /MoodBooster
    application.add_handler(CommandHandler("MoodBooster", moodbooster))

    # Menambahkan handler untuk perintah eksekusi script
    application.add_handler(CommandHandler("IPreputation", execute_script_22))


    # Menjalankan bot
    application.run_polling()
