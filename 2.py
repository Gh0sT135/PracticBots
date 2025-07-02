import telebot
from datetime import datetime
from config import BOT_TOKEN

bot = telebot.TeleBot(BOT_TOKEN)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    text = (
        "Привет! Я бот, который показываю время и дату.\n"
        "Доступные команды:\n"
        "/time - текущее время\n"
        "/date - текущая дата"
    )
    bot.reply_to(message, text)

@bot.message_handler(commands=['time'])
def send_time(message):
    current_time = datetime.now().strftime("%H:%M:%S")
    bot.reply_to(message, f"Текущее время: {current_time}")

@bot.message_handler(commands=['date'])
def send_date(message):
    current_date = datetime.now().strftime("%d.%m.%Y")
    bot.reply_to(message, f"Текущая дата: {current_date}")

bot.infinity_polling()