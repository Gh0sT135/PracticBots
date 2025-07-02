import telebot
from config import BOT_TOKEN

bot = telebot.TeleBot(BOT_TOKEN)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    username = message.from_user.first_name
    bot.reply_to(message, f"Привет, {username}! Отправь мне любое сообщение, и я его повторю.")

@bot.message_handler(func=lambda message: True)
def echo_all(message):
    bot.reply_to(message, f"Я получил сообщение: {message.text}")

bot.infinity_polling()