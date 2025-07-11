import asyncio
import base64
import html
from config import BOT_TOKEN
from aiogram import Bot, Dispatcher, types, F
from aiogram.enums import ParseMode
from aiogram.filters import Command, StateFilter
from aiogram.client.default import DefaultBotProperties
from aiogram.types import BotCommand
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from cryptography.fernet import Fernet

# --- Конфигурация ---


bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher()


# --- Состояния FSM ---
class Form(StatesGroup):
    waiting_for_morse = State()
    waiting_for_demorse = State()
    waiting_for_bin = State()
    waiting_for_debin = State()
    waiting_for_b64 = State()
    waiting_for_deb64 = State()
    waiting_for_encrypt = State()
    waiting_for_decrypt = State()
    waiting_for_decrypt_key = State()


# --- Шифры ---
MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', ' ': '/',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
}

REVERSE_MORSE = {v: k for k, v in MORSE_CODE.items()}


# --- Команды бота ---
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "🔐 <b>Бот-шифровальщик</b>\n\n"
        "Доступные команды:\n"
        "/morse - Кодировать в Морзе 📡 (Only Eng)\n"
        "/demorse - Декодировать из Морзе\n"
        "/bin - Кодировать в бинарный код 0️⃣1️⃣\n"
        "/debin - Декодировать из бинарного кода\n"
        "/b64 - Кодировать в Base64  📃 (ASCII)\n"
        "/deb64 - Декодировать из Base64 (ASCII)\n"
        "/encrypt - Зашифровать текст 🔒 (Fernet)\n"
        "/decrypt - Расшифровать текст 🔓  (Fernet)\n\n"
        "<i>Пример: выберите /morse и введите SOS</i>"
    )


# Обработчики команд, которые устанавливают состояние
@dp.message(Command("morse"))
async def morse_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите текст для кодирования в Морзе:")
    await state.set_state(Form.waiting_for_morse)


@dp.message(Command("demorse"))
async def demorse_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите код Морзе для декодирования:")
    await state.set_state(Form.waiting_for_demorse)


@dp.message(Command("bin"))
async def bin_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите текст для кодирования в бинарный код:")
    await state.set_state(Form.waiting_for_bin)


@dp.message(Command("debin"))
async def debin_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите бинарный код для декодирования:")
    await state.set_state(Form.waiting_for_debin)


@dp.message(Command("b64"))
async def b64_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите текст для кодирования в Base64:")
    await state.set_state(Form.waiting_for_b64)


@dp.message(Command("deb64"))
async def deb64_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите Base64-код для декодирования:")
    await state.set_state(Form.waiting_for_deb64)


@dp.message(Command("encrypt"))
async def encrypt_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите текст для шифрования (Fernet):")
    await state.set_state(Form.waiting_for_encrypt)


@dp.message(Command("decrypt"))
async def decrypt_command(message: types.Message, state: FSMContext):
    await message.answer("📝 Введите зашифрованный текст для расшифровки:")
    await state.set_state(Form.waiting_for_decrypt)
    await state.update_data(step="waiting_for_text")
@dp.message(Form.waiting_for_bin)
async def process_bin(message: types.Message, state: FSMContext):
    text = message.text
    # Используем UTF-8 для поддержки русского
    binary = ' '.join(format(byte, '08b') for byte in text.encode('utf-8'))
    await message.answer(f"🔢 Бинарный код (UTF-8):\n<code>{binary}</code>")
    await state.clear()

@dp.message(Form.waiting_for_debin)
async def process_debin(message: types.Message, state: FSMContext):
    binary_str = message.text
    try:
        # Разбиваем на байты (по 8 бит)
        bytes_list = [int(byte, 2) for byte in binary_str.split()]
        # Преобразуем байты обратно в текст с UTF-8
        text = bytes(bytes_list).decode('utf-8')
        escaped_text = html.escape(text)
        await message.answer(f"🔢 Текст:\n<code>{escaped_text}</code>")
    except Exception as e:
        await message.answer(f"❌ Ошибка декодирования: {str(e)}")
    await state.clear()

# Обработчики состояний
@dp.message(Form.waiting_for_morse)
async def process_morse(message: types.Message, state: FSMContext):
    text = message.text.upper()
    encoded = []
    for char in text:
        if char in MORSE_CODE:
            encoded.append(MORSE_CODE[char])
        else:
            encoded.append('�')
    await message.answer(f"📡 Морзе-код:\n<code>{' '.join(encoded)}</code>")
    await state.clear()


@dp.message(Form.waiting_for_demorse)
async def process_demorse(message: types.Message, state: FSMContext):
    code = message.text
    decoded = []
    for part in code.split():
        if part in REVERSE_MORSE:
            decoded.append(REVERSE_MORSE[part])
        else:
            decoded.append('�')
    escaped_text = html.escape(''.join(decoded))
    await message.answer(f"📡 Текст:\n<code>{escaped_text}</code>")
    await state.clear()


@dp.message(Form.waiting_for_bin)
async def process_bin(message: types.Message, state: FSMContext):
    text = message.text
    binary = ' '.join(format(ord(c), '08b') for c in text)
    await message.answer(f"🔢 Бинарный код:\n<code>{binary}</code>")
    await state.clear()


@dp.message(Form.waiting_for_debin)
async def process_debin(message: types.Message, state: FSMContext):
    binary_str = message.text
    binary_list = binary_str.split()
    text = []

    for byte in binary_list:
        try:
            if not all(bit in '01' for bit in byte):
                text.append('�')
                continue

            clean_byte = byte.strip()
            if len(clean_byte) == 8:
                text.append(chr(int(clean_byte, 2)))
            else:
                text.append('�')
        except:
            text.append('�')

    escaped_text = html.escape(''.join(text))
    await message.answer(f"🔢 Текст:\n<code>{escaped_text}</code>")
    await state.clear()


@dp.message(Form.waiting_for_b64)
async def process_b64(message: types.Message, state: FSMContext):
    text = message.text
    encoded = base64.b64encode(text.encode()).decode()
    await message.answer(f"📄 Base64:\n<code>{encoded}</code>")
    await state.clear()


@dp.message(Form.waiting_for_deb64)
async def process_deb64(message: types.Message, state: FSMContext):
    code = message.text
    try:
        decoded = base64.b64decode(code).decode()
        escaped_text = html.escape(decoded)
        await message.answer(f"📄 Текст:\n<code>{escaped_text}</code>")
    except Exception as e:
        await message.answer(f"❌ Ошибка декодирования: {str(e)}")
    await state.clear()


@dp.message(Form.waiting_for_encrypt)
async def process_encrypt(message: types.Message, state: FSMContext):
    text = message.text
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())

    # Отправляем ключ и зашифрованный текст отдельными сообщениями
    await message.answer(f"🔑 Ключ (сохраните для расшифровки):\n<code>{key.decode()}</code>")
    await message.answer(f"🔒 Зашифрованный текст:\n<code>{encrypted.decode()}</code>")
    await state.clear()


@dp.message(Form.waiting_for_decrypt)
async def process_decrypt(message: types.Message, state: FSMContext):
    user_data = await state.get_data()

    if user_data.get("step") == "waiting_for_text":
        await state.update_data(encrypted_text=message.text)
        await message.answer("🔑 Теперь введите ключ для расшифровки:")
        await state.update_data(step="waiting_for_key")
    else:
        encrypted_text = user_data.get("encrypted_text")
        key = message.text

        try:
            fernet = Fernet(key.encode())
            decrypted = fernet.decrypt(encrypted_text.encode()).decode()
            escaped_text = html.escape(decrypted)
            await message.answer(f"🔓 Расшифрованный текст:\n<code>{escaped_text}</code>")
        except Exception as e:
            await message.answer(f"❌ Ошибка расшифровки: {str(e)}")

        await state.clear()


# Меню команд
async def set_main_menu(bot: Bot):
    main_menu_commands = [
        BotCommand(command='/start', description='Главное меню'),
        BotCommand(command='/morse', description='Кодировать в Морзе 📡 '),
        BotCommand(command='/demorse', description='Декодировать из Морзе 📡'),
        BotCommand(command='/bin', description='Кодировать в бинарный 0️⃣1️⃣'),
        BotCommand(command='/debin', description='Декодировать из бинарного 0️⃣1️⃣'),
        BotCommand(command='/b64', description='Кодировать в Base64 📃 (ASCII)'),
        BotCommand(command='/deb64', description='Декодировать из Base64 📃(ASCII)'),
        BotCommand(command='/encrypt', description='Шифрование 🔒 (Fernet)'),
        BotCommand(command='/decrypt', description='Расшифровка 🔓 (Fernet)'),
    ]
    await bot.set_my_commands(main_menu_commands)


# Запуск бота
async def main():
    await set_main_menu(bot)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())