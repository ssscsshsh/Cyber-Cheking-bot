import asyncio, hashlib, logging, os, re, sqlite3, tempfile

import httpx
from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from google import genai
from dotenv import load_dotenv

load_dotenv()
BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = int(os.environ["ADMIN_ID"])
VT_KEY = os.environ["VT_API_KEY"]
MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
ai = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

MAX_FILE = 20 * 1024 * 1024  # Telegram botlar uchun yuklab olish limiti
LANGS = {"uz": "Uzbek", "ru": "Russian", "en": "English"}

TXT = {
    "uz": dict(
        menu="Bo'limni tanlang:", check="🔍 Tekshirish", admin="✉️ Adminga xabar",
        ask_check="Tekshirish uchun havola (link) yuboring yoki APK/fayl tashlang (20 MB gacha).",
        ask_admin="Adminga xabaringizni yozing:", sent="✅ Xabar adminga yuborildi.",
        wait="⏳ Tekshirilmoqda, 1-2 daqiqa kuting...", back="⬅️ Orqaga",
        safe="✅ Xavfli narsa topilmadi. Ishlatishingiz mumkin.\n\n",
        danger="🚨 DIQQAT! Xavfli! Bu havola/fayl kiber hujum yoki zararli dastur bo'lishi mumkin. Ochmang va o'rnatmang!\n\n",
        bad_input="Faqat havola yoki fayl yuboring.", big="Fayl 20 MB dan katta, tekshirib bo'lmaydi.",
        err="Xatolik yuz berdi, keyinroq urinib ko'ring.",
        note="\n\nℹ️ Hech qaysi tekshiruv 100% kafolat bermaydi. Shubha bo'lsa, ishlatmang."),
    "ru": dict(
        menu="Выберите раздел:", check="🔍 Проверка", admin="✉️ Написать админу",
        ask_check="Отправьте ссылку или файл/APK для проверки (до 20 МБ).",
        ask_admin="Напишите сообщение админу:", sent="✅ Сообщение отправлено админу.",
        wait="⏳ Идёт проверка, подождите 1-2 минуты...", back="⬅️ Назад",
        safe="✅ Угроз не найдено. Можно использовать.\n\n",
        danger="🚨 ВНИМАНИЕ! Опасно! Это может быть кибератака или вредоносная программа. Не открывайте и не устанавливайте!\n\n",
        bad_input="Отправьте только ссылку или файл.", big="Файл больше 20 МБ, проверить нельзя.",
        err="Произошла ошибка, попробуйте позже.",
        note="\n\nℹ️ Ни одна проверка не даёт 100% гарантии. При сомнениях не используйте."),
    "en": dict(
        menu="Choose a section:", check="🔍 Check", admin="✉️ Message admin",
        ask_check="Send a link, or upload an APK/file to check (up to 20 MB).",
        ask_admin="Write your message to the admin:", sent="✅ Message sent to the admin.",
        wait="⏳ Checking, please wait 1-2 minutes...", back="⬅️ Back",
        safe="✅ No threats found. You can use it.\n\n",
        danger="🚨 WARNING! Dangerous! This may be a cyber attack or malware. Do not open or install it!\n\n",
        bad_input="Please send only a link or a file.", big="File is over 20 MB, cannot be checked.",
        err="Something went wrong, try again later.",
        note="\n\nℹ️ No scan gives a 100% guarantee. If in doubt, don't use it."),
}

db = sqlite3.connect("users.db")
db.execute("create table if not exists u(id integer primary key, lang text)")


def get_lang(uid):
    r = db.execute("select lang from u where id=?", (uid,)).fetchone()
    return r[0] if r else "uz"


def set_lang(uid, lang):
    db.execute("insert or replace into u values(?,?)", (uid, lang))
    db.commit()


class S(StatesGroup):
    checking = State()
    admin = State()


router = Router()


def kb_lang():
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🇺🇿 O'zbekcha", callback_data="lang:uz"),
        InlineKeyboardButton(text="🇷🇺 Русский", callback_data="lang:ru"),
        InlineKeyboardButton(text="🇬🇧 English", callback_data="lang:en")]])


def kb_menu(lang):
    t = TXT[lang]
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t["check"], callback_data=f"m:check:{lang}")],
        [InlineKeyboardButton(text=t["admin"], callback_data=f"m:admin:{lang}")]])


def kb_back(lang):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=TXT[lang]["back"], callback_data=f"m:menu:{lang}")]])


# ---------- VirusTotal ----------
VT = "https://www.virustotal.com/api/v3"
H = {"x-apikey": VT_KEY}


async def vt_wait(c, analysis_id):
    for _ in range(25):
        r = await c.get(f"{VT}/analyses/{analysis_id}", headers=H)
        a = r.json()["data"]["attributes"]
        if a["status"] == "completed":
            return a["stats"]
        await asyncio.sleep(6)
    return None


async def scan_url(url):
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f"{VT}/urls", headers=H, data={"url": url})
        r.raise_for_status()
        return await vt_wait(c, r.json()["data"]["id"])


async def scan_file(path):
    with open(path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    async with httpx.AsyncClient(timeout=180) as c:
        r = await c.get(f"{VT}/files/{sha}", headers=H)  # avval hash bo'yicha qidiramiz
        if r.status_code == 200:
            return r.json()["data"]["attributes"]["last_analysis_stats"]
        with open(path, "rb") as f:
            r = await c.post(f"{VT}/files", headers=H, files={"file": (os.path.basename(path), f)})
        r.raise_for_status()
        return await vt_wait(c, r.json()["data"]["id"])


def apk_info(path):
    try:
        from androguard.core.apk import APK
        a = APK(path)
        return {"package": a.get_package(), "app_name": a.get_app_name(),
                "permissions": a.get_permissions()[:40]}
    except Exception:
        return None


async def ai_explain(lang, kind, target, stats, info):
    prompt = (
        f"You are a cybersecurity assistant inside a Telegram bot. Reply in {LANGS[lang]}, "
        f"max 120 words, plain text, no markdown.\n"
        f"Item type: {kind}\nItem: {target}\nVirusTotal stats: {stats}\nAPK info: {info}\n"
        "Explain what this item is and what it contains. For an APK, explain what the app "
        "can do based on its permissions and flag risky ones (SMS, accessibility, device admin, "
        "overlay, install packages). If the scan found threats, explain the likely risk. "
        "Never claim it is 100% safe."
    )
    r = await ai.aio.models.generate_content(model=MODEL, contents=prompt)
    return r.text or ""


# ---------- Handlerlar ----------
@router.message(CommandStart())
async def start(m: Message, state: FSMContext):
    await state.clear()
    await m.answer("🌐 Tilni tanlang / Выберите язык / Choose language:", reply_markup=kb_lang())


@router.callback_query(F.data.startswith("lang:"))
async def pick_lang(cb: CallbackQuery):
    lang = cb.data.split(":")[1]
    set_lang(cb.from_user.id, lang)
    t = TXT[lang]
    await cb.message.edit_text(t["menu"], reply_markup=kb_menu(lang))


@router.callback_query(F.data.startswith("m:"))
async def menu(cb: CallbackQuery, state: FSMContext):
    parts = cb.data.split(":")
    action = parts[1]
    lang = parts[2] if len(parts) > 2 else get_lang(cb.from_user.id)
    set_lang(cb.from_user.id, lang)
    t = TXT[lang]
    if action == "check":
        await state.set_state(S.checking)
        await cb.message.edit_text(t["ask_check"], reply_markup=kb_back(lang))
    elif action == "admin":
        await state.set_state(S.admin)
        await cb.message.edit_text(t["ask_admin"], reply_markup=kb_back(lang))
    else:
        await state.clear()
        await cb.message.edit_text(t["menu"], reply_markup=kb_menu(lang))
    await cb.answer()


@router.message(S.admin)
async def to_admin(m: Message, state: FSMContext, bot: Bot):
    lang = get_lang(m.from_user.id)
    t = TXT[lang]
    u = m.from_user
    await bot.send_message(ADMIN_ID, f"📩 {u.full_name} (@{u.username}) id={u.id}\nJavob: /reply {u.id} matn")
    await m.copy_to(ADMIN_ID)
    await state.clear()
    await m.answer(t["sent"], reply_markup=kb_menu(lang))


@router.message(Command("reply"), F.from_user.id == ADMIN_ID)
async def admin_reply(m: Message, bot: Bot):
    parts = (m.text or "").split(maxsplit=2)
    if len(parts) < 3:
        return await m.answer("/reply <user_id> <matn>")
    await bot.send_message(int(parts[1]), f"👨‍💻 Admin:\n{parts[2]}")
    await m.answer("✅")


@router.message(S.checking)
async def check(m: Message, bot: Bot):
    lang = get_lang(m.from_user.id)
    t = TXT[lang]
    url_match = re.search(r"https?://\S+", m.text or "")
    if not url_match and not m.document:
        return await m.answer(t["bad_input"])
    if m.document and m.document.file_size > MAX_FILE:
        return await m.answer(t["big"])

    wait = await m.answer(t["wait"])
    try:
        info = None
        if url_match:
            target, kind = url_match.group(0), "link"
            stats = await scan_url(target)
        else:
            target, kind = m.document.file_name, "file"
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "f.bin")
                await bot.download(m.document, destination=path)
                stats = await scan_file(path)
                if target.lower().endswith(".apk"):
                    kind, info = "APK", apk_info(path)
        if stats is None:
            raise RuntimeError("scan timeout")

        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        dangerous = bad >= 1  # xohlasangiz chegarani 2-3 ga oshiring (false-positive kamayadi)
        explanation = await ai_explain(lang, kind, target, stats, info)
        head = t["danger"] if dangerous else t["safe"]
        stat_line = f"🛡 VirusTotal: {bad} / {sum(stats.values())}\n\n"
        await wait.edit_text(head + stat_line + explanation + t["note"])
    except Exception:
        logging.exception("check failed")
        await wait.edit_text(t["err"])
    await m.answer(t["menu"], reply_markup=kb_menu(lang))


BASE_URL = os.getenv("RENDER_EXTERNAL_URL") or os.getenv("BASE_URL")
SECRET = hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:32]


def run_webhook():
    from aiohttp import web
    from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application

    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    async def on_startup(bot: Bot):
        await bot.set_webhook(f"{BASE_URL}/webhook", secret_token=SECRET)

    dp.startup.register(on_startup)
    app = web.Application()
    app.router.add_get("/", lambda r: web.Response(text="ok"))  # Render sog'liq tekshiruvi
    SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=SECRET).register(app, path="/webhook")
    setup_application(app, dp, bot=bot)
    web.run_app(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))


async def run_polling():
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    await bot.delete_webhook()
    await dp.start_polling(bot)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if BASE_URL:
        run_webhook()
    else:
        asyncio.run(run_polling())
