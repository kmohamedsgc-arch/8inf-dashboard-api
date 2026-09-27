"""
8INF Dashboard API — خدمة واحدة منفصلة تمامًا، مش هتلمس كود بوتاتك خالص.
بتاخد بس توكن كل بوت (زي باسورد) عشان تقرأ بياناته من ديسكورد مباشرة.
شغّلها كخدمة لوحدها (Railway/Render)، وبوتاتك تفضل شغالة زي ما هي على wispbyte من غير أي تعديل.
"""
import os
import json
import time
import asyncio
from pathlib import Path
from urllib.parse import urlencode

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")          # تطبيق تسجيل الدخول (منفصل عن البوتات)
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
ADMIN_SEED = [x.strip() for x in os.getenv("ADMIN_DISCORD_IDS", "").split(",") if x.strip()]
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
BOT_PERMISSIONS = os.getenv("BOT_INVITE_PERMISSIONS", "8")  # 8 = Administrator افتراضيًا، غيّرها لو عايز صلاحيات محددة

# ---- كل بوت عندك بتوكنه + client id بتاعه، من متغيرات البيئة BOT1_*, BOT2_*, ... ----
def _load_bots_from_env():
    bots = []
    i = 1
    while True:
        token = os.getenv(f"BOT{i}_TOKEN")
        client_id = os.getenv(f"BOT{i}_CLIENT_ID")
        if not token or not client_id:
            break
        bots.append({"name": os.getenv(f"BOT{i}_NAME", f"Bot {i}"), "client_id": client_id, "token": token})
        i += 1
    return bots

BOTS = _load_bots_from_env()

DB_PATH = Path(__file__).parent / "site_data.json"
_lock = asyncio.Lock()
_cache = {}  # key -> (value, expires_at)  — عشان منضربش Discord API كتير


async def cached(key, ttl_seconds, fetcher):
    now = time.time()
    if key in _cache and _cache[key][1] > now:
        return _cache[key][0]
    value = await fetcher()
    _cache[key] = (value, now + ttl_seconds)
    return value


DEFAULT_CONFIG = {
    "price": "9.99",
    "currency": "USD",
    "cycle": "monthly",
    "methods": [{"name": "PayPal", "link": "https://paypal.me/yourname"}],
    "lockedFeatures": ["Analytics", "Tickets", "Levels", "Permission Calculator", "Snowflake Tools"],
}


def _load():
    if not DB_PATH.exists():
        data = {"admins": ADMIN_SEED[:], "users": {}, "premium": {}, "site_config": DEFAULT_CONFIG.copy()}
        DB_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        return data
    data = json.loads(DB_PATH.read_text())
    for a in ADMIN_SEED:
        if a not in data.get("admins", []):
            data.setdefault("admins", []).append(a)
    data.setdefault("site_config", DEFAULT_CONFIG.copy())
    return data


async def _save(data):
    async with _lock:
        DB_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2))


app = FastAPI(title="8INF Dashboard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def sign_session(discord_id: str) -> str:
    return jwt.encode({"uid": discord_id, "exp": int(time.time()) + 7 * 24 * 3600}, JWT_SECRET, algorithm="HS256")


def require_auth(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "no_token")
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
        return payload["uid"]
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid_token")


def require_admin(discord_id: str, data: dict):
    if discord_id not in data.get("admins", []):
        raise HTTPException(403, "not_admin")


PERM_BITS = {
    "ADMINISTRATOR": 0x8, "BAN_MEMBERS": 0x4, "KICK_MEMBERS": 0x2,
    "MANAGE_GUILD": 0x20, "MANAGE_ROLES": 0x10000000,
    "MANAGE_CHANNELS": 0x10, "MANAGE_MESSAGES": 0x2000,
}


def decode_permissions(perm_int: int) -> dict:
    admin = bool(perm_int & PERM_BITS["ADMINISTRATOR"])
    return {k: admin or bool(perm_int & v) for k, v in PERM_BITS.items()}


async def discord_get(path: str, token: str, is_bot=False, params=None):
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"https://discord.com/api/v10{path}",
            headers={"Authorization": f"{'Bot' if is_bot else 'Bearer'} {token}"},
            params=params or {},
        )
        if r.is_error:
            return None
        return r.json()


# ---------------- OAuth2 (تسجيل دخول الموقع) ----------------
@app.get("/auth/discord/login")
def login():
    params = {
        "client_id": DISCORD_CLIENT_ID, "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code", "scope": "identify guilds", "prompt": "consent",
    }
    return RedirectResponse(f"https://discord.com/api/oauth2/authorize?{urlencode(params)}")


@app.get("/auth/discord/callback")
async def callback(code: str = None):
    if not code:
        raise HTTPException(400, "missing_code")
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID, "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code", "code": code, "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    token = token_res.json()
    if "access_token" not in token:
        raise HTTPException(500, f"discord_token_exchange_failed:{token}")

    me = await discord_get("/users/@me", token["access_token"])
    avatar = (
        f"https://cdn.discordapp.com/avatars/{me['id']}/{me['avatar']}.png" if me.get("avatar")
        else f"https://cdn.discordapp.com/embed/avatars/{int(me.get('discriminator', 0)) % 5}.png"
    )
    data = _load()
    data.setdefault("users", {})[me["id"]] = {
        "access_token": token["access_token"], "refresh_token": token.get("refresh_token"),
        "expires_at": time.time() + token.get("expires_in", 604800),
        "username": me.get("global_name") or me["username"], "avatar": avatar,
    }
    await _save(data)
    return RedirectResponse(f"{FRONTEND_URL}?token={sign_session(me['id'])}")


# ---------------- API ----------------
@app.get("/api/me")
def me(authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    data = _load()
    u = data.get("users", {}).get(discord_id)
    if not u:
        raise HTTPException(404, "not_found")
    return {"id": discord_id, "username": u["username"], "avatar": u["avatar"], "isAdmin": discord_id in data.get("admins", [])}


async def _bot_guild_ids(bot):
    async def fetch():
        guilds = await discord_get("/users/@me/guilds", bot["token"], is_bot=True)
        return {g["id"] for g in guilds} if guilds else set()
    return await cached(f"botguilds:{bot['client_id']}", 60, fetch)


@app.get("/api/guilds")
async def guilds(authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    data = _load()
    u = data.get("users", {}).get(discord_id)
    if not u:
        raise HTTPException(404, "not_found")

    user_guilds = await discord_get("/users/@me/guilds", u["access_token"])
    manageable = [g for g in (user_guilds or []) if g.get("owner") or decode_permissions(int(g["permissions"]))["MANAGE_GUILD"]]

    bot_id_sets = [await _bot_guild_ids(b) for b in BOTS]
    out = []
    for g in manageable:
        our_bots_here = [BOTS[i]["name"] for i, ids in enumerate(bot_id_sets) if g["id"] in ids]
        out.append({
            "id": g["id"], "name": g["name"],
            "icon": f"https://cdn.discordapp.com/icons/{g['id']}/{g['icon']}.png" if g.get("icon") else None,
            "owner": g.get("owner", False),
            "permissions": decode_permissions(int(g["permissions"])),
            "hasBot": len(our_bots_here) > 0,
            "bots": our_bots_here,
        })
    return out


@app.get("/api/guilds/{guild_id}/commands")
async def guild_commands(guild_id: str, bot: int = 0, authorization: str = Header(None)):
    """bot=0 معناها أول بوت من بوتاتك المتاح في السيرفر ده. مرّر ?bot=1 للتاني وهكذا."""
    discord_id = require_auth(authorization)
    data = _load()
    u = data.get("users", {}).get(discord_id)
    if not u or not BOTS:
        raise HTTPException(400, "no_bots_configured")

    user_guilds = await discord_get("/users/@me/guilds", u["access_token"])
    guild_info = next((g for g in (user_guilds or []) if g["id"] == guild_id), None)
    if not guild_info:
        raise HTTPException(403, "not_your_guild")
    my_perms = decode_permissions(int(guild_info["permissions"]))

    present = [b for b in BOTS if guild_id in await _bot_guild_ids(b)]
    if not present or bot >= len(present):
        return []
    b = present[bot]

    cmds = await discord_get(f"/applications/{b['client_id']}/guilds/{guild_id}/commands", b["token"], is_bot=True)
    if cmds is None:
        cmds = await discord_get(f"/applications/{b['client_id']}/commands", b["token"], is_bot=True) or []

    result = []
    for c in cmds:
        needed = c.get("default_member_permissions")
        allowed = True
        if needed:
            needed_bits = decode_permissions(int(needed))
            allowed = all((not needed_bits[k]) or my_perms[k] for k in PERM_BITS)
        result.append({"name": c["name"], "description": c.get("description", ""), "allowed": allowed})
    return result


# ---------------- البوتات (صفحة "أضف بوت") ----------------
@app.get("/api/bots")
async def public_bots():
    out = []
    for b in BOTS:
        async def fetch(b=b):
            return await discord_get("/users/@me", b["token"], is_bot=True)
        info = await cached(f"botinfo:{b['client_id']}", 300, fetch)
        avatar = (
            f"https://cdn.discordapp.com/avatars/{info['id']}/{info['avatar']}.png"
            if info and info.get("avatar") else None
        )
        invite = (
            f"https://discord.com/api/oauth2/authorize?client_id={b['client_id']}"
            f"&scope=bot%20applications.commands&permissions={BOT_PERMISSIONS}"
        )
        out.append({"name": b["name"], "avatar": avatar, "inviteUrl": invite})
    return out


@app.get("/api/stats")
async def public_stats():
    all_guild_ids = set()
    total_members = 0
    for b in BOTS:
        ids = await _bot_guild_ids(b)
        for gid in ids:
            if gid in all_guild_ids:
                continue
            all_guild_ids.add(gid)

            async def fetch_count(gid=gid, b=b):
                g = await discord_get(f"/guilds/{gid}", b["token"], is_bot=True, params={"with_counts": "true"})
                return g.get("approximate_member_count", 0) if g else 0
            total_members += await cached(f"members:{gid}", 300, fetch_count)
    return {"servers": len(all_guild_ids), "members": total_members, "bots": len(BOTS)}


# ---------------- الإعدادات المشتركة (بتاعة صاحب الموقع بس) ----------------
@app.get("/api/site-config")
def get_site_config():
    return _load()["site_config"]


@app.put("/api/site-config")
async def set_site_config(payload: dict, authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    data = _load()
    require_admin(discord_id, data)
    data["site_config"] = {
        "price": str(payload.get("price", data["site_config"]["price"])),
        "currency": payload.get("currency", data["site_config"]["currency"]),
        "cycle": payload.get("cycle", data["site_config"]["cycle"]),
        "methods": payload.get("methods", data["site_config"]["methods"]),
        "lockedFeatures": payload.get("lockedFeatures", data["site_config"]["lockedFeatures"]),
    }
    await _save(data)
    return {"ok": True}


@app.get("/api/admins")
def list_admins(authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    data = _load()
    require_admin(discord_id, data)
    return [{"id": a, "username": data.get("users", {}).get(a, {}).get("username")} for a in data.get("admins", [])]


@app.post("/api/admins")
async def add_admin(payload: dict, authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    data = _load()
    require_admin(discord_id, data)
    new_id = str(payload.get("discordId", "")).strip()
    if not new_id:
        raise HTTPException(400, "missing_discordId")
    if new_id not in data["admins"]:
        data["admins"].append(new_id)
        await _save(data)
    return {"ok": True}


@app.delete("/api/admins/{admin_id}")
async def remove_admin(admin_id: str, authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    data = _load()
    require_admin(discord_id, data)
    data["admins"] = [a for a in data["admins"] if a != admin_id]
    await _save(data)
    return {"ok": True}


# ---------------- الدفع ----------------
@app.post("/api/billing/create-checkout")
async def create_checkout(payload: dict, authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    if not STRIPE_SECRET_KEY:
        raise HTTPException(400, "stripe_not_configured")
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    session = stripe.checkout.Session.create(
        mode="subscription", line_items=[{"price": payload["priceId"], "quantity": 1}],
        client_reference_id=discord_id, success_url=f"{FRONTEND_URL}?paid=1", cancel_url=FRONTEND_URL,
    )
    return {"url": session.url}


@app.get("/api/billing/status")
def billing_status(authorization: str = Header(None)):
    discord_id = require_auth(authorization)
    return {"premium": bool(_load().get("premium", {}).get(discord_id))}


@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    if not (STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET):
        raise HTTPException(400, "stripe_not_configured")
    import stripe
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, request.headers.get("stripe-signature"), STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(400, f"bad_signature: {e}")
    if event["type"] == "checkout.session.completed":
        discord_id = event["data"]["object"].get("client_reference_id")
        if discord_id:
            data = _load()
            data.setdefault("premium", {})[discord_id] = True
            await _save(data)
    return {"received": True}


@app.get("/")
def root():
    return JSONResponse({"status": "8INF dashboard API running", "bots_configured": len(BOTS)})
