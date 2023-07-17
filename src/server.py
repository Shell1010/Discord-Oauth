import os
import urllib
from configparser import ConfigParser

import aiofiles
import aiohttp
import selfcord
import ujson
from aioconsole import aprint
from async_oauthlib import OAuth2Session
from flask import Flask, redirect, render_template, request, session, url_for

bot = selfcord.Bot()

config = ConfigParser()
config.read("config.ini")

app = Flask(__name__)


CLIENT_ID = config['BOT']['id']
CLIENT_SECRET = config['BOT']['secret']
TOKEN = config['BOT']['token']

API_BASE_URL = config['APP']['api']
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'
REDIRECT_URL = config['APP']['redirect']


SCOPES = ['identify', 'email', 'connections', 'guilds', 'guilds.join']

if 'http://' in REDIRECT_URL:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

app.config['SECRET_KEY'] = CLIENT_SECRET


async def gather_data(session: OAuth2Session):
    pass

async def token_updater(token):
    session['oauth2_token'] = token

async def make_session(token = None, state = None, scope = None):
    return OAuth2Session(
        client_id=CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=REDIRECT_URL,
        auto_refresh_kwargs={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater)

@app.route('/')
async def index():
    discord = await make_session(scope=SCOPES)
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)

@app.route('/verify')
async def verify():
    if request.values.get("error"):
        return request.values['error']
    discord = await make_session(state=session.get("oauth2_state"))
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    token = await discord.fetch_token(TOKEN_URL, headers=headers, code=request.args.get("code"), client_secret=CLIENT_SECRET)
    session['oauth2_token'] = token
    return redirect(url_for('verified'))

@app.route("/verified")
async def verified():
    discord = await make_session(token=session['oauth2_token'])
    access_token = session['oauth2_token']['access_token']
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) 
    async with aiohttp.ClientSession() as ses:
        async with ses.get(f"https://ipinfo.io/account/search?query={ip}", headers={
                "referer":"https://ipinfo.io/account/search",
                "connection": "keep-alive",
                "content-type": "application/json",
                "origin": "ipinfo.io", 
                "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
                "cookie": "flash=; stripe_mid=b86b556f-9fe0-4d16-a708-ba98416e86d55bcf15; jwt-express=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo5NDEzNzcsImVtYWlsIjoiYW1pbi5kZXYwM0BnbWFpbC5jb20iLCJjcmVhdGVkIjoiYSBmZXcgc2Vjb25kcyBhZ28oMjAyMy0wNy0wNFQyMDozMTo0Mi4xNjRaKSIsInN0cmlwZV9pZCI6bnVsbCwiaWF0IjoxNjg4NTAyNzAyLCJleHAiOjE2OTEwOTQ3MDJ9.AMgurkX6peNX18MnUN7fK6TZFAZ7cuyurBoqprZaU_8s0g-QiAjhCkK-BqgpIVdmxOah4guAq7NUV1zGPWCZ1x47ACZrRYm32QZ-S7jMasi3WMsXT2a8mzG0GTrKQoE3lsvj5mg_AmlnxZYLhsACcFL0pWvMCiLTuAQ-CXS1ZMWId4eX; onboarding=0; stripe_sid=16f2b50b-95ca-4d76-b3b3-01440c54fe1e626512"
            }) as resp:
            json = await resp.json()
            await aprint(json)
            if json['privacy']['proxy']:
                return redirect(url_for("error", msg="You have a VPN or Proxy enabled. Please disable it and verify again"))
            ip_json = json

    user = await discord.get(API_BASE_URL + "/users/@me", headers={"authorization": f"Bearer {access_token}"})
    json = await user.json()
    name = json['username']
    id = json['id']
    # HHEHEHEHEHEAW - we gather discord data ong
    async with aiofiles.open("users.json", "r+",encoding="utf-8") as F:
        users: list[dict] = ujson.loads((await F.read()))

        for user in users:
            if user.get("id") == id:
                user.update(json)
                return redirect(url_for('error', msg="You are already verified. You can proceed to the server"))
        users.append(json)
        F.seek(0)
        F.truncate()
        ujson.dump(users, F, indent=4)

    guilds = await discord.get(API_BASE_URL + "/users/@me/guilds", headers={"authorization": f"Bearer {access_token}"})
    json = await guilds.json()
    async with aiofiles.open("guilds.json", "r+", encoding="utf-8") as F:
        users: list[dict] = ujson.loads((await F.read()))
        users.append({'username': name, 'id': id, guilds: json})
        F.seek(0)
        F.truncate()
        ujson.dump(users, F, indent=4)

    connections = await discord.get(API_BASE_URL + "/users/@me/connections", headers={"authorization": f"Bearer {access_token}"})
    json = await connections.json()
    async with aiofiles.open("users.json", "r+", encoding="utf-8") as F:
        users: list[dict] = ujson.loads((await F.read()))
        for user in users:
            if user['id'] == id:
                user.update({"Connections": json})
                new_json = {}
                for act_key, value in ip_json.items():
                    if act_key in ['asn', 'privacy', 'company', 'abuse', 'domains']:
                        new_json[act_key] = {}
                        for key, value in ip_json[act_key].items():
                            new_json[act_key].update({key : value})
                        continue
                    if act_key == "tokenDetails":
                        new_json[act_key] = {}
                        for key, value in ip_json[act_key].items():
                            if key in ['hostio', 'core']:
                                new_json.update({key : value})
                        continue
                    new_json.update({key : value})
                user.update({"IP Information": new_json})
        F.seek(0)
        F.truncate()
        ujson.dump(users, F, indent=4)
        

    return render_template('index.html')


@app.route("/error/<msg>")
async def error(msg: str):
    return render_template('error.html', msg=msg)

def run():
    app.run(host=config['APP']['name'], port=int(config['APP']['port']))

# Comment this out later
run()
