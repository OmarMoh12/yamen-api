import requests
import urllib3
import warnings
import json
import asyncio
from twocaptcha import TwoCaptcha
from flask import Flask, request, jsonify
from telethon import TelegramClient
from telethon.sessions import MemorySession
from telethon.errors import PhoneNumberBannedError, PhoneNumberInvalidError


app = Flask(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

API_ID = 8858737
API_HASH = "728f6774ed815ff313eb2f7fc3b9096f"
TWO_CAPTCHA_API_KEY = "7e412dee99e4fd1ebc5b0bb88bc92e8e"


def create_account_with_proxy(email, proxy):
    headers = {
        'authority': '2no.pl',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/json',
        'origin': 'https://2nd-no.com',
        'referer': 'https://2nd-no.com/',
        'sec-ch-ua': '"Chromium";v="139", "Not;A=Brand";v="99"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    }

    if ':' not in proxy:
        return 'invalid proxy format'

    ip, port = proxy.split(":")
    types = [
        ('SOCKS5', f'socks5://{ip}:{port}'),
        ('SOCKS4', f'socks4://{ip}:{port}'),
        ('HTTP', f'http://{ip}:{port}')
    ]
    for type_name, proxy_url in types:
        try:
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

            json_data = {
                'id': 103,
                'query': {
                    'email': email,
                    'password': 'Roq9@#',
                },
            }

            response = requests.post(
                'https://2no.pl/',
                headers=headers,
                json=json_data,
                proxies=proxies,
                timeout=10,
                verify=False
            )

            response_text = response.text.replace(" ", "")

            if '"success":true' in response_text:
                return {"status": "success", "proxy_type": type_name}
            elif '"error":"EmailExists"' in response_text:
                return {"status": "exists"}

        except Exception as e:
            continue

    return {"status": "failed", "reason": "All proxy types failed"}

def get_number():
    headers = {
        'authority': '2no.pl',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/json',
        'origin': 'https://2nd-no.com',
        'referer': 'https://2nd-no.com/',
        'sec-ch-ua': '"Chromium";v="139", "Not;A=Brand";v="99"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36',
        'X-Auth-Token': '34102ac01fb88e7234ed98f6e06f86c2e40f37d3103f7c2cb2b20555388169da',
    }

    payload = {
        'id': 310,
    }
    while True:
        try:
            response = requests.post('https://2no.pl/', headers=headers, json=payload)
            data = response.json()
            number = '+48' + data['result'][0]['number']
            number_id = data['result'][0]['id']
            return {'number': number, 'number_id': number_id}
        except:
            continue

def login(email: str, password: str):
    url = "https://2no.pl"
    payload = {
        "id": 101,
        "query": {
            "email": email,
            "password": password
        }
    }
    headers = {
        'authority': '2no.pl',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/json',
        'origin': 'https://2nd-no.com',
        'referer': 'https://2nd-no.com/',
        'sec-ch-ua': '"Chromium";v="139", "Not;A=Brand";v="99"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36',
    }
    try:
        response =  requests.post(url=url, headers=headers, json=payload)

        if response.status_code == 200:
            try:
                user_numbers = len(response.json()['badges']['user_numbers'])
            except:
                user_numbers = 0
            number_limit = response.json().get("number_limit")
            x_auth_token = response.json().get("token")
            return {'x_auth_token': x_auth_token, 'number_limit': number_limit, 'user_numbers': user_numbers, 'status': True}
    except Exception as e:
        return {'status': False}

def solver_captcha():
    while True:
        solver = TwoCaptcha(TWO_CAPTCHA_API_KEY)
        try:
            result = solver.turnstile(
                sitekey='0x4AAAAAAAh6YYTPTzEcN3Ep',
                url='https://2nd-no.com/app/numbers'
            )
            response_key = result['code']
            return {'response_key': response_key}
        except:
            continue

def confirm_account(email, token):
    url = "https://2no.pl"
    payload = {
        "id": 104,
        "query": {
            "email": email,
            "token": token
        }
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36',
        'Accept': "application/json, text/plain, */*",
        'Content-Type': "application/json",
        'sec-fetch-site': "cross-site",
        'origin': "https://2nd-no.com",
        'sec-fetch-mode': "cors",
        'referer': "https://2nd-no.com/",
        'sec-fetch-dest': "empty",
        'accept-language': "ar",
        'priority': "u=3, i"
    }
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
        if '"success":true' in response.text:
            return {'status': True}            
        else:
            return {'status': False}
    except Exception as e:
        return {'status': False}
def add_number(token: str, response_key: str, number_id: int):
    url = "https://2no.pl"

    payload = {
        "id": 301,
        "query": {
            "number_id": number_id,
            "name": "@aa2222a",
            "color": "#4893EC",
            "response_key": response_key,
            "availability_days": [1, 2, 3, 4, 5, 6, 7],
            "hour_from": "00:00:00.000Z",
            "hour_to": "23:59:59.999Z",
            "right_to_transfer_number": True,
            "marketing": True
        }
    }

    headers = {
        'authority': '2no.pl',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/json',
        'origin': 'https://2nd-no.com',
        'referer': 'https://2nd-no.com/',
        'sec-ch-ua': '"Chromium";v="139", "Not;A=Brand";v="99"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'x-auth-token': token,
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36',
    }

    response = requests.post(url, json=payload, headers=headers)
    try:
        error = response.json().get('error')
        if error == 1010:
            return {'status': 'response key Invalid'}
        elif 'Reserve number' in error:
            return {'status': 'Account full account'}

        return {'status': error}
    except:
        return {'status': 'success'}

async def check_number(number):
    client = TelegramClient(MemorySession(), API_ID, API_HASH)

    try:
        await client.connect()
        await client.send_code_request(number)
        return {'status': 'Valid'}
    except PhoneNumberBannedError:
        return {'status': 'Banned'}
    except PhoneNumberInvalidError:
        return {'status': 'Invalid'}
    finally:
        await client.disconnect()


@app.route("/", methods=["POST"])
def create():
    data = request.json
    email = data.get('email')
    proxy = data.get('proxy')

    if not email or not proxy:
        return jsonify({"error": "Missing email or proxy"}), 400

    result = create_account_with_proxy(email, proxy)
    return jsonify(result)

@app.route("/get_number", methods=["GET"])
def number():
    result = get_number()
    return jsonify(result)

@app.route("/login", methods=["POST"])
def do_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    result = login(email, password)
    return jsonify(result)
@app.route("/solver_captcha", methods=["GET"])
def do_captcha():
    response_key = solver_captcha()
    return jsonify(response_key)

@app.route("/confirm_account", methods=["POST"])
def confirm():
    data = request.json
    email = data.get('email')
    token = data.get('token')

    if not email or not token:
        return jsonify({"error": "Missing email or token"}), 400

    result = confirm_account(email, token)
    return jsonify(result)

@app.route("/add_number", methods=["POST"])
def add():
    data = request.json
    response_key = data.get('response_key')
    token = data.get('token')
    number_id = data.get('number_id')

    if not response_key or not token or not number_id:
        return jsonify({"error": "Missing response_key or token or number_id"}), 400

    result = add_number(token , response_key , number_id)
    return jsonify(result)

@app.route("/check_number", methods=["POST"])
def chk_number():
    data = request.json
    number = data.get('number')

    if not number:
        return jsonify({"error": "Missing number"}), 400

    result = asyncio.run(check_number(number))
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
