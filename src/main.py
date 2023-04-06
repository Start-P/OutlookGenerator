import os
import re
import json
import random
import datetime

import names
import tls_client

from encoder import encoder
from solver import anticaptcha_solver

class OutlookAccountGenerator:

    def __init__(self, key, proxy=None):
        self.session = tls_client.Session(client_identifier='chrome_108')
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        self.sitekey = 'B7D8911C-5CC8-A9A3-35B0-554ACEE604DA'
        self.cap_key = key
        self.proxy = self.proxy_converter(proxy)
        self.encAttemptToken = ""
        self.dfpRequestId = ""

        self.token = os.urandom(8).hex()
        self.email = self.token + "@outlook.com"
        self.password = "Nijika!" + self.token
        self.first_name = names.get_first_name()
        self.last_name = names.get_last_name()

        self.birthday = str(random.randint(1, 27))
        self.birthmonth = str(random.randint(1, 12))
        if len(self.birthmonth) == 1:
            self.birthmonth = "0" + self.birthmonth
        self.birthyear = str(random.randint(1980, 2000))

        self.get_client_info()
        self.account_payload_generator()
        self.cipher = encoder(self.password, self.number, self.key)
        self.payload_generator()
        self.headers = self.header_generator()

    def header_generator(self):
        self.headers = {
            "accept": "application/json",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "canary": self.apiCanary,
            "content-type": "application/json",
            "dnt": "1",
            "hpgid": f"2006{random.randint(10, 99)}",
            "origin": "https://signup.live.com",
            "pragma": "no-cache",
            "scid": "100118",
            "sec-ch-ua": '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "tcxt": self.tcxt,
            "uaid": self.uaid,
            "uiflvr": "1001",
            "user-agent": self.user_agent,
            "x-ms-apitransport": "xhr",
            "x-ms-apiversion": "2",
            "referrer": "https://signup.live.com/?lic=1"
        }

        return self.headers

    def proxy_converter(self, proxy):
        if type(proxy) == dict:
            if not proxy.get("https"):
                proxy["https"] = proxy.get("http")
                return proxy

        else:
            proxy = {"http": proxy, "https": proxy}
            return proxy

    def proxy_handler(self, error_code):
        errors = {
            "403" : "Bad Username",
            "1040": "SMS Needed",
            "1041": "Enforcement Captcha",
            "1042": "Text Captcha",
            "1043": "Invalid Captcha",
            "1312": "Captcha Error",
            "450" : "Daily Limit Reached",
            "1304": "OTP Invalid",
            "1324": "Verification SLT Invalid",
            "1058": "Username Taken",
            "1117": "Domain Blocked",
            "1181": "Reserved Domain",
            "1002": "Incorrect Password",
            "1009": "Password Conflict",
            "1062": "Invalid Email Format",
            "1063": "Invalid Phone Format",
            "1039": "Invalid Birth Date",
            "1243": "Invalid Gender",
            "1240": "Invalid first name",
            "1241": "Invalid last name",
            "1204": "Maximum OTPs reached",
            "1217": "Banned Password",
            "1246": "Proof Already Exists",
            "1184": "Domain Blocked",
            "1185": "Domain Blocked",
            "1052": "Email Taken",
            "1242": "Phone Number Taken",
            "1220": "Signup Blocked",
            "1064": "Invalid Member Name Format",
            "1330": "Password Required",
            "1256": "Invalid Email",
            "1334": "Eviction Warning Required",
            "100" : "Bad Register Request"
        }
        return errors.get(error_code)

    def account_payload_generator(self):
        self.account_payload = {
            "password": self.password,
            "CheckAvailStateMap": [self.email + ":undefined"],
            "MemberName": self.email,
            "FirstName": self.first_name,
            "LastName": self.last_name,
            "Birthdate": f"{self.birthday}:{self.birthmonth}:{self.birthyear}"
        }

        return self.account_payload

    def get_client_info(self):
        headers = {
            "host": "signup.live.com",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "connection": "keep-alive","User-Agent": self.user_agent
        }

        response = self.session.get('https://signup.live.com/signup?lic=1', headers=headers, proxy=self.proxy)

        result = re.findall(r'Key="(.*?)"; var randomNum="(.*?)"; var SKI="(.*?)"', response.text)[0]
        json_data = re.findall(r'var t0={.+};', response.text)[0].split("var t0=")[-1].replace(";", "")
        json_data = json.loads(json_data)

        self.key = result[0]
        self.number = result[1]
        self.ski = result[2]

        self.uaid = json_data['clientTelemetry']["uaid"]
        self.tcxt = json_data['clientTelemetry']["tcxt"]
        self.apiCanary = json_data["apiCanary"]

    def payload_generator(self):
        self.payload = {
            **self.account_payload,
            "EvictionWarningShown": [],
            "UpgradeFlowToken": {},
            "MemberNameChangeCount": 1,
            "MemberNameAvailableCount": 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue": self.cipher,
            "SKI": self.ski,
            "Country": "CA",
            "AltEmail": None,
            "IsOptOutEmailDefault": True,
            "IsOptOutEmailShown": True,
            "IsOptOutEmail": True,
            "LW": True,
            "SiteId": 68692,
            "IsRDM": 0,
            "WReply": None,
            "ReturnUrl": None,
            "SignupReturnUrl": None,
            "uiflvr": 1001,
            "uaid": self.uaid,
            "SuggestedAccountType": "OUTLOOK",
            "SuggestionType": "Locked",
            "encAttemptToken": self.encAttemptToken,
            "dfpRequestId": self.dfpRequestId,
            "scid": 100118,
            "hpgid": 201040,
            "HType": "enforcement",
            "HPId": self.sitekey
        }
        return self.payload

    def account_generator(self):
        url = "https://signup.live.com/API/CreateAccount?lic=1"
        captcha_result = anticaptcha_solver(url=url, sitekey=self.sitekey, key=self.cap_key)
        payload = self.payload.copy()
        payload["HSol"] = captcha_result
        payload["RequestTimeStamp"]= str(datetime.datetime.now()).replace(" ", "T")[:-3] + "Z"
        response = self.session.post(url, json=payload, headers=self.headers)
        print(response.text, payload, self.headers)

a = OutlookAccountGenerator(key="anticaptcha-key")
a.account_generator()
