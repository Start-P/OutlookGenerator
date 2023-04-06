import requests
import time
import sys

def anticaptcha_solver(url, sitekey, key):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    json_data = {
        'clientKey': key,
        'task': {
            'type': 'FunCaptchaTaskProxyless',
            'websiteURL': url,
            'websitePublicKey': sitekey,
            "funcaptchaApiJSSubdomain": "https://client-api.arkoselabs.com",
        },
        'softId': 0,
    }

    response = requests.post('https://api.anti-captcha.com/createTask', headers=headers, json=json_data)
    print(response.json(), key)
    task_id = response.json()["taskId"] 
    print('[/] Start Captcha Solving...')
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    json_data = {
        'clientKey': key,
        'taskId': task_id,
    }

    response = requests.post('https://api.anti-captcha.com/getTaskResult', headers=headers, json=json_data).json()
    while response["status"] != "ready":
        response = requests.post('https://api.anti-captcha.com/getTaskResult', headers=headers, json=json_data).json()
        time.sleep(1)
    print("[+] Captcha Solved!")
    return "|".join(response["solution"]["token"].split("|")[:2])
