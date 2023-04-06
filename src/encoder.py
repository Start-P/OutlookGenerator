from execjs import compile


script = compile(open("assets/encode.js").read())
def encoder(password: str, randomNum: str, key: str):
    return script.call("encrypt", password, randomNum, key)
