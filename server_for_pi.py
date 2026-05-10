import socket
import hmac
import hashlib
import time
import random
import matplotlib.pyplot as plt


HOST = "0.0.0.0"
PORT = 5000

DEVICE_ID = "raspberrypi1"
SECRET_KEY = b"secret_key"


def sign_data(data):
    return hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Raspberry Pi device is waiting for connection...")


while True:
    conn, addr = server_socket.accept()
    print("Connected by:", addr)

    data = conn.recv(4096).decode()

    parts = data.split("|")

    mode = parts[0]
    challenge_hex = parts[1]
    session_id = parts[2]

    challenge = bytes.fromhex(challenge_hex)

    # this makes the Raspberry Pi behave more like real hardware
    device_delay = random.uniform(0.05, 0.3)
    time.sleep(device_delay)

    if mode == "weak":
        message = challenge

    elif mode == "medium":
        message = challenge + session_id.encode()

    else:
        message = challenge + session_id.encode() + DEVICE_ID.encode()

    signature = sign_data(message)

    conn.send(signature.encode())
    conn.close()