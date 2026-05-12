import socket
import os
import uuid
import hmac
import hashlib
import time
import random
import matplotlib.pyplot as plt


PI_IP = "192.168.1.91"
PI_PORT = 5000

DEVICE_ID = "raspberrypi1"
SECRET_KEY = b"secret_key"


class Session:
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.challenge = os.urandom(16)
        self.created_time = time.time()


def local_sign(data):
    return hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()


def is_session_still_valid(session, max_time_allowed):
    current_time = time.time()
    time_used = current_time - session.created_time

    if time_used <= max_time_allowed:
        return True
    else:
        return False


def get_signature_from_pi(mode, session):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to:", PI_IP, PI_PORT)

    client.connect((PI_IP, PI_PORT))

    message = mode + "|" + session.challenge.hex() + "|" + session.id

    client.send(message.encode())

    signature = client.recv(4096).decode()

    client.close()

    return signature


def weak_check(session, sig):
    expected = local_sign(session.challenge)
    return hmac.compare_digest(sig, expected)


def medium_check(session, sig):
    expected_data = session.challenge + session.id.encode()
    expected = local_sign(expected_data)
    return hmac.compare_digest(sig, expected)


def strong_check(session, sig):
    expected_data = session.challenge + session.id.encode() + DEVICE_ID.encode()
    expected = local_sign(expected_data)
    return hmac.compare_digest(sig, expected)


def test_weak():
    session1 = Session()
    session2 = Session()

    # attacker reuses the same challenge
    session2.challenge = session1.challenge

    sig = get_signature_from_pi("weak", session1)

    delay_time = random.uniform(0, 2)
    time.sleep(delay_time)

    max_time_allowed = 1.0

    if is_session_still_valid(session2, max_time_allowed) == False:
        return False

    return weak_check(session2, sig)


def test_medium():
    session1 = Session()
    session2 = Session()

    # attacker reuses the same challenge
    session2.challenge = session1.challenge

    sig = get_signature_from_pi("medium", session1)

    delay_time = random.uniform(0, 2)
    time.sleep(delay_time)

    max_time_allowed = 1.0

    if is_session_still_valid(session2, max_time_allowed) == False:
        return False

    return medium_check(session2, sig)


def test_strong():
    session1 = Session()
    session2 = Session()

    # attacker reuses the same challenge
    session2.challenge = session1.challenge

    sig = get_signature_from_pi("strong", session1)

    delay_time = random.uniform(0, 2)
    time.sleep(delay_time)

    max_time_allowed = 1.0

    if is_session_still_valid(session2, max_time_allowed) == False:
        return False

    return strong_check(session2, sig)


if __name__ == "__main__":
    trials = 20

    weak_success = 0
    medium_success = 0
    strong_success = 0

    for i in range(trials):
        if test_weak():
            weak_success += 1

        if test_medium():
            medium_success += 1

        if test_strong():
            strong_success += 1

    weak_rate = (weak_success / trials) * 100
    medium_rate = (medium_success / trials) * 100
    strong_rate = (strong_success / trials) * 100

    print("Weak binding attack successes:", weak_success, "out of", trials)
    print("Medium binding attack successes:", medium_success, "out of", trials)
    print("Strong binding attack successes:", strong_success, "out of", trials)

    print("Weak binding attack success rate:", weak_rate, "%")
    print("Medium binding attack success rate:", medium_rate, "%")
    print("Strong binding attack success rate:", strong_rate, "%")

    labels = ["Weak Binding", "Medium Binding", "Strong Binding"]
    rates = [weak_rate, medium_rate, strong_rate]

    plt.figure(figsize=(7, 4))
    plt.bar(labels, rates)

    plt.ylabel("Attack Success Rate (%)")
    plt.title("Weak vs Medium vs Strong Session Binding with Raspberry Pi Delay")
    plt.ylim(0, 110)

    plt.grid(axis="y", linestyle="--", linewidth=1, alpha=0.7)

    for i in range(len(rates)):
        plt.text(i, rates[i] + 3, f"{rates[i]:.1f}%", ha="center")

    plt.tight_layout()
    plt.savefig("pi_binding_with_delay_result.png", dpi=300)
    plt.show()