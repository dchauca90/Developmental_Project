import hmac
import hashlib
import os
import uuid
import time
import random
import matplotlib.pyplot as plt


class Session:
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.challenge = os.urandom(16)
        self.created_time = time.time()


class Device:
    def __init__(self, device_id):
        self.device_id = device_id
        self.key = b"secret_key"

    def sign(self, data):
        return hmac.new(self.key, data, hashlib.sha256).digest()


def is_session_still_valid(session, max_time_allowed):
    current_time = time.time()
    time_used = current_time - session.created_time

    if time_used <= max_time_allowed:
        return True
    else:
        return False


# weak binding: only signs the challenge
def weak_login(device, session):
    return device.sign(session.challenge)


def weak_check(device, session, sig):
    correct_sig = device.sign(session.challenge)
    return hmac.compare_digest(sig, correct_sig)


# medium binding: signs challenge + session id
def medium_login(device, session):
    data = session.challenge + session.id.encode()
    return device.sign(data)


def medium_check(device, session, sig):
    data = session.challenge + session.id.encode()
    correct_sig = device.sign(data)
    return hmac.compare_digest(sig, correct_sig)


# strong binding: signs challenge + session id + device id
def strong_login(device, session):
    data = session.challenge + session.id.encode() + device.device_id.encode()
    return device.sign(data)


def strong_check(device, session, sig):
    data = session.challenge + session.id.encode() + device.device_id.encode()
    correct_sig = device.sign(data)
    return hmac.compare_digest(sig, correct_sig)


def test_weak(device):
    session1 = Session()
    session2 = Session()

    # attacker reuses the same challenge
    session2.challenge = session1.challenge

    sig = weak_login(device, session1)

    delay_time = random.uniform(0, 2)
    time.sleep(delay_time)

    max_time_allowed = 1.0

    if is_session_still_valid(session2, max_time_allowed) == False:
        return False

    return weak_check(device, session2, sig)


def test_medium(device):
    session1 = Session()
    session2 = Session()

    # attacker reuses the same challenge
    session2.challenge = session1.challenge

    sig = medium_login(device, session1)

    delay_time = random.uniform(0, 2)
    time.sleep(delay_time)

    max_time_allowed = 1.0

    if is_session_still_valid(session2, max_time_allowed) == False:
        return False

    return medium_check(device, session2, sig)


def test_strong(device):
    session1 = Session()
    session2 = Session()

    # attacker reuses the same challenge
    session2.challenge = session1.challenge

    sig = strong_login(device, session1)

    delay_time = random.uniform(0, 2)
    time.sleep(delay_time)

    max_time_allowed = 1.0

    if is_session_still_valid(session2, max_time_allowed) == False:
        return False

    return strong_check(device, session2, sig)


if __name__ == "__main__":
    device = Device("phone1")

    trials = 100

    weak_success = 0
    medium_success = 0
    strong_success = 0

    for i in range(trials):
        if test_weak(device):
            weak_success += 1

        if test_medium(device):
            medium_success += 1

        if test_strong(device):
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
    plt.title("Weak vs Medium vs Strong Session Binding with Delay")
    plt.ylim(0, 110)

    plt.grid(axis="y", linestyle="--", linewidth=1, alpha=0.7)

    for i in range(len(rates)):
        plt.text(i, rates[i] + 3, f"{rates[i]:.1f}%", ha="center")

    plt.tight_layout()
    plt.savefig("binding_with_delay_result.png", dpi=300)
    plt.show()
