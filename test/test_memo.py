import subprocess
import time
import socket
import pytest
import os
from threading import Thread
from memo_client import MemoClient

MEMO_HOST = "localhost"
MEMO_PORT = 5000
DATA_FILE = "./test/lorem_6k.txt"

def run_threads(*targets):
    """Start and join a list of thread target functions."""
    threads = [Thread(target=fn) for fn in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

def wait_for_memo(timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((MEMO_HOST, f"{MEMO_PORT}"), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Memo server did not start in time")

@pytest.fixture
def memo_server(request):
    """Starts up a Memo Server in a separate process."""
    env = os.environ.copy()
    if getattr(request, "param", None) == "partial_write":
        env["MEMO_PARTIAL_WRITE"] = "Y"
    proc = subprocess.Popen(
        ["./build/memod", f"{MEMO_PORT}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env)
    
    try:
        wait_for_memo()
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
        time.sleep(0.1)

def test_pub_sub_round_trip(memo_server):
    """The most basic test: subscribe and publish to a topic, all in the same process."""
    received = []

    def handle_news(client, topic, body):
        received.append((topic, body.decode()))

    with MemoClient() as client:
        client.subscribe("news", handle_news)
        client.publish("news", b"hello world")
        client.listen(timeout=1.0)

    assert received == [("news", "hello world")]

def test_pub_sub_multiple_subscribers(memo_server):
    """One publisher, two subscribers."""
    received_1 = []
    received_2 = []

    def subscriber1():
        with MemoClient() as client:
            client.subscribe("news", lambda c, t, b: received_1.append((t, b.decode())))
            client.listen(timeout=1.0)

    def subscriber2():
        with MemoClient() as client:
            client.subscribe("news", lambda c, t, b: received_2.append((t, b.decode())))
            client.listen(timeout=1.0)

    def publisher():
        time.sleep(0.1)
        with MemoClient() as client:
            client.publish("news", b"Hello subscribers!")

    run_threads(subscriber1, subscriber2, publisher)

    assert received_1 == [("news", "Hello subscribers!")]
    assert received_2 == [("news", "Hello subscribers!")]

def test_two_part_write(memo_server):
    """
    Publisher sends a message in two parts, two bytes then the rest. Part one
    does not contain the full header.
    """
    received = []

    def subscriber():
        with MemoClient() as client:
            client.subscribe("news", lambda c, t, b: received.append((t, b.decode())))
            client.listen(timeout=1.0)

    def publisher():
        time.sleep(0.1)
        with MemoClient() as client:
            msg = client.build_message_bytes(1, "news", b"Breaking news!")
            client.send_raw_data(msg[:2])
            time.sleep(0.1)
            client.send_raw_data(msg[2:])

    run_threads(subscriber, publisher)

    assert received == [("news", "Breaking news!")]

def test_two_part_write_two(memo_server):
    """
    Publisher sends a message in two parts, 71 bytes then the rest. Part one
    does contain the full header.
    """
    received = []

    def subscriber():
        with MemoClient() as client:
            client.subscribe("news", lambda c, t, b: received.append((t, b.decode())))
            client.listen(timeout=1.0)

    def publisher():
        time.sleep(0.1)
        with MemoClient() as client:
            msg = client.build_message_bytes(1, "news", b"Breaking news!")
            client.send_raw_data(msg[:71])
            time.sleep(0.1)
            client.send_raw_data(msg[71:])

    run_threads(subscriber, publisher)

    assert received == [("news", "Breaking news!")]

def test_multi_message_write(memo_server):
    """
    Publisher sends three messages in quick succession. This will be received
    as a single lump of data on the Memo server.
    """
    received = []
    with open(DATA_FILE, "rb") as f:
        file_data = f.read()

    def subscriber():
        with MemoClient() as client:
            client.subscribe("news", lambda c, t, b: received.append((t, b.decode())))
            client.listen(timeout=1.0)

    def publisher():
        time.sleep(0.1)
        with MemoClient() as client:
            msg1 = client.build_message_bytes(1, "news", b"First message")
            msg2 = client.build_message_bytes(1, "news", b"Second message")
            msg3 = client.build_message_bytes(1, "news", file_data)
            client.send_raw_data(msg1)
            client.send_raw_data(msg2)
            client.send_raw_data(msg3)

    run_threads(subscriber, publisher)

    assert received == [("news", "First message"),
                        ("news", "Second message"),
                        ("news", file_data.decode())]

@pytest.mark.parametrize("memo_server", ["partial_write"], indirect=True)
def test_large_write_pw(memo_server):
    """
    Publisher sends a large message. Force Memo to do partial writes
    in order to test how the event loop handles that situation.
    """
    received = []
    with open(DATA_FILE, "rb") as f:
        file_data = f.read()

    def subscriber():
        with MemoClient() as client:
            client.subscribe("news", lambda c, t, b: received.append((t, b.decode())))
            client.listen(timeout=1.0)

    def publisher():
        time.sleep(0.1)
        with MemoClient() as client:
            client.publish("news", file_data)

    run_threads(subscriber, publisher)

    assert received == [("news", file_data.decode())]
