# Send a complete short message in one go.
from memo_client import MemoClient

with MemoClient() as client:
    client.publish("news", b"Breaking news!")

