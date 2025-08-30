# Send a complete short message in one go.
from memo_client import MemoClient

with open("lorem_6k.txt", "rb") as f:
    file_data = f.read();

with MemoClient() as client:
    client.publish("news", file_data)

