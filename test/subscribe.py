from memo_client import MemoClient

def handle_news(topic, body):
    print(f"Received topic='{topic}'; Body='{body.decode()}'")

with MemoClient() as client:
    client.subscribe("news", handle_news)
    client.listen()

