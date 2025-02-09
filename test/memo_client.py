import socket
import struct

MSG_TYPE_PUBLISH = 1
MSG_TYPE_SUBSCRIBE = 2
TOPIC_LEN = 64

class MemoClient:
    """Client for connecting to and interacting with a Memo pub/sub server."""
    
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.sock = None
        self.callbacks = {}

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        """Establish a connection to the Memo server."""
        self.sock = socket.create_connection((self.host, self.port))

    def close(self):
        """Close the connection to the Memo server."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def subscribe(self, topic: str, callback):
        """
        Subscribe to a topic and register a callback.

        Args:
            topic (str): The topic to subscribe to.
            callback (function): A function taking (topic: str, body: bytes).
        """
        self.callbacks[topic] = callback
        self.send_message(MSG_TYPE_SUBSCRIBE, topic, b'')

    def publish(self, topic: str, message: bytes):
        """
        Publish a message to a topic.

        Args:
            topic (str): The topic to publish to.
            message (bytes): The message body to send.
        """
        self.send_message(MSG_TYPE_PUBLISH, topic, message)

    def listen(self, timeout: float = None):
        """
        Listen for messages from the server and dispatch to callbacks.

        Args:
            timeout (float, optional): Time in seconds to wait before giving up.
                                       If None, blocks indefinitely.
        """
        if timeout is not None:
            self.sock.settimeout(timeout)
        else:
            self.sock.settimeout(None)

        try:
            while True:
                header = self._recv_exact(4)
                if not header:
                    break
                (msg_size,) = struct.unpack('<I', header)
                payload = self._recv_exact(msg_size - 4)
                if not payload:
                    break

                msg_type = payload[0]
                topic = payload[1:65].rstrip(b'\0').decode('utf-8')
                body = payload[65:]
                callback = self.callbacks.get(topic)
                if callback:
                    callback(topic, body)
                else:
                    print(f"[WARN] No callback registered for topic '{topic}'")
        except socket.timeout:
            print("MemoClient listen() timed out")
        finally:
            self.sock.settimeout(None)

    def send_message(self, msg_type: int, topic: str, body: bytes):
        """Send a full message immediately (msg_type + topic + body)."""
        data = self.build_message_bytes(msg_type, topic, body)
        self.sock.sendall(data)
        
    def build_message_bytes(self, msg_type: int, topic: str, body: bytes) -> bytes:
        """Constructs and returns the full message as bytes (including size header)."""
        topic_bytes = topic.encode("utf-8").ljust(TOPIC_LEN, b"\0")
        payload = struct.pack(f"B{TOPIC_LEN}s", msg_type, topic_bytes) + body
        msg_size = 4 + len(payload)
        header = struct.pack("<I", msg_size)
        return header + payload

    def send_raw_data(self, data):
        """Sends some bytes directly to the Memo server"""
        self.sock.sendall(data)

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

