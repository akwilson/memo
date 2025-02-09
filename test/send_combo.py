# Send two little messages and a 6K message in one go.
import socket, time, struct

def build_message(msg_type: int, topic: bytes, msg_body: bytes) -> bytes:
    # Pad or truncate topic to exactly 64 bytes
    padded_topic = topic.ljust(64, b'\0')[:64]

    # Assemble message parts excluding size
    message = struct.pack('B', msg_type) + padded_topic + msg_body

    # Prefix with 4-byte little-endian message size
    msg_size = struct.pack('<I', len(message) + 4)

    return msg_size + message

with open('lorem_6k.txt', 'rb') as f:
    data = f.read()
    
msg1 = build_message(1, b'news', b'First Message')
msg2 = build_message(1, b'news', b'Second Message')
msg3 = build_message(1, b'news', data)

s = socket.socket()
s.connect(('localhost', 5000))
s.sendall(msg1)
s.sendall(msg2)
s.sendall(msg3)
s.close()
