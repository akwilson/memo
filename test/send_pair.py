# Send two short messages in quick succession. Will appear on the server
# as two messages in a single read.
import socket, time, struct

def build_message(msg_type: int, topic: bytes, msg_body: bytes) -> bytes:
    # Pad or truncate topic to exactly 64 bytes
    padded_topic = topic.ljust(64, b'\0')[:64]

    # Assemble message parts excluding size
    message = struct.pack('B', msg_type) + padded_topic + msg_body

    # Prefix with 4-byte little-endian message size
    msg_size = struct.pack('<I', len(message) + 4)

    return msg_size + message

msg = build_message(1, b'news', b'Breaking News!')
msg2 = build_message(1, b'sports', b'Big Game Tonight!')

s = socket.socket()
s.connect(('localhost', 5000))
s.sendall(msg)
# time.sleep(0.1)
s.sendall(msg2)
s.close()
