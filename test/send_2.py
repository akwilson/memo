# Send the first two bytes of a short message then send the rest.
import socket, time

msg = b'\x53\x00\x00\x00' + b'\x01' + b'news'.ljust(64, b'\0') + b'Breaking News!'

s = socket.socket()
s.connect(('localhost', 5000))
s.sendall(msg[:2])
time.sleep(0.1)
s.sendall(msg[2:])
s.close()
