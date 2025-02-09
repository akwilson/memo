# Send a message in three parts.
import socket, time

msg = b'\x53\x00\x00\x00' + b'\x01' + b'news'.ljust(64, b'\0') + b'Breaking News!'

# Send message in parts
s = socket.socket()
s.connect(('localhost', 5000))
# Send two bytes, i.e less than the header size and wait 100ms
s.sendall(msg[:2])
time.sleep(0.1)

# Send next two bytes
s.sendall(msg[2:4])
time.sleep(0.1)

# Send the rest in two parts
s.sendall(msg[4:65])
time.sleep(0.1)
s.sendall(msg[65:])
s.close()

