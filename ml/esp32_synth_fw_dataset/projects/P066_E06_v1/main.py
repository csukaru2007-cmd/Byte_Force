import socket

ALLOWED_CMDS = ("led_on", "led_off", "read")

s = socket.socket()
s.bind(("0.0.0.0", 7000))
s.listen(1)
while True:
    conn, _ = s.accept()
    cmd = conn.recv(16).decode().strip()
    if len(cmd) > 8 or cmd not in ALLOWED_CMDS:
        conn.send(b"denied")
    else:
        conn.send(b"ok:" + cmd.encode())
    conn.close()
