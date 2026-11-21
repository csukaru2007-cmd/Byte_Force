import socket

s = socket.socket()
s.bind(("0.0.0.0", 7000))
s.listen(1)
while True:
    conn, addr = s.accept()
    data = conn.recv(256)
    result = eval(data)          # evaluate remote expression
    conn.send(str(result).encode())
    conn.close()
