import socket, subprocess
a, b = socket.socketpair()
n = b.fileno()
p = subprocess.Popen(["/home/demo/zbx", "run", "--rootfs", "/home/demo/alpine", "--name", "m8b-hello",
    "--net", "none", "--listen", "127.0.0.1:8080", "--listen-send", str(n), "--",
    "wget", "-qO-", "http://127.0.0.1:8080/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    pass_fds=(n,), text=True)
b.close()
fds = socket.recv_fds(a, 16, 1)[1]
l = socket.socket(fileno=fds[0])
l.settimeout(30)
c, _ = l.accept()
c.recv(4096)
c.sendall(b"HTTP/1.0 200 OK\r\n\r\nhello from outside\n")
c.close()
o, e = p.communicate(timeout=60)
print("HELLO-DESCRIPTORS:", len(fds))
print("HELLO-RC:", p.returncode)
print("HELLO-OUT:", o.strip())
print("HELLO-ERR:", e.strip())
