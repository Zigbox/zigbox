import socket, subprocess
inside = ("nc -l -p 8080 2>&1; echo NC-EXIT:$?\n"
  "echo SOCKETS:$(ls -l /proc/1/fd /proc/self/fd | grep -c socket)\n"
  "wget -qO- -T 2 http://127.0.0.1:9999/ >/dev/null 2>&1; echo W9999:$?\n"
  "echo READY; read x; echo DONE\n")
h = socket.socket()
h.bind(("127.0.0.1", 9999))
h.listen(1)
h.setblocking(False)
a, b = socket.socketpair()
n = b.fileno()
p = subprocess.Popen(["/home/demo/zbx", "run", "--rootfs", "/home/demo/alpine", "--name", "m8b-hostile",
    "--net", "none", "--listen", "127.0.0.1:8080", "--listen-send", str(n), "--", "sh", "-c", inside],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(n,), text=True)
b.close()
fds = socket.recv_fds(a, 16, 1)[1]
for line in p.stdout:
    print(line.strip())
    if line.strip() == "READY":
        break
ss = subprocess.run(["ss", "-tln"], capture_output=True, text=True).stdout
print("HOST-SS-8080:", sum(":8080 " in x for x in ss.splitlines()))
try:
    h.accept()
    print("HOST-9999-ACCEPTED: 1")
except BlockingIOError:
    print("HOST-9999-ACCEPTED: 0")
p.stdin.write("\n")
p.stdin.flush()
o, e = p.communicate(timeout=60)
print(o.strip())
print("HOSTILE-RC:", p.returncode)
print("HOSTILE-ERR:", e.strip())
