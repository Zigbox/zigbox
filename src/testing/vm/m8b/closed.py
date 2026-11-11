import os, socket, subprocess
inside = ("echo READY; read x\n"
  "wget -qO- -T 3 http://127.0.0.1:8080/ 2>&1; echo AFTER:$?\n"
  "echo ALIVE\n")
a, b = socket.socketpair()
n = b.fileno()
p = subprocess.Popen(["/home/demo/zbx", "run", "--rootfs", "/home/demo/alpine", "--name", "m8b-closed",
    "--net", "none", "--listen", "127.0.0.1:8080", "--listen-send", str(n), "--", "sh", "-c", inside],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(n,), text=True)
b.close()
fds = socket.recv_fds(a, 16, 1)[1]
for line in p.stdout:
    if line.strip() == "READY":
        break
os.close(fds[0])
a.close()
print("CLOSED-HARNESS-END")
p.stdin.write("\n")
p.stdin.flush()
o, e = p.communicate(timeout=60)
print(o.strip())
print("CLOSED-RC:", p.returncode)
print("CLOSED-ERR:", e.strip())
