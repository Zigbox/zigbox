import os, socket, subprocess, time
r, w = os.pipe()
def go(label, *args, command="true", fds=(w,)):
    started = time.monotonic()
    p = subprocess.run(["/home/demo/zbx", "run", "--rootfs", "/home/demo/alpine", "--name", "m8b-r",
        *args, "--", *command.split()], capture_output=True, text=True, pass_fds=fds,
        stdin=subprocess.DEVNULL)
    e = p.stderr.strip().splitlines()
    print("REFUSED", label, "rc=%d" % p.returncode, e[0] if e else "")
    return time.monotonic() - started
L = ("--listen", "127.0.0.1:8080")
go("host", "--net", "host", *L, "--listen-send", "3")
go("publish", "--publish", "8080:80", *L, "--listen-send", "3")
go("nosend", *L)
# A pipe is no Unix socket, and a number past a descriptor is none either: refused before the start.
go("notsocket", "--net", "none", *L, "--listen-send", str(w))
go("badfd", "--net", "none", *L, "--listen-send", "4294967295")
go("remote", "--net", "none", "--listen", "10.0.0.1:8080", "--listen-send", "3")
# A socket whose peer is gone: the send fails after the start, and the container (a long sleep,
# so only a stop ends it) must be stopped, not left running.
a, b = socket.socketpair()
b.close()
seconds = go("gone", "--net", "none", *L, "--listen-send", str(a.fileno()), command="sleep 31",
    fds=(a.fileno(),))
print("GONE-SECS:%d" % int(seconds))
left = subprocess.run(["pgrep", "-f", "^sleep 31$"], capture_output=True, text=True)
print("GONE-LEFT:%d" % len(left.stdout.split()))
