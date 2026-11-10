import os, subprocess
r, w = os.pipe()
def go(label, *args):
    p = subprocess.run(["/home/demo/zbx", "run", "--rootfs", "/home/demo/alpine", "--name", "m8b-r",
        *args, "--", "true"], capture_output=True, text=True, pass_fds=(w,), stdin=subprocess.DEVNULL)
    e = p.stderr.strip().splitlines()
    print("REFUSED", label, "rc=%d" % p.returncode, e[0] if e else "")
L = ("--listen", "127.0.0.1:8080")
go("host", "--net", "host", *L, "--listen-send", "3")
go("publish", "--publish", "8080:80", *L, "--listen-send", "3")
go("nosend", *L)
go("notsocket", "--net", "none", *L, "--listen-send", str(w))
go("remote", "--net", "none", "--listen", "10.0.0.1:8080", "--listen-send", "3")
