from lib import *
import os
H = "/home/demo/mesh-hosts"
open(H, "w").write("127.0.0.1 localhost\n10.9.9.9 svc.mesh\n")
rc, o, e = zx("run", "-d", "--rootfs", R, "--name", "c4m", "--net", "none",
    "--hosts-file", H, "--", "sleep", "3000")
say("HOSTS-RC", rc)
say("HOSTS-ERR", e)
def hx(*a):
    return S.run([Z, "exec", "c4m", "--", *a], capture_output=True, text=True, timeout=60)
say("HOSTS-CAT", hx("cat", "/etc/hosts").stdout.replace("\n", "|"))
say("HOSTS-GETENT", hx("getent", "hosts", "svc.mesh").stdout.split()[:1])
open(H, "w").write("127.0.0.1 localhost\n10.9.9.10 svc.mesh\n")
say("HOSTS-INPLACE", hx("getent", "hosts", "svc.mesh").stdout.split()[:1])
open(H + ".new", "w").write("127.0.0.1 localhost\n10.9.9.11 svc.mesh\n")
os.replace(H + ".new", H)
say("HOSTS-RENAMED", hx("getent", "hosts", "svc.mesh").stdout.split()[:1])
say("HOSTS-WRITE", hx("sh", "-c", "echo x >> /etc/hosts").returncode)
zx("stop", "c4m")
say("HOSTS-REFUSED-NET", zx("run", "--rootfs", R, "--net", "host", "--hosts-file", H, "--", "true")[2])
say("HOSTS-REFUSED-MISSING", zx("run", "--rootfs", R, "--net", "none", "--hosts-file", "/nope", "--", "true")[2])
say("HOSTS-REFUSED-DIR", zx("run", "--rootfs", R, "--net", "none", "--hosts-file", "/tmp", "--", "true")[2])
