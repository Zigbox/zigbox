from lib import *
import shutil
s = Sup()
procs = ex("sh", "-c", "ls /proc | grep -c '^[0-9]'")[1]
say("PROCS", procs)
cmd = "kill -9 %s 2>&1; echo kill-rc=$?; ls /proc/%s 2>&1" % (s.pid, s.pid)
say("KILL-SUPERVISOR", ex("sh", "-c", cmd)[1].replace("\n", " | "))
# ptrace from inside: the static supervisor binary, copied into the rootfs, tries to seize it.
shutil.copy("/home/demo/c4-supervisor", R + "/tmp/c4-tracer")
say("PTRACE-SUPERVISOR", ex("/tmp/c4-tracer", "ptrace", s.pid)[1])
# While a thread makes and closes many sockets (a helper each), /proc inside never grows.
s.p.stdin.write("churn 5 c4 3000\n")
s.p.stdin.flush()
counts = set()
for _ in range(12):
    counts.add(ex("sh", "-c", "ls /proc | grep -c '^[0-9]'")[1])
say("CHURN", s.p.stdout.readline().strip())
say("PROCS-DURING-CHURN", " ".join(sorted(counts)))
say("PROCS-STEADY", int(counts == {procs}))
ex("sh", "-c", "kill -9 -1")
say("KILL-ALL", "ran")
say("SUPERVISOR", s.do("ping"))
say("CONTAINER", int("c4" in zx("ps")[1]))
say("WRITE-ETC-HOSTS", ex("sh", "-c", "echo x >> /etc/hosts")[0])
s.end()
