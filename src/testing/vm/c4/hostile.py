from lib import *
import shutil, threading
s = Sup()
# One shell globs /proc before any fork: exact, less itself.
P = ("sh", "-c", "cd /proc; set -- [0-9]*; echo $(($#-1))")
procs = ex(*P)[1]
say("PROCS", procs)
cmd = "kill -9 %s 2>&1; echo kill-rc=$?; ls /proc/%s 2>&1" % (s.pid, s.pid)
say("KILL-SUPERVISOR", ex("sh", "-c", cmd)[1].replace("\n", " | "))
# A copy of the supervisor tries to ptrace it.
shutil.copy("/home/demo/c4-supervisor", R + "/tmp/c4-tracer")
say("PTRACE-SUPERVISOR", ex("/tmp/c4-tracer", "ptrace", s.pid)[1])
# /proc never changes while 3000 helpers come and go; samples begun
# after CHURNING and done before CHURNED count as during.
s.send("churn 5 c4 3000")
go, end, lines = threading.Event(), threading.Event(), []
def read():
    for _ in range(2):
        lines.append(s.p.stdout.readline().strip())
        go.set()
        if not lines[-1].startswith("CHURNING"):
            break
    end.set()
t = threading.Thread(target=read, daemon=True)
t.start()
go.wait(60)
counts, n, during = set(), 0, 0
while not end.is_set() and n < 400:
    counts.add(ex(*P)[1])
    n += 1
    during += not end.is_set()
t.join(120)
say("CHURN-START", lines[0])
say("CHURN", lines[-1])
say("SAMPLES-DURING-CHURN", during)
say("PROCS-DURING-CHURN", " ".join(sorted(counts)))
say("PROCS-STEADY", int(counts == {procs}))
ex("sh", "-c", "kill -9 -1")
say("KILL-ALL", "ran")
say("SUPERVISOR", s.do("ping"))
say("CONTAINER", int("c4" in zx("ps")[1]))
say("WRITE-ETC-HOSTS", ex("sh", "-c", "echo x >> /etc/hosts")[0])
s.end()
