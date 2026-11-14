import subprocess as S
Z = "/home/demo/zbx"
R = "/home/demo/alpine"
def zx(*a):
    r = S.run([Z, *a], capture_output=True, text=True, timeout=90)
    return r.returncode, r.stdout.strip(), r.stderr.strip()
def ex(*a):
    return zx("exec", "c4", "--", *a)
def say(k, v):
    print(k + ":", v, flush=True)
class Sup:
    def __init__(s):
        s.p = S.Popen(["/home/demo/c4-supervisor"], stdin=S.PIPE, stdout=S.PIPE, text=True, bufsize=1)
        s.pid = s.p.stdout.readline().split()[1]
    def do(s, line):
        s.p.stdin.write(line + "\n")
        s.p.stdin.flush()
        return s.p.stdout.readline().strip()
    def end(s):
        s.do("quit")
        s.p.wait(timeout=10)
def wait_inside(port):
    for _ in range(40):
        if ex("sh", "-c", "netstat -tln | grep -c :%d" % port)[1] == "1":
            return True
        S.run(["sleep", "0.5"])
    return False
