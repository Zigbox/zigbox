from lib import *
import os, signal
s = Sup()
say("HOLD", s.do("hold 3 c4"))
# The agent: another process that adopts the container, then dies by SIGKILL.
agent = Sup()
say("AGENT-ADOPT", agent.do("adopt c4"))
os.kill(int(agent.pid), signal.SIGKILL)
say("AGENT-KILLED", agent.p.wait(timeout=10))
# The supervisor restarts: a new image in the same process, no Zigbox state, the socket kept.
old = s.pid
s.pid = s.do("restart").split()[1]
say("RESTARTED-SAME-PID", int(s.pid == old))
say("RESTART", s.p.stdout.readline().strip())
say("ADOPT", s.do("adopt c4"))
srv = S.Popen([Z, "exec", "c4", "--", "sh", "-c", "echo pong-from-inside | nc -l -p 9000"],
    stdout=S.PIPE, text=True)
say("SERVER-UP", int(wait_inside(9000)))
say("DIAL", s.do("dial 3 127.0.0.1 9000 ping-from-supervisor"))
say("SERVER-GOT", srv.communicate(timeout=30)[0].strip())
s.end()
