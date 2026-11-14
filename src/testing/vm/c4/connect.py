from lib import *
s = Sup()
say("HOLD", s.do("hold 3 c4"))
say("ADOPT", s.do("adopt c4"))
srv = S.Popen([Z, "exec", "c4", "--", "sh", "-c", "echo pong-from-inside | nc -l -p 9000"],
    stdout=S.PIPE, text=True)
say("SERVER-UP", int(wait_inside(9000)))
say("DIAL", s.do("dial 3 127.0.0.1 9000 ping-from-supervisor"))
say("SERVER-GOT", srv.communicate(timeout=30)[0].strip())
say("SOCKET-AFTER", s.do("hold 3 c4"))
s.end()
