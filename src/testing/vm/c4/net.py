from lib import *
import socket
srv = S.Popen([Z, "exec", "c4", "--", "sh", "-c", "echo inside | nc -l -p 9100"],
    stdout=S.PIPE, text=True)
say("SERVER-UP", int(wait_inside(9100)))
rc, o, e = ex("nc", "127.0.0.1", "9100")
say("OTHER-EXEC", o)
say("HOST-9100", socket.socket().connect_ex(("127.0.0.1", 9100)))
srv.communicate(timeout=30)
say("ADDRS", ex("ip", "-o", "addr")[1].count("inet "))
