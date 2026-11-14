from lib import *
import socket
def get(ip):
    return ex("wget", "-qO-", "-T", "3", "http://%s:8080/" % ip)
s = Sup()
say("LISTEN-A", s.do("listen 0 c4 127.77.0.2 8080"))
rc, o, e = get("127.77.0.2")
say("A-RC", rc)
say("A-OUT", o)
say("CLOSE-A", s.do("close 0"))
say("LISTEN-B", s.do("listen 1 c4 127.77.0.3 8080"))
say("B-OUT", get("127.77.0.3")[1])
say("A-AFTER-RC", get("127.77.0.2")[0])
h = socket.socket()
h.settimeout(3)
say("HOST-A", h.connect_ex(("127.77.0.2", 8080)))
say("HOST-B", socket.socket().connect_ex(("127.77.0.3", 8080)))
say("CLOSE-B", s.do("close 1"))
s.end()
