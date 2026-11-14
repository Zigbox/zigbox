from lib import *
s = Sup()
zx("run", "-d", "--rootfs", R, "--name", "c4h", "--net", "host", "--", "sleep", "3000")
say("REFUSED host", s.do("hold 0 c4h"))
say("REFUSED unknown", s.do("hold 0 nope"))
zx("stop", "c4h")
say("REFUSED stopped", s.do("hold 0 c4h"))
s.end()
