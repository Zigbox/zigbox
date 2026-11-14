from lib import *
rc, o, e = zx("run", "-d", "--rootfs", R, "--name", "c4", "--net", "none", "--", "sleep", "3000")
say("START-RC", rc)
say("START-ERR", e)
rc, o, e = ex("ip", "-o", "link")
say("LINKS", len(o.splitlines()))
say("LINK-LO", int(": lo:" in o or " lo:" in o))
