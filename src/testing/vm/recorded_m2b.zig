//! What demo-m2b's guest printed, copied byte for byte from the log of run
//! `run` below (the `vm| ` echo lines and the timestamps removed), for the tests of
//! checks_m2b.zig. Refresh it from a new run's log; never edit the text by hand.

pub const run = "44074433710";

/// E0311 in text mode, `--ulimit nofile=` one above the demo user's hard limit.
pub const e0311_text =
    "error[ZBX-E0311]: --ulimit is above your own hard limit\n" ++
    "  cause  --ulimit nofile asks for a hard limit of 1048577, above your own,\n" ++
    "         1048576; a rootless run can't raise it\n" ++
    "  fix    raise it for logins (then log in again):                            echo \"$(id -" ++
    "un) hard nofile 1048577\" | sudo tee -a /etc/security/limits.conf\n" ++
    "         or for the user manager, add LimitNOFILE=1048577 under [Service]:   sudo systemct" ++
    "l edit user@1000.service\n" ++
    "  more   zbx explain E0311 · rerun with --verbose for the full cause chain\n" ++
    "  docs   https://zigbox.github.io/zigbox/errors/E0311.html\n";

/// E0319 in text mode, `--require-host 'vm.max_map_count>=262144'` on 65530.
pub const e0319_text =
    "error[ZBX-E0319]: vm.max_map_count is 65530, needs >=262144\n" ++
    "  cause  --require-host asks for vm.max_map_count>=262144, and this host's is\n" ++
    "         65530\n" ++
    "  fix    set it on the host (a file in /etc/sysctl.d/ keeps it across boots):   sudo sysct" ++
    "l -w vm.max_map_count=262144\n" ++
    "         check every setting:                                                   zbx doctor" ++
    "\n" ++
    "  more   zbx explain E0319 · rerun with --verbose for the full cause chain\n" ++
    "  docs   https://zigbox.github.io/zigbox/errors/E0319.html\n";

/// E0311 with `--output json`.
pub const e0311_json =
    "{\"code\":\"ZBX-E0311\",\"severity\":\"error\",\"blame\":\"environment\",\"summary\":\"--u" ++
    "limit is above your own hard limit\",\"causes\":[\"--ulimit nofile asks for a hard limit o" ++
    "f 1048577, above your own, 1048576; a rootless run can't raise it\"],\"while\":[\"checking" ++
    " --ulimit nofile\"],\"context\":{\"asked\":\"1048577\",\"hard\":\"1048576\",\"unit\":\"Lim" ++
    "itNOFILE=1048577\"},\"fixes\":[{\"sentence\":\"raise it for logins (then log in again):\"," ++
    "\"command\":\"echo \\\"$(id -un) hard nofile 1048577\\\" | sudo tee -a /etc/security/limit" ++
    "s.conf\",\"needs_root\":true},{\"sentence\":\"or for the user manager, add LimitNOFILE=104" ++
    "8577 under [Service]:\",\"command\":\"sudo systemctl edit user@1000.service\",\"needs_root" ++
    "\":true}],\"docs\":\"https://zigbox.github.io/zigbox/errors/E0311.html\",\"omitted\":{\"ca" ++
    "uses\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";

/// E0316 with `--output json`, `--sysctl vm.max_map_count=262144`.
pub const e0316_json =
    "{\"code\":\"ZBX-E0316\",\"severity\":\"error\",\"blame\":\"user\",\"summary\":\"a --sysctl" ++
    " is a host setting\",\"causes\":[\"vm.max_map_count is a host setting, not one of the cont" ++
    "ainer's own namespaces, so a container can't set it\"],\"while\":[\"reading --sysctl\"],\"" ++
    "context\":{\"sysctl\":\"vm.max_map_count\"},\"fixes\":[{\"sentence\":\"set it on the host " ++
    "instead:\",\"command\":\"sudo sysctl -w vm.max_map_count=<value>\",\"needs_root\":true,\"t" ++
    "emplate\":true},{\"sentence\":\"or refuse the run on a host without it:\",\"command\":\"--" ++
    "require-host 'vm.max_map_count>=<value>'\",\"template\":true},{\"sentence\":\"the keys a c" ++
    "ontainer may set:\",\"command\":\"zbx explain E0316\"}],\"docs\":\"https://zigbox.github.i" ++
    "o/zigbox/errors/E0316.html\",\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\"" ++
    ":0}}\n";

/// E0319 with `--output json`.
pub const e0319_json =
    "{\"code\":\"ZBX-E0319\",\"severity\":\"error\",\"blame\":\"environment\",\"summary\":\"vm." ++
    "max_map_count is 65530, needs >=262144\",\"causes\":[\"--require-host asks for vm.max_map_" ++
    "count>=262144, and this host's is 65530\"],\"while\":[],\"context\":{\"key\":\"vm.max_map_" ++
    "count\",\"host\":\"65530\",\"needed\":\">=262144\"},\"fixes\":[{\"sentence\":\"set it on t" ++
    "he host (a file in /etc/sysctl.d/ keeps it across boots):\",\"command\":\"sudo sysctl -w v" ++
    "m.max_map_count=262144\",\"needs_root\":true},{\"sentence\":\"check every setting:\",\"com" ++
    "mand\":\"zbx doctor\"}],\"docs\":\"https://zigbox.github.io/zigbox/errors/E0319.html\",\"o" ++
    "mitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";

/// The text doctor's host-settings line at 65530.
pub const doctor_text =
    "ok   host-settings  vm.max_map_count 65530, fs.aio-max-nr 65536, vm.overcommit_memory 0, t" ++
    "ransparent_hugepage madvise\n";

/// `zbx --output json doctor` after the fix was applied.
pub const doctor_json =
    "{\"schema\":\"zbx.doctor/1\",\"ok\":true,\"checks\":[{\"id\":\"kernel\",\"status\":\"ok\"," ++
    "\"detail\":\"6.8.0-147-generic x86_64 (minimum 5.15)\"},{\"id\":\"userns\",\"status\":\"ok" ++
    "\",\"detail\":\"user.max_user_namespaces=7718, unshare(CLONE_NEWUSER) works\"},{\"id\":\"c" ++
    "group\",\"status\":\"ok\",\"detail\":\"cgroup v2, user@1000.service delegated to uid 1000:" ++
    " cpu memory pids; systemd 255.4-1ubuntu8.18 on the user bus\"},{\"id\":\"overlay\",\"statu" ++
    "s\":\"ok\",\"detail\":\"overlayfs mounts inside a user and mount namespace; id-mapped moun" ++
    "ts of /root: not allowed (zbx does not use them)\"},{\"id\":\"subid\",\"status\":\"ok\",\"" ++
    "detail\":\"demo (uid 1000): subuid 65536 ids, subgid 65536 ids; newuidmap: setuid root, ne" ++
    "wgidmap: setuid root\"},{\"id\":\"seccomp\",\"status\":\"ok\",\"detail\":\"seccomp is supp" ++
    "orted (current mode: disabled for this process)\"},{\"id\":\"host-settings\",\"status\":\"" ++
    "ok\",\"detail\":\"vm.max_map_count 262144, fs.aio-max-nr 65536, vm.overcommit_memory 0, tr" ++
    "ansparent_hugepage madvise\"},{\"id\":\"fuse\",\"status\":\"ok\",\"detail\":\"FUSE mounts " ++
    "inside a user namespace (zbx run --lazy)\"},{\"id\":\"net\",\"status\":\"ok\",\"detail\":" ++
    "\"pasta unknown version at /usr/bin/pasta\"}],\"host_settings\":{\"vm.max_map_count\":2621" ++
    "44,\"fs.aio-max-nr\":65536,\"vm.overcommit_memory\":0,\"transparent_hugepage\":\"madvise\"" ++
    "}}\n";

/// container_exit of `--ulimit nofile=4096:8192`.
pub const exit_ulimit =
    "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\",\"published\":[" ++
    "],\"ulimits\":{\"nofile\":{\"soft\":4096,\"hard\":8192}},\"writable_mounts\":[],\"user\":{" ++
    "\"uid\":0,\"gid\":0}},\"ran\":{\"kind\":\"rootfs\",\"path\":\"/home/demo/alpine\"}}\n";

/// container_exit of `--shm-size 256m`.
pub const exit_shm =
    "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\",\"published\":[" ++
    "],\"shm_bytes\":268435456,\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},\"ran\":{" ++
    "\"kind\":\"rootfs\",\"path\":\"/home/demo/alpine\"}}\n";

/// container_exit of `--sysctl net.core.somaxconn=8192`.
pub const exit_sysctl =
    "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\",\"published\":[" ++
    "],\"sysctls\":[{\"key\":\"net.core.somaxconn\",\"value\":\"8192\"}],\"writable_mounts\":[]" ++
    ",\"user\":{\"uid\":0,\"gid\":0}},\"ran\":{\"kind\":\"rootfs\",\"path\":\"/home/demo/alpine" ++
    "\"}}\n";

/// container_exit of the write to memory.max (the program exited 1).
pub const exit_failed =
    "{\"container_exit\":{\"reason\":\"exited\",\"code\":1,\"network\":\"none\",\"published\":[" ++
    "],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},\"ran\":{\"kind\":\"rootfs\",\"pa" ++
    "th\":\"/home/demo/alpine\"}}\n";

/// What sh said of the write to memory.max.
pub const read_only =
    "sh: can't create /sys/fs/cgroup/memory.max: Read-only file system\n";

/// numactl under v0.5.2, whose filter lacked the policy calls.
pub const old_numactl =
    "set_mempolicy: Operation not permitted\n" ++
    "setting interleave mask: Operation not permitted\n";

/// busybox `df -k /dev/shm` under `--shm-size 256m`.
pub const df_shm =
    "Filesystem           1K-blocks      Used Available Use% Mounted on\n" ++
    "tmpfs                   262144         0    262144   0% /dev/shm\n";

/// `zbx --output json ps` with the three containers v0.5.2 started.
pub const ps_old =
    "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"m2bpub\",\"state\":\"running\",\"pid" ++
    "\":2749,\"supervisor\":2747,\"scope\":\"zbx-m2bpub.scope\",\"detached\":true,\"timed_out\"" ++
    ":false,\"started\":1794915371,\"ended\":null,\"reason\":\"none\",\"exit_code\":null,\"comm" ++
    "and\":[\"sleep\",\"300\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"" ++
    "cpu_millis\":null},\"network\":\"user\",\"published\":[{\"host\":18080,\"container\":80}]," ++
    "\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"m2bold\",\"s" ++
    "tate\":\"running\",\"pid\":2739,\"supervisor\":2738,\"scope\":\"zbx-m2bold.scope\",\"detac" ++
    "hed\":true,\"timed_out\":false,\"started\":1794915371,\"ended\":null,\"reason\":\"none\"," ++
    "\"exit_code\":null,\"command\":[\"sleep\",\"300\"],\"labels\":[],\"limits\":{\"memory_byte" ++
    "s\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published\":[],\"env\":" ++
    "[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"m2bdev\",\"state\":" ++
    "\"running\",\"pid\":2765,\"supervisor\":2764,\"scope\":\"zbx-m2bdev.scope\",\"detached\":t" ++
    "rue,\"timed_out\":false,\"started\":1794915371,\"ended\":null,\"reason\":\"none\",\"exit_c" ++
    "ode\":null,\"command\":[\"sleep\",\"300\"],\"labels\":[],\"limits\":{\"memory_bytes\":null" ++
    ",\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published\":[],\"env\":[],\"wri" ++
    "table_mounts\":[],\"user\":{\"uid\":0,\"gid\":0},\"devices\":[{\"asked\":\"/dev/fuse\",\"p" ++
    "ath\":\"/dev/fuse\"}]}]}\n";

/// `zbx stop` of the first of them.
pub const stopped =
    "m2bold stopped (killed), exit code 137\n";

/// `zbx --output json ps --all` after the three stops.
pub const ps_all =
    "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"zbx-edfc43\",\"state\":\"stopped\",\"" ++
    "pid\":2722,\"supervisor\":2721,\"scope\":\"zbx-zbx-edfc43.scope\",\"detached\":false,\"tim" ++
    "ed_out\":false,\"started\":1794915371,\"ended\":1794915371,\"reason\":\"exited\",\"exit_co" ++
    "de\":0,\"command\":[\"sh\",\"-c\",\"cat /proc/self/cgroup /sys/fs/cgroup/memory.max /sys/f" ++
    "s/cgroup/cpu.max\"],\"labels\":[],\"limits\":{\"memory_bytes\":268435456,\"pids\":null,\"c" ++
    "pu_millis\":1500},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[]," ++
    "\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"m2bpub\",\"state\":\"stopped\",\"pid\":2749,\"" ++
    "supervisor\":2747,\"scope\":\"zbx-m2bpub.scope\",\"detached\":true,\"timed_out\":false,\"s" ++
    "tarted\":1794915371,\"ended\":1794915371,\"reason\":\"signal\",\"exit_code\":137,\"command" ++
    "\":[\"sleep\",\"300\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu" ++
    "_millis\":null},\"network\":\"user\",\"published\":[{\"host\":18080,\"container\":80}],\"e" ++
    "nv\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zbx-dbd039\",\"" ++
    "state\":\"stopped\",\"pid\":2730,\"supervisor\":2729,\"scope\":\"zbx-zbx-dbd039.scope\",\"" ++
    "detached\":false,\"timed_out\":false,\"started\":1794915371,\"ended\":1794915371,\"reason" ++
    "\":\"exited\",\"exit_code\":1,\"command\":[\"sh\",\"-c\",\"echo 1 > /sys/fs/cgroup/memory." ++
    "max\"],\"labels\":[],\"limits\":{\"memory_bytes\":268435456,\"pids\":null,\"cpu_millis\":n" ++
    "ull},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"u" ++
    "id\":0,\"gid\":0}},{\"name\":\"m2bold\",\"state\":\"stopped\",\"pid\":2739,\"supervisor\":" ++
    "2738,\"scope\":\"zbx-m2bold.scope\",\"detached\":true,\"timed_out\":false,\"started\":1794" ++
    "915371,\"ended\":1794915371,\"reason\":\"signal\",\"exit_code\":137,\"command\":[\"sleep\"" ++
    ",\"300\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":nul" ++
    "l},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid" ++
    "\":0,\"gid\":0}},{\"name\":\"m2bdev\",\"state\":\"stopped\",\"pid\":2765,\"supervisor\":27" ++
    "64,\"scope\":\"zbx-m2bdev.scope\",\"detached\":true,\"timed_out\":false,\"started\":179491" ++
    "5371,\"ended\":1794915371,\"reason\":\"signal\",\"exit_code\":137,\"command\":[\"sleep\"," ++
    "\"300\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null" ++
    "},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid" ++
    "\":0,\"gid\":0},\"devices\":[{\"asked\":\"/dev/fuse\",\"path\":\"/dev/fuse\"}]},{\"name\":" ++
    "\"zbx-e7dc6d\",\"state\":\"stopped\",\"pid\":2714,\"supervisor\":2713,\"scope\":\"zbx-zbx-" ++
    "e7dc6d.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915371,\"ended\":179" ++
    "4915371,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"true\"],\"labels\":[],\"limit" ++
    "s\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"publi" ++
    "shed\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zb" ++
    "x-545857\",\"state\":\"stopped\",\"pid\":2671,\"supervisor\":2670,\"scope\":\"zbx-zbx-5458" ++
    "57.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915371,\"ended\":1794915" ++
    "371,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"true\"],\"labels\":[],\"limits\":" ++
    "{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published" ++
    "\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0},\"sysctls\":[{\"key" ++
    "\":\"net.core.somaxconn\",\"value\":\"8192\"}]},{\"name\":\"zbx-f87c68\",\"state\":\"stopp" ++
    "ed\",\"pid\":2569,\"supervisor\":2568,\"scope\":\"zbx-zbx-f87c68.scope\",\"detached\":fals" ++
    "e,\"timed_out\":false,\"started\":1794915370,\"ended\":1794915370,\"reason\":\"exited\",\"" ++
    "exit_code\":1,\"command\":[\"numactl\",\"--interleave=all\",\"true\"],\"labels\":[],\"limi" ++
    "ts\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"publ" ++
    "ished\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"z" ++
    "bx-722d03\",\"state\":\"stopped\",\"pid\":2577,\"supervisor\":2576,\"scope\":\"zbx-zbx-722" ++
    "d03.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915370,\"ended\":179491" ++
    "5370,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"/numa-probe\"],\"labels\":[],\"l" ++
    "imits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"p" ++
    "ublished\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":" ++
    "\"zbx-caac35\",\"state\":\"stopped\",\"pid\":2636,\"supervisor\":2635,\"scope\":\"zbx-zbx-" ++
    "caac35.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915370,\"ended\":179" ++
    "4915370,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"true\"],\"labels\":[],\"limit" ++
    "s\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"publi" ++
    "shed\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0},\"ulimits\":{\"" ++
    "nofile\":{\"soft\":4096,\"hard\":8192}}},{\"name\":\"zbx-ce965f\",\"state\":\"stopped\",\"" ++
    "pid\":2561,\"supervisor\":2560,\"scope\":\"zbx-zbx-ce965f.scope\",\"detached\":false,\"tim" ++
    "ed_out\":false,\"started\":1794915370,\"ended\":1794915370,\"reason\":\"exited\",\"exit_co" ++
    "de\":0,\"command\":[\"numactl\",\"--interleave=all\",\"true\"],\"labels\":[],\"limits\":{" ++
    "\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published" ++
    "\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zbx-e6" ++
    "ea6d\",\"state\":\"stopped\",\"pid\":2655,\"supervisor\":2654,\"scope\":\"zbx-zbx-e6ea6d.s" ++
    "cope\",\"detached\":false,\"timed_out\":false,\"started\":1794915370,\"ended\":1794915370," ++
    "\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"true\"],\"labels\":[],\"limits\":{\"m" ++
    "emory_bytes\":null,\"pids\":null,\"cpu_millis\":null,\"shm_bytes\":268435456},\"network\":" ++
    "\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}" ++
    "},{\"name\":\"zbx-e96f99\",\"state\":\"stopped\",\"pid\":2545,\"supervisor\":2544,\"scope" ++
    "\":\"zbx-zbx-e96f99.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915370," ++
    "\"ended\":1794915370,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"sh\",\"-c\",\"ca" ++
    "t /proc/self/cgroup /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max\"],\"labels\":[],\"li" ++
    "mits\":{\"memory_bytes\":268435456,\"pids\":null,\"cpu_millis\":1500},\"network\":\"none\"" ++
    ",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"nam" ++
    "e\":\"zbx-92faf9\",\"state\":\"stopped\",\"pid\":2553,\"supervisor\":2552,\"scope\":\"zbx-" ++
    "zbx-92faf9.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915370,\"ended\"" ++
    ":1794915370,\"reason\":\"exited\",\"exit_code\":1,\"command\":[\"sh\",\"-c\",\"echo 1 > /s" ++
    "ys/fs/cgroup/memory.max\"],\"labels\":[],\"limits\":{\"memory_bytes\":268435456,\"pids\":n" ++
    "ull,\"cpu_millis\":null},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mount" ++
    "s\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zbx-b287f1\",\"state\":\"stopped\",\"pi" ++
    "d\":2536,\"supervisor\":2535,\"scope\":\"zbx-zbx-b287f1.scope\",\"detached\":false,\"timed" ++
    "_out\":false,\"started\":1794915370,\"ended\":1794915370,\"reason\":\"exited\",\"exit_code" ++
    "\":0,\"command\":[\"true\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null," ++
    "\"cpu_millis\":null},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":" ++
    "[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zbx-8a446d\",\"state\":\"stopped\",\"pid\":" ++
    "2616,\"supervisor\":2614,\"scope\":\"zbx-zbx-8a446d.scope\",\"detached\":false,\"timed_out" ++
    "\":false,\"started\":1794915370,\"ended\":1794915370,\"reason\":\"exited\",\"exit_code\":0" ++
    ",\"command\":[\"sh\",\"-c\",\"for e in /sys/fs/cgroup/*; do echo LS:${e##*/}; done; echo M" ++
    "EMORY:$(cat /sys/fs/cgroup/memory.max); echo CGROUP:$(cat /proc/self/cgroup); echo SYSCTL:" ++
    "$(cat /proc/sys/net/core/somaxconn)\"],\"labels\":[],\"limits\":{\"memory_bytes\":26843545" ++
    "6,\"pids\":null,\"cpu_millis\":null},\"network\":\"user\",\"published\":[],\"env\":[],\"wr" ++
    "itable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0},\"sysctls\":[{\"key\":\"net.core.somaxco" ++
    "nn\",\"value\":\"8192\"}]},{\"name\":\"zbx-ec5748\",\"state\":\"stopped\",\"pid\":2594,\"s" ++
    "upervisor\":2593,\"scope\":\"zbx-zbx-ec5748.scope\",\"detached\":false,\"timed_out\":false" ++
    ",\"started\":1794915370,\"ended\":1794915370,\"reason\":\"exited\",\"exit_code\":0,\"comma" ++
    "nd\":[\"sh\",\"-c\",\"for e in /sys/fs/cgroup/*; do echo LS:${e##*/}; done; echo MEMORY:$(" ++
    "cat /sys/fs/cgroup/memory.max); echo CGROUP:$(cat /proc/self/cgroup)\"],\"labels\":[],\"li" ++
    "mits\":{\"memory_bytes\":268435456,\"pids\":null,\"cpu_millis\":null},\"network\":\"host\"" ++
    ",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"nam" ++
    "e\":\"zbx-56f471\",\"state\":\"stopped\",\"pid\":2605,\"supervisor\":2604,\"scope\":\"zbx-" ++
    "zbx-56f471.scope\",\"detached\":false,\"timed_out\":false,\"started\":1794915370,\"ended\"" ++
    ":1794915370,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"sh\",\"-c\",\"for e in /s" ++
    "ys/fs/cgroup/*; do echo LS:${e##*/}; done; echo MEMORY:$(cat /sys/fs/cgroup/memory.max); e" ++
    "cho CGROUP:$(cat /proc/self/cgroup)\"],\"labels\":[],\"limits\":{\"memory_bytes\":26843545" ++
    "6,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published\":[],\"env\":[],\"wr" ++
    "itable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zbx-e108ac\",\"state\":\"st" ++
    "opped\",\"pid\":2586,\"supervisor\":2585,\"scope\":\"zbx-zbx-e108ac.scope\",\"detached\":f" ++
    "alse,\"timed_out\":false,\"started\":1794915370,\"ended\":1794915370,\"reason\":\"oom\",\"" ++
    "exit_code\":137,\"command\":[\"dd\",\"if=/dev/zero\",\"of=/dev/shm/fill\",\"bs=1M\",\"coun" ++
    "t=100\"],\"labels\":[],\"limits\":{\"memory_bytes\":67108864,\"pids\":null,\"cpu_millis\":" ++
    "null,\"shm_bytes\":67108864},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_m" ++
    "ounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"zbx-d4361b\",\"state\":\"stopped\"," ++
    "\"pid\":2478,\"supervisor\":2477,\"scope\":\"zbx-zbx-d4361b.scope\",\"detached\":false,\"t" ++
    "imed_out\":false,\"started\":1794915369,\"ended\":1794915369,\"reason\":\"exited\",\"exit_" ++
    "code\":0,\"command\":[\"sh\",\"-c\",\"ulimit -n; ulimit -Hn\"],\"labels\":[],\"limits\":{" ++
    "\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published" ++
    "\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0},\"ulimits\":{\"nofi" ++
    "le\":{\"soft\":4096,\"hard\":8192}}},{\"name\":\"zbx-062152\",\"state\":\"stopped\",\"pid" ++
    "\":2505,\"supervisor\":2504,\"scope\":\"zbx-zbx-062152.scope\",\"detached\":false,\"timed_" ++
    "out\":false,\"started\":1794915369,\"ended\":1794915369,\"reason\":\"exited\",\"exit_code" ++
    "\":0,\"command\":[\"cat\",\"/proc/sys/net/core/somaxconn\"],\"labels\":[],\"limits\":{\"me" ++
    "mory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"published\":[]" ++
    ",\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0},\"sysctls\":[{\"key\":\"" ++
    "net.core.somaxconn\",\"value\":\"8192\"}]},{\"name\":\"zbx-2d1cec\",\"state\":\"stopped\"," ++
    "\"pid\":2493,\"supervisor\":2492,\"scope\":\"zbx-zbx-2d1cec.scope\",\"detached\":false,\"t" ++
    "imed_out\":false,\"started\":1794915369,\"ended\":1794915369,\"reason\":\"exited\",\"exit_" ++
    "code\":0,\"command\":[\"df\",\"-k\",\"/dev/shm\"],\"labels\":[],\"limits\":{\"memory_bytes" ++
    "\":null,\"pids\":null,\"cpu_millis\":null,\"shm_bytes\":268435456},\"network\":\"none\",\"" ++
    "published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}},{\"name\"" ++
    ":\"apk1\",\"state\":\"stopped\",\"pid\":2462,\"supervisor\":2460,\"scope\":\"zbx-apk1.scop" ++
    "e\",\"detached\":false,\"timed_out\":false,\"started\":1794915368,\"ended\":1794915369,\"r" ++
    "eason\":\"exited\",\"exit_code\":0,\"command\":[\"apk\",\"add\",\"--no-cache\",\"numactl-t" ++
    "ools\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null}" ++
    ",\"network\":\"host\",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\"" ++
    ":0,\"gid\":0}}]}\n";
