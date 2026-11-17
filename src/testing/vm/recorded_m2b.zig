//! What demo-m2b's guest printed, copied byte for byte from the log of run
//! `run` below (the `vm| ` echo lines and the timestamps removed), for the tests of
//! checks_m2b.zig. Refresh it from a new run's log; never edit the text by hand.

pub const run = "44056029258";

/// E0311 in text mode, `--ulimit nofile=` one above the demo user's hard limit.
pub const e0311_text =
    "error[ZBX-E0311]: --ulimit is above your own hard limit\n" ++
    "  cause  --ulimit nofile asks for a hard limit of 1048577, above your own,\n" ++
    "         1048576; a rootless run can't raise it\n" ++
    "  fix    raise it for logins (then log in again):    echo \"$(id -un) hard nofile 1048577" ++
    "\" | sudo tee -a /etc/security/limits.conf\n" ++
    "         or for the user manager, under [Service]:   sudo systemctl edit user@1000.service" ++
    "\n" ++
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
    "s.conf\",\"needs_root\":true},{\"sentence\":\"or for the user manager, under [Service]:\"," ++
    "\"command\":\"sudo systemctl edit user@1000.service\",\"needs_root\":true}],\"docs\":\"htt" ++
    "ps://zigbox.github.io/zigbox/errors/E0311.html\",\"omitted\":{\"causes\":0,\"while\":0,\"c" ++
    "ontext\":0,\"fixes\":0}}\n";

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
    "tmpfs                   262144         0    262144   0% /dev/shm\n" ++
    "--- stderr\n";

/// `zbx --output json ps` with the container v0.5.2 started.
pub const ps_old =
    "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"m2bold\",\"state\":\"running\",\"pid" ++
    "\":2727,\"supervisor\":2726,\"scope\":\"zbx-m2bold.scope\",\"detached\":true,\"timed_out\"" ++
    ":false,\"started\":1794908114,\"ended\":null,\"reason\":\"none\",\"exit_code\":null,\"comm" ++
    "and\":[\"sleep\",\"300\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"" ++
    "cpu_millis\":null},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[]" ++
    ",\"user\":{\"uid\":0,\"gid\":0}}]}\n";

/// `zbx stop` of that container.
pub const stopped =
    "m2bold stopped (killed), exit code 137\n";
