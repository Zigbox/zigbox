# M4b · Mac: public DNS fallback when the Mac has no IPv4 resolver

*Decided 2026-10-30, after the `mac.yml` run 41136813336 (15 of 31 steps failed with ZBX-E0502).*

The guest asks the DNS servers the Mac asks, IPv4 only (`src/mac/dns.zig`). A Mac whose only resolver is an IPv6 router (`fe80::...%en0`) gives the field `-`, and the guest was left with the NAT gateway, which refuses DNS: every name failed to resolve. **Only in that case** the guest's `/etc/resolv.conf` is 1.1.1.1 (Cloudflare), 8.8.8.8 (Google) (`vm_protocol.dns_fallback`), then the DHCP gateway. A Mac with an IPv4 resolver is unchanged: its resolvers, then the gateway, and no public resolver is ever added. No new protocol field: the guest decides from `-`.

The cost is a privacy change in that one case: the machine's lookups (a pull's registry names, a container's) go to Cloudflare and Google. So the command that starts the machine prints `warning[ZBX-W1003]`, once per boot, and the fix is a network with an IPv4 DNS server, then `zbx vm stop`. The public resolvers come first because `--net user` goes through pasta, which forwards to the first nameserver of the guest's file only; with the refusing gateway first, `nslookup` in a `--net user` container timed out (measured 2026-10-30 on a phone tether, IPv6-only with 464XLAT).
