# `put_tree`: a checked tree put for untrusted bytes
*Decided 2026-11-03, by the Z1/Z5 slice.*

`trees.put_checked` (re-exported as `store.put_tree`) hashes the bytes, compares with the claimed id and returns `error.Malformed` on a mismatch or a bad encoding (`check_encoding`) instead of asserting, then stores under the shared store lock like other mutations. The asserting `put` stays for trusted callers. `has` is added for trees and objects so a peer can skip what it has.

See `src/store/trees.zig`, `src/fuzz_peer.zig`.
