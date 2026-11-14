# S2: `zigbox.lazy.Source` checked against Zigcube's swarm

*Decided 2026-11-14, by slice 3 (a check, not a ruling: the gaps go to the supervisor).*

Open question 13 of `docs/briefs/S2-lazy-start.md` asked for `lazy.Source` to be checked against
Zigcube's `docs/swarm.md` and `docs/peer.md`. Slice 3 read them at zigcube `ebfbac5` (docs only, not
the swarm's source such as `fetch_plan.zig`).

**Verdict: fits with a small change, not yet made.** The interface is unchanged in slice 3; the
change below needs a ruling first.

## Gaps

1. **Fetch key (must change).** Zigcube serves a chunk by its hash, `GET /v1/peer/chunk/<hash>`
   (`peer.md`, the serving paragraph; `swarm.md`, `receive` checks "against the chunk list").
   `Source.fetch` passes `(id, index)` only, so an adapter cannot build the request without its own
   copy of the chunk lists. The resolver already holds the expected hash (and length) of every chunk
   it asks for. Proposal: `fetch` also takes the chunk's `Digest` and expected length.
2. **Which peer lied (should change).** The swarm strikes a peer on a bad hash and reports it once,
   naming it (ZC-W0601, `swarm.md` "Trust"). `lied(context, id, index)` does not say which peer
   served the bytes, so a swarm-wide `Source` must remember it per chunk across up to 10 resolver
   threads. Proposal: one `Source` per peer (the resolver's model, so its `name` names the peer), or
   `fetch` returns an opaque peer token that `lied` receives back.
3. **Peer choice and health (decide).** The swarm picks the peer itself (filter, 2 requests per
   peer, 8 per node, bandwidth, `swarm.md` "Source"). If Zigcube passes one `Source` for the whole
   swarm, the resolver's down state (30 s of failures, a probe every 5 s) applies to the whole
   swarm, not to one peer. That is acceptable but should be a stated choice.
4. **Bandwidth caps (decide).** The swarm's token buckets can answer "wait until"; `fetch` has no
   such result. The adapter either waits inside `deadline_ms` or answers `NotFound` (which moves on
   to the registry at once). Either works with the resolver as built; Zigcube should choose.

## What fits

- The errors map: a peer's refusal is `NotFound`, its timeout `TimedOut`, the rest `Failed`
  (`swarm.md`, `receive`).
- Verification is the resolver's, never the source's; Zigcube trusts peers "for speed only".
- The chunk is 1 MiB on both sides, one chunk per request; no batching is needed.
- Concurrent calls are fine; no cancellation hook is needed, as `deadline_ms` is a ceiling and
  Zigcube's own peer reply limit (5 s) is under the resolver's attempt timeout (10 s).
