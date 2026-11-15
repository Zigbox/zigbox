# Lazy start: the peer source interface

*Decided 2026-11-14, by the supervisor (rulings on the slice 3 review), recorded by the slice 3 fix.*

The slice 3 reviews found the `lazy.Source` interface ambiguous on what a peer is asked for, who
is told of a lie, and what a short or slow answer means. The rulings, now in `src/lazy/lazy.zig`:

1. **`fetch` takes the chunk's digest and length** (`lazy.Request`). The object id and the chunk's
   index travel with them as hints for a source that files chunks by object; what is asked for is
   the digest, and the resolver checks the bytes against it.
2. **`fetch` returns an opaque peer token** (`lazy.Fetched.peer`), and the resolver passes it back to
   `lied()` with the same request. A source that stands for many peers (the swarm) knows from the
   token which peer sent the wrong bytes.
3. **The swarm is one `Source`.** It keeps its own down state per peer token, and is down to the
   resolver only when no peer serves: it fails or times out only when none of its peers answered.
4. **Bandwidth caps wait inside the timeout.** A source that is rate limited waits within the
   request's `timeout_ms` and then returns `TimedOut`, never `NotFound` (which would tell the resolver
   the chunk is not there, and move on for good).
5. **`deadline_ms` is renamed `timeout_ms`** in `Source.fetch` and `Range.fetch`: it is the time
   this one attempt may take, not the read's deadline.

Two rules from the same review fix what a source's answer means:

- **Only wrong bytes are a lie.** An answer shorter than asked (`Fetched.length` below the request's
  length, or a range that ends early) is a failed fetch, like `Failed`, and never names the source.
  A lie is bytes that do not hash to the chunk's digest.
- **A read's bound is its own.** A read gives up `lazy_read_deadline_ms` after it began (or
  `lazy_down_fail_ms` while every source it can use is down), however many times it asks again and
  whoever else waits on the same chunk.

The reasons: a short answer is what a dropped connection looks like, and naming a peer a liar for it
would let a flaky network evict honest peers; the digest is the only name a content-addressed peer
needs, and the token is the only way a multi-peer source can act on `lied()`.
