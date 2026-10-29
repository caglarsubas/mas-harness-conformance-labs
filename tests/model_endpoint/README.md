# MEQ probe client core (CONF-MEQ-001A)

This root is the contract-independent core of roadmap item MODEL-EXIST-QUAL-001's campaign: the parts that run plan
revision 3 fixes whatever MEQ-CAMPAIGN-CONTRACT says. It is data and tests only, under the lane monitor's ruling
MON-R12-MEQC (Q-MEQC-1 to Q-MEQC-6, all (a)). It uses only the Python 3.12 standard library.

**No endpoint is contacted.** Nothing here runs against any server: `test_client.py` drives the client over
`socket.socketpair()` with an in-thread fake responder and patches the default connection factory to fail in every one
of its tests; `test_guard.py` and `test_evidence.py` never reach the factory. It runs as acceptance argv 16: `python3 -m unittest discover -s tests/model_endpoint -p test_*.py`.

## What is here

| File | Role |
|---|---|
| `_client.py` | the probe client: the base-URL guard, the fixed parameters, the injectable connection factory, JSON GET and POST, the streaming POST that reads server-sent events up to `[DONE]`, and the closed `MEQ_*` error set |
| `_evidence.py` | the per-profile evidence record: a builder, a closed-shape validator, canonical bytes |
| `test_guard.py` | every admitted and every refused base-URL class, with every resolver and connection call patched to fail |
| `test_client.py` | round trips, streaming, the refusals and every error code, over `socketpair()` only |
| `test_evidence.py` | the closed shape, statuses, row ids, no pooling, every leak class, a round trip per profile |

### The guard (owner decision Q-MEQ-SCOPE; Q-MEQC-4 (a))

- Admitted: the schemes `http` and `https`; IP literals in loopback (127.0.0.0/8, ::1) or the private ranges (10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16, fc00::/7); and the name `localhost`, mapped to 127.0.0.1 with no resolver call.
- Refused, each with its own code: link-local addresses (169.254.0.0/16, fe80::/10), the two IPv6 cloud metadata
  addresses inside fc00::/7 that `_client.py` lists (Q-MEQA-1 (a); provenance unverified), every other address
  (including the shared address space 100.64.0.0/10, 192.0.0.0/24 and 198.18.0.0/15, pinned by tests), every other
  name (never resolved), userinfo, a query, a fragment, an empty host, an invalid port, any other scheme and anything
  the guard cannot parse plainly.

### The fixed parameters

A 2 s connect timeout; a request timeout of 30 s for `dev-macos-arm64` and `linux-amd64-nvidia` and 600 s for
`linux-amd64-cpu`; an 8 MiB response bound (justified in `_client.py`), 1 MiB per event line; one request per
connection. The client uses `http.client` directly, so the proxy environment variables have no effect, and any 3xx is
the coded refusal `MEQ_REDIRECT_REFUSED`: a `Location` header is never followed.

### The evidence record (owner decision Q-MEQ-PROFILES)

One record per profile id, never pooled: `dev-macos-arm64` (`planeon.ollama`), `linux-amd64-cpu` (`planeon.llamacpp`)
and `linux-amd64-nvidia` (`planeon.vllm`). Each record carries one row per probe row of run plan section 5, in order,
with a status of exactly `PASS`, `FAIL`, `NOT_SERVED` or `NOT_RUN_ENV_UNAVAILABLE`.

The validator's leak check is **best-effort detection**. It scans every string of a record outside the shape's own
vocabulary and refuses what it catches: a URL (`://`, a token starting with `//`, or, as written in any letter case, a
percent-encoded scheme separator, an encoded double slash, or a doubly encoded colon or slash); the name `localhost`;
an e-mail-style account (`user@host`); a local path under a home, root, private or temporary directory; an IPv4 or
IPv6 literal, an integer, hex or short dotted IPv4 form bounded to address shapes (see `_short_ipv4`), or a dotted
quad with a hex or leading-zero part; a `:port`; a dotted host name, also inside a path or followed by `:` and letters;
and credential shapes (authorization, password,
secret and key markers, known key prefixes, signed, unsigned or two-segment JWT shapes, and long opaque tokens). The
host, JWT and short-IPv4 rules apply to every part of a token split on `/`, `\`, `#`, `&`, `~` and `:`.

Its limits:
- a denylist cannot be complete, and the check cannot recognise a bare account or host name without a dot or an `@`;
- some benign strings are refused as false positives: decimals with a whole part of 10 or more (`42.7 tok/s`,
  `99.9`), two- and three-part version strings (`Ubuntu 24.04`, `CUDA 12.4`, `Python 3.12.14`, `vLLM 1.0.0`) and
  integers from 2^24 up (a 20,000,000 byte count); `test_evidence.py` asserts them as a known limit;
- per MON-MEQ-EVIDENCE-TYPED, CONF-MEQ-001B makes every record field typed and closed before it writes any detail,
  and this leak check stays as defence in depth.

## What waits for MEQ-CAMPAIGN-CONTRACT

- the rows' pass rules (this packet fixes only the row ids and the statuses);
- the mapping of each `MEQ_*` code to a PI-D1 normalised class (each code carries a placeholder comment, and no mapping
  data exists yet);
- the binding to the MAS-RA-002 run manifest and MAS-RA-003 events;
- the run itself, against the owner's endpoint, in CONF-MEQ-001B under its own review rounds and the owner's
  authorisation (owner decision Q-MEQ-CANCEL's 5 s cancellation bound is applied there).

Whether the client moves into `src/` is that later packet's decision, under its own scoped exception.

## Why socketpair

The MEQ-CLIENT-0 dossier (section 2) recorded an experiment under the verify sandbox's profile
`(version 1) (allow default) (deny network*)`: binding or connecting a TCP socket on 127.0.0.1 is denied (errno 1),
while `socket.socketpair()` works, and `http.client.HTTPConnection` with a socketpair end set as its `sock` completes a
request and a response. So the client takes an injectable connection factory and the tests use no TCP at all, loopback
included (Q-MEQC-3 (a)).
