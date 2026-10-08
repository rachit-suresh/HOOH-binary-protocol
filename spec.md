# HOOH v1 — A Binary Frame Protocol for Persistent Request/Response over TCP



## 1. Scope and Goals

HOOH is a binary, frame-based application protocol carrying HTTP-like request/response semantics over a single persistent TCP connection. It replaces HTTP/1.1's text framing with fixed-size binary frames so that every message's boundary is known before its payload is read, and it reserves wire-format space so later versions can add multiplexing, negotiated limits, and header-block continuation without breaking v1 receivers. Version 1 supports one concurrent request stream per connection, indexed-name header encoding with length-prefixed literals, optional liveness probes, per-stream abort, and graceful shutdown. Request bodies may flow on the wire but carry no meaning in v1; receivers discard them. HOOH v1 does not define TLS, flow control, padding, server push, request-body semantics, or dynamic header compression. MUST, MUST NOT, SHOULD, and MAY are normative in their usual sense.



## 2. Conventions

**All integers are little-endian.** Byte values are written in hexadecimal. Frame-header field widths are stated in bits; all payload-grammar lengths are stated in bytes, suffixed `B`. A *frame* is one header-plus-payload unit (§4). A *stream* is one request/response conversation identified by a Stream ID (§7). The *client* opens the connection; the *server* accepts it.



## 3. Connection Establishment and Preface

Both peers greet. The client MUST send, as the first bytes of the connection, the ten-byte preface `HeLlOOlLeH` = `48 65 4c 6c 4f 4f 6c 4c 65 48`. The server MUST compare these bytes exactly; on mismatch it MUST close immediately without transmitting anything, and on match it MUST send the same ten bytes back at once. A peer MAY close at the first byte that differs and MUST NOT wait for all ten bytes to fail. The client MUST validate the server's preface before sending its first frame, and MUST close with a transport failure on mismatch. **Until the exchange completes — the client's preface validated by the server and the server's preface received by the client — both peers close silently on any error or timeout; no GOAWAY is sent before the greeting is done.** The preface is opaque magic, constant across all versions of this frame format; greeting in both directions lets whichever side dialed a wrong-protocol peer fail it before any frame is parsed.



## 4. Frame Layout

```

+-------------------------+-----------+-----------+--------------------------+

|   Length (24 bits)      | Type (4b) | Flags(4b) |   Stream ID (24 bits)    |

|        bytes 0–2        | byte 3 hi | byte 3 lo |        bytes 4–6         |

+-------------------------+-----------+-----------+--------------------------+

```

- **Length** — payload size in bytes, excluding this 7-byte header. The 24-bit width is the protocol's only size grammar: no frame can express more than 16,777,215 payload bytes.

- **Type** — frame type (§5); selects payload grammar, legal flags, and legal stream IDs.

- **Flags** — per-frame booleans (§6). Only bits 0–1 are defined in v1.

- **Stream ID** — the stream this frame belongs to (§7).



A receiver MUST read exactly `Length` payload bytes and MUST treat the next byte as the start of the following frame. A receiver **MUST skip frames of undefined Type — and of optional Types it does not implement — by `Length` bytes and resume parsing**; this skip is the protocol's forward-compatibility mechanism (§13). **Undefined flag bits MUST be ignored.** **A conforming receiver MUST accept any frame with Length ≤ 16,384 B;** above that floor a receiver MAY enforce an implementation size limit, handled per §11.

*Informative:* v1 defines no protocol-level cap below the grammar; limits are receiver policy until v1.1 introduces SETTINGS negotiation. Two conforming v1 implementations therefore interoperate guaranteed for frames up to 16,384 B, and above that up to the smaller of their implementation limits; senders bound for unknown peers SHOULD stay at or below the floor until negotiation exists.



## 5. Type Registry

| Type | Name | Status |

|---|---|---|

| 0x0 | DATA | body bytes; request-direction bodies are discarded in v1 (§8.1) |

| 0x1 | HEADERS | header block (request or response, by direction) |

| 0x2 | RST_STREAM | mandatory |

| 0x3 | PING | **optional** (§8.4) |

| 0x4 | GOAWAY | mandatory |

| 0x5 | PONG | **optional** (§8.5) |

| 0x6–0xF | *undefined* | skipped per §4 |



## 6. Flags

**Bit 0 is the least significant bit of byte 3.** **bit0 END_STREAM** — this frame carries the last payload bytes of its stream in its direction. **bit1 END_HEADERS** — this frame's header block is complete. Bits 2–3 are undefined and MUST be ignored.



| Type | END_STREAM | END_HEADERS |

|---|---|---|

| DATA | optional (set = last body frame in this direction) | MUST be 0 |

| HEADERS (request) | optional (set = request has no body) | MUST be 1 |

| HEADERS (response) | optional (set = empty body) | MUST be 1 |

| RST_STREAM, PING, GOAWAY, PONG | MUST be 0 | MUST be 0 |



A **defined** flag bit set where this table forbids it is a malformed-frame condition (§11).



## 7. Streams and Concurrency

Stream ID **0** denotes the connection itself. PING, PONG, and GOAWAY MUST use stream 0; HEADERS and DATA MUST NOT appear on stream 0. Request streams use **odd IDs, strictly increasing, never reused; gaps between consecutive IDs are legal.** The first is 1. A 24-bit ID space yields 8,388,608 odd IDs; **after using `0xFFFFFF` the client MUST NOT use more IDs on this connection; it MAY open a new connection for further requests.** A stream ID is *new* if it is odd and strictly greater than the highest odd ID used on this connection so far. A stream ID is a *gap* if it is odd, strictly less than the highest used odd ID, and has never been used. A stream ID is *open* from its HEADERS frame until END_STREAM has been seen in both directions or it is aborted, and *closed* thereafter. A rejected new ID counts as used and transitions directly to closed. **A stream-level error action (§11) closes the stream in both directions immediately; any END_STREAM still owed is discarded**, so an errored stream can never hold the one-stream limit hostage. **v1 permits at most one open request stream at a time**; a HEADERS opening a stream while one is open is a stream-level error on the new stream.



## 8. Payloads

**8.1 DATA** — raw bytes; no internal structure. **DATA sent in the request direction (client to server) carries a request body; v1 defines no semantics for request bodies, and the server MUST read such frames and discard them by Length. DATA sent in the response direction (server to client) carries response body bytes delivered to standard output.** DATA frames with Length 0 MUST NOT be sent.

**8.2 HEADERS** — a header block per §9. Request blocks MUST contain `:method` and `:path`, exactly once each. Response blocks MUST contain `:status`, exactly once. An empty body in either direction — including an empty file, or a request with no body — is expressed as HEADERS carrying END_HEADERS|END_STREAM with no DATA frames. **A server MUST NOT send any response frame on a stream before it has seen the request's END_STREAM, except an error response produced by §11 steps 3 to 6, which closes the stream instead of completing it; §11 step 7 is the only check that waits for the request's END_STREAM.** Consequently all request validation completes before any success response exists, and the only error possible after response HEADERS is a read failure, answered with RST_STREAM(INTERNAL).

**8.3 RST_STREAM** — `[error:1B]`; Length MUST equal 1 B. Sent only on the open stream; aborts it without closing the connection; the aborted stream receives no response. On stream 0: connection error. On a closed ID: MUST be ignored. On a new or gap ID: connection error.

**8.4 PING (optional)** — `[challenge:8B]`; Length MUST equal 8 B. An implementation that supports PING MUST also support PONG, MUST have at most one PING outstanding, and MUST answer a valid PING with PONG unless it is closing. An implementation that does not support PING MUST skip the frame per §4. Absence of a PONG therefore means *unknown*, not *dead*: a sender MUST NOT conclude liveness failure from silence, which the idle rule (§12) already governs.

**8.5 PONG (optional)** — `[challenge:8B]`; Length MUST equal 8 B; the outstanding challenge echoed verbatim. In an implementation that supports PONG, a PONG whose challenge does not match the outstanding PING is a connection-level error. A receiver MUST NOT answer a PONG.

**8.6 GOAWAY** — `[last_stream_id:3B][error:1B]`; Length MUST equal 4 B. `last_stream_id` is the highest stream ID whose request the sender has fully received (seen END_STREAM) and committed to answering. If none, it is 0. A server idle-closing after processing streams 1 and 3 sends 3. A client always sends 0, because v1 has no server-initiated streams. The sender will process no stream above it and will close after draining in-flight work. Either peer MAY send it; the receiver SHOULD drain and close. A client MAY retry idempotent requests (in v1, GET) above `last_stream_id` on a new connection.



## 9. Header Block

A block is concatenated fields consuming exactly `Length` bytes. One field is: `[name:1B]`; **if name = 0x00**, immediately followed by `[name-len:1B][name bytes]`; **then always** `[value-len:2B LE][value bytes]`. A field whose declared lengths overrun the remaining block, or a zero-length literal name, is malformed. Name `0x01–0x0A` = static table; `0x0B–0xFF` = malformed.

**Static table:** `1 :method · 2 :path · 3 :status · 4 host · 5 user-agent · 6 server · 7 date · 8 content-type · 9 content-length · 10 accept`.

Pseudo-headers (`:method :path` request / `:status` response) MUST precede all regular headers and appear exactly once. **A pseudo-header appearing in the wrong direction — `:status` in a request, or `:method` or `:path` in a response — is a stream-level error.** `:status` is three ASCII digits; `:method` is a case-sensitive ASCII token; `:path` begins with `/`. Literal names are sent lowercase and compared case-insensitively. **A literal name matching a static-table name is treated as that static name**, counting toward its rules including exactly-once and pseudo ordering. **An unknown literal name beginning with `:` is malformed** (unknown pseudo-headers carry unknown semantics); **an unknown literal name not beginning with `:` MUST be ignored.** Duplicate regular headers: last wins. `content-length`, if present, MUST be ASCII digits only, without a sign, fitting in 64 bits, and MUST equal the total DATA payload bytes of its message; a mismatch is a stream-level error; senders MAY omit it. An unknown *static index* is malformed, not skippable: the index vocabulary is closed and versioned, matching HPACK, where an out-of-range index is a decompression error; the open vocabulary is the literal path. **No reason phrases exist anywhere in HOOH.**



## 10. Request Semantics and Statuses

v1 defines method `GET`. Methods known but disallowed — `HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, PATCH, TRACE` — yield `405`; any other method token yields `501`. **Checks apply in a fixed order: block and value grammar (400), then method (405 or 501), then path (404); the first failing check decides the status.** A well-formed request body, if sent, is discarded per §8.1 and does not change the response. Statuses v1 produces: `200, 400, 404, 405, 413, 501`. Content-type mapping from file extension is implementation-defined.

`:path` handling is split into grammar checks (yielding 400) and path checks (yielding 404):

- **Grammar:** (a) bytes from the first `?` onward are discarded; (b) a NUL (0x00) byte in the remainder is malformed; (c) the remainder MUST begin with `/`.

- **Path:** (d) the remainder is normalized lexically, resolving `.` and `..`, collapsing consecutive slashes, and removing a trailing slash (`/` stays `/`); for example `/index.html/` becomes `/index.html`; **a `..` that escapes the root lexically yields `404` here, before any filesystem access**; (e) any remaining path component beginning with `.` yields `404`, hiding dotfiles like everything else; (f) the remainder is joined under the server root and resolved through symlinks, by `realpath` or an open-below-root descriptor, and containment is checked **component-wise, not as a string prefix**, so `/srv/www` does not contain `/srv/www-x`; **the dot rule of (e) is re-applied to the resolved path, so a symlink leading into a dot directory yields `404` like the directory itself**; (g) the resolved path MUST be a regular file, or a directory served as `<dir>/index.html` if that is a readable regular file; anything else — missing, escaped, special such as FIFO or device, directory without index, unreadable — yields `404`.

**Existence-hiding policy:** the wire never distinguishes missing, escaped, special, dotfile, and unreadable; all are the same anonymous `404`. The server logs the true reason to stderr. The server fixes the body length at open time (e.g., via `fstat`). Status `500` is reserved but not produced in v1: a read failure before the response is hidden as `404`, and a file that shrinks or errors during a read after the `200` response has started cannot be un-sent, so it aborts the stream with RST_STREAM(INTERNAL). Success → `200`.

**Response blocks:** error responses (`400, 404, 405, 413, 501`) MUST consist of exactly one HEADERS frame containing only `:status`, flags END_HEADERS|END_STREAM, and no body — hence **identical except for the Stream ID field** across occurrences. A `200` response MUST contain `:status`, SHOULD contain `content-type` when the body has a type, and MAY contain other headers. v1 performs no percent-decoding.



## 11. Error Handling

Two tiers, with role-dependent actions. **In this document, *malformed block* refers to header-block and value grammar violations (§9, §10), and *malformed frame* refers to frame shape, flag, and per-type Length violations (§6, §8).** **Stream-level:** a *server* MUST discard the stream's buffered state and MUST send HEADERS with the error status (`400`, or `413` for over-limit) and END_STREAM on that stream; a *client* MUST send RST_STREAM(PROTOCOL_ERROR) on that stream and treat the request as failed. Either way the stream closes (§7) and **the connection MUST remain open**. **Connection-level:** send GOAWAY(PROTOCOL_ERROR) then close, except preface mismatch and any failure before the preface exchange completes, which close with no frames (§3).



**Ordered frame processing**, both roles, after the preface exchange:

1. Read the 7-byte frame header. EOF at any point → silent close (§12).

2. Type undefined, or optional and not implemented → read and discard `Length` bytes in bounded chunks and resume at step 1. Skipping never allocates the payload and is **not** subject to the implementation size limit, so unknown future frames survive even when large.

3. Ownership and IDs: PING/PONG/GOAWAY on a non-zero stream, HEADERS or DATA on stream 0, or RST_STREAM on stream 0 → connection error. Non-zero even ID → connection error. **For a server, HEADERS on a *new* ID opens the stream (subject to the one-open-stream limit); HEADERS on a *gap* ID or on an already-closed ID is a connection error (stream ID reuse). For a client, HEADERS on any ID it did not open is a connection error.** HEADERS on an open stream in a direction that has already produced HEADERS on that stream is a stream error (each direction produces at most one HEADERS per stream), while the first HEADERS of the other direction is the normal half of the exchange. **A new ID counts as used from the moment it appears in a HEADERS frame; if that frame is rejected, the ID transitions directly to closed.** **For a client, any frame (HEADERS or DATA) arriving on an ID it has already aborted via RST_STREAM → ignore by discarding `Length`; this abort-ignore rule is checked before the new, gap, and closed checks.** DATA or RST on a **new** or **gap** ID → connection error. DATA or RST on a **closed** ID → ignore by discarding `Length`.

4. Size: `Length` above the receiver's implementation limit (never below 16,384 B, §4) → on stream 0, connection error; on a request stream, discard `Length` bytes then stream error with `:status 413`.

5. Shape: per-type Length (RST 1 B, PING/PONG 8 B, GOAWAY 4 B), zero-length DATA, defined flags per §6 (malformed frame); violation on a stream-0 frame → connection error; on RST on the open stream, or on HEADERS/DATA → stream error.

6. Semantics of control frames: RST on the open stream aborts it (§8.3); PING is answered with PONG by an implementation that supports PING; a PONG whose challenge does not match the outstanding PING (by an implementation that supports PONG) is a connection error; GOAWAY drains and closes.

7. Payload grammars (§9, §10) (malformed block), evaluated for a request once its END_STREAM is seen — the only step that waits for it (§8.2) — and for a response when its HEADERS frame arrives; violations (including `content-length` value grammar and mismatch) → stream error. **Catch-all:** any other violation of §6–§10 is a stream-level error.



**Client reception rules:**

| Event | Client action | Exit severity |

|---|---|---|

| DATA before HEADERS on its stream · malformed response block · missing `:status` · `:status` outside 100–599 · received 1xx · oversize response frame | RST_STREAM(PROTOCOL_ERROR) on that stream; request failed; connection stays open for remaining URLs | 3 |

| Complete error response (END_STREAM) received before the client finishes sending its request | Client finishes sending the current frame, stops sending further frames on that stream, and treats the stream as closed | 1 or 2 (per status) |

| RST_STREAM from server on its stream | request failed (truncated if a 200 was already seen); the client continues with remaining URLs on the same connection, next odd ID | 3 |

| GOAWAY with `last_stream_id` above the highest ID the client has opened | GOAWAY(PROTOCOL_ERROR) + close; remaining URLs fail | 3 |

| GOAWAY with `last_stream_id` below its current stream | request unprocessed; report failure; every remaining URL in the invocation fails with severity 3 and no second connection is opened | 3 |

| GOAWAY with `last_stream_id` at or above its current stream, but not above the highest ID the client has opened | finish current stream normally; every remaining URL fails with severity 3 and no second connection is opened | 3 |

| EOF mid-response · no bytes received for 60 s while a request is outstanding | transport failure; close; remaining URLs fail | 3 |

| Response frame on an ID it never opened, on an even ID, or on an ID it opened but which is already closed (unless aborted by client RST) | GOAWAY(PROTOCOL_ERROR) + close; remaining URLs fail | 3 |

| `:status` 4xx / 5xx | request failed | 1 / 2 |



**Protocol error enum** (RST_STREAM/GOAWAY payload): `0 NO_ERROR · 1 PROTOCOL_ERROR · 2 CANCELLED · 3 INTERNAL`. **A receiver MUST treat any received protocol error code outside the range 0–3 as PROTOCOL_ERROR (1).** Implementation size limits are reported at the status layer (`413`), never in this enum.



## 12. Lifecycle

Connections are persistent by default; the server MUST NOT close after responding. The server closes only upon GOAWAY (including server-initiated shutdown), idle timeout, connection-level error, preface mismatch, or EOF. **EOF (`recv` returns 0) at any point — between frames, mid-header, mid-payload — means silent close; no GOAWAY is sent into a dead connection,** and any close before the preface exchange completes is likewise silent (§3). A connection is *idle* when **no bytes at all, preface included, have transferred in either direction for 60 s, counted from accept;** then GOAWAY(NO_ERROR) + close. Traffic in either direction resets the clock, so active transfers and open streams with traffic are never idle; only silence reaps, which is what makes half-open requests and vanished peers safely collectable. *Informative:* a sender dribbling one byte per minute defeats the idle clock; v1 accepts this and defers a per-stream deadline to v1.1. The client MAY close at any time after its final response; closing is not a violation.



## 13. Extensibility and Versioning

The MUST-skip (undefined or unimplemented-optional Type) and MUST-ignore (undefined flag bits) rules of §4 are HOOH's versioning mechanism for *additive* change: future versions may introduce types and flag bits that v1 receivers survive. Reserved: flag bits 2–3; Types 0x6–0xF; even stream IDs, for future server-initiated streams; stream concurrency above one; semantics for request bodies. *Version discovery:* **a v1.1 peer sends SETTINGS immediately after the preface and operates in v1 mode until it receives a SETTINGS frame from the other side; extensions are used only between peers that have both sent SETTINGS. A peer that sends no SETTINGS is treated as v1** — a v1 server simply skips the v1.1 client's SETTINGS by the §4 rule and answers in v1 forever. *Informative, honest limits:* semantic extensions are not covered by the skip rule — a v1.1 peer sending CONTINUATION (END_HEADERS=0) or a second concurrent stream to a v1 peer receives v1's §6/§7 answers (400) — which is why negotiation must precede extension use. v1.1 roadmap, same header and preface: SETTINGS with negotiated maximum frame size; multiplexing; CONTINUATION giving END_HEADERS real semantics; request-body semantics over syntax v1 already carries; a per-stream deadline.



## 14. Design Rationale

| Choice | Why |

|---|---|

| Seven-byte fixed header | One read answers length, kind, owner, and finality. A fixed size means no delimiter scanning, and it is what makes the skip rule possible at all. |

| Length 24 bits | Any single frame this protocol family is likely to want fits within it, while what is allowed today stays a policy decision separate from the grammar; the 16,384 B acceptance floor then gives every pair of implementations a guaranteed interoperable size. |

| Stream ID 24 bits | It shares the length field's little-endian helper, and with millions of client streams per connection, running out becomes a scheduled reconnect rather than a wrap. |

| Type 4 bits | Three bits would hold eight values, six used, leaving only two for growth; four bits keep a real extension budget and still share one byte with the flags, so the header stays unpadded. |

| Flags 4 bits | Two meanings serve this version and two remain for later; ignoring unknown bits lets future flags age gracefully. |

| Little-endian | HOOH breaks network byte order on purpose: with no installed base, one order rule covers every field, and 24-bit fields decode with a native load and mask on x86 and ARM hosts. The readability cost in hexdumps is accepted openly and paid in annotation, since every handed-in byte is labelled anyway. |

| Symmetric preface | Wrong-protocol detection should work for whichever side dialed; a client that reaches an HTTP server otherwise parses garbage as a multi-megabyte length and waits. The cost is one round trip before the client's first frame, which on localhost is invisible. |

| Odd client IDs, even reserved | Parity is a free validity check today and leaves room for server-initiated streams later without renumbering anything; legal gaps keep the rule monotonic rather than arithmetic. |

| Omissions: padding, priority, reason phrases, continuation | The wire carries only what a receiver must act on now. Header blocks fit one frame, so no reassembly machinery exists to break. |

| Skip and ignore rules | Length makes unknown kinds steppable and reserved bits make unknown flags predictable, so extension is structural rather than promissory; skipping before the size check keeps even oversized future frames survivable, and the limits of skipping are stated alongside it. |

| Closed index vocabulary, open literal vocabulary | A bad index means two peers disagree about a shared table, which is an error; a new regular name arriving as a literal is an extension old receivers ignore, while an unknown pseudo-header is rejected because its semantics cannot be known. |

| Two-tier errors and ordered processing | A bad message costs its stream and not the conversation; only framing the receiver can no longer trust ends the connection. One ordered check list means two implementations cannot disagree about which rule fires first. |

| No protocol frame cap in v1, but an acceptance floor | Capping senders is a negotiation and negotiation arrives with SETTINGS; the floor guarantees interop for ordinary frames while private limits stay private policy. |

| Request bodies carried but meaningless in v1 | The syntax stays stable so the next version adds meaning without rewiring, and silence-based idle reaps any body that never finishes. |

| Idle minute, counted from accept over all bytes | Persistent connections accumulate peers that vanished without closing, and silence long enough in both directions is the only honest evidence of absence, including from a client that never completes its preface. |

| Optional liveness probes | Conformance stays small for implementations that skip them, skipping is itself the skip rule at work, and one-outstanding-PING plus no-liveness-from-silence keeps the option free of dead-peer ambiguity. |

| Existence-hiding and near-identical errors | The wire answers every unservable path with one anonymous reply, differing only in Stream ID, and the truth lives in the server log where operators read it. |

| Ten indexed names | Exactly the ten headers the implementation sends across a single exchange (five from the client, five from the server); names cost one byte and values pay their own length. |



## 15. Worked Example

```
client  48 65 4c 6c 4f 4f 6c 4c 65 48                          preface "HeLlOOlLeH"

server  48 65 4c 6c 4f 4f 6c 4c 65 48                          preface echoed after match

client  3c 00 00 | 13 | 01 00 00                               HEADERS len=60 B stream=1 flags=ES|EH
          01 03 00 47 45 54                                    :method = "GET"
          02 0b 00 2f 69 6e 64 65 78 2e 68 74 6d 6c           :path = "/index.html"
          04 0e 00 31 32 37 2e 30 2e 30 2e 31 3a 39 30 38 30   host = "127.0.0.1:9080"
          05 0e 00 68 6f 6f 68 2d 62 63 75 72 6c 2f 31 2e 30   user-agent = "hooh-bcurl/1.0"
          0a 03 00 2a 2f 2a                                    accept = "*/*"

server  48 00 00 | 12 | 01 00 00                               HEADERS len=72 B stream=1 flags=EH
          03 03 00 32 30 30                                    :status = "200"
          06 0f 00 68 6f 6f 68 2d 62 73 65 72 76 65 2f 31 2e 30 server = "hooh-bserve/1.0"
          07 1d 00 46 72 69 2c 20 30 39 20 4f 63 74 20 32 30 32 36 20 31 32 3a 30 30 3a 30 30 20 47 4d 54 date = "Fri, 09 Oct 2026 12:00:00 GMT"
          08 09 00 74 65 78 74 2f 68 74 6d 6c                  content-type = "text/html"
          09 01 00 35                                          content-length = "5"

        05 00 00 | 01 | 01 00 00 | 68 65 6c 6c 6f              DATA len=5 B stream=1 flags=ES "hello"
```

*Informative:* this example illustrates the complete 10-header single exchange in wire order; the hand-in annotated hexdump is regenerated deterministically from live `bcurl -v` capture.



## Appendix A (informative) — Reference Programs

`bserve <root> <port>` serves files under `<root>`. After sending GOAWAY, the server half-closes the write side and reads to EOF, bounded to about two seconds, before closing. `bcurl [-v] <url>...` fetches the URLs sequentially over **one** connection (streams 1, 3, 5…); **all URLs in one invocation MUST share host and port, else usage error.** If the client exhausts its 24-bit odd ID space, it fails the remaining URLs with severity 3. bcurl never opens a second connection. URL grammar: optional `http://` prefix ignored, then `host:port/path`; port optional, default 9000; path optional, default `/`. Bodies go to stdout, all diagnostics to stderr. Exit codes: 0 = all responses 2xx or 3xx (v1 produces neither 1xx nor 3xx); otherwise the worst severity seen, ordered 4 (usage) > 3 (transport/framing) > 2 (5xx) > 1 (4xx). `-v` prints **both directions in wire order, prefaces as the first two lines**; per frame: direction arrow (`->` sent, `<-` received), byte offset, decoded 7-byte header (Length, Type name, flag names, Stream ID), then payload hex with per-type annotation (header fields decoded to names and values; DATA shown as hex plus printable ASCII).
