# HOOH v1 — A Binary Frame Protocol for Persistent Request/Response over TCP

A standard-compliant, zero-dependency C++17 implementation of the **HOOH v1** application protocol, featuring the `bserve` HTTP-like file server, the `bcurl` client utility, comprehensive automated test suites, and an interactive decision workflow architecture.

---

## 1. Protocol Architecture & Overview

HOOH is a binary, frame-based application protocol carrying HTTP-like request/response semantics over a single persistent TCP connection. It replaces text framing with fixed 7-byte binary frames so that message boundaries are deterministically known before reading payloads.

### Key Protocol Invariants
* **7-Byte Fixed Framing**: `[Length 24b LE][Type 4b | Flags 4b][Stream ID 24b LE]`.
* **10-Byte Greeting Handshake**: Both peers exchange and validate the magic preface `HeLlOOlLeH` before frames can flow (§3).
* **Single Concurrent Stream**: Version 1 allows exactly **one open request stream** per connection (§7).
* **Odd Client-Initiated Streams**: Streams are numbered $1, 3, 5, \dots$; even stream IDs are strictly forbidden (§7).
* **Stream 0 Connection Control**: Stream ID `0` is strictly reserved for control frames (`PING`, `PONG`, `GOAWAY`).
* **60-Second Inactivity Clock**: Complete silence in both directions for 60 seconds triggers `GOAWAY(NO_ERROR)` and connection termination (§12).
* **Existence Hiding**: Unauthorized paths, hidden dotfiles, and missing resources all return `404 Not Found` with an identical frame shape (§10).
* **Status 500 Reserved**: Servers never return status 500; disk read failures are hidden as 404 or aborted mid-stream with `RST_STREAM(INTERNAL)` (§10).

---

## 2. Deliverables & Documentation Index

| Deliverable | File | Description |
|---|---|---|
| **Deliverable 1** | [`spec.md`](spec.md) | The complete, original normative specification of the HOOH v1 protocol. |
| **Deliverable 2** | [`apps/bserve_main.cc`](apps/bserve_main.cc)<br/>[`apps/bcurl_main.cc`](apps/bcurl_main.cc) | Reference implementation: multi-threaded server (`bserve`) and client (`bcurl`). |
| **Deliverable 3** | [`annotated_hexdump.md`](annotated_hexdump.md) | Annotated wire trace from actual `bcurl -v` output against `bserve`, matching §15. |
| **Workflow Map** | [`WORKFLOW.md`](WORKFLOW.md) | Full end-to-end continuous decision tree with verified Mermaid diagrams, source code traceability, and bug catalog. |

---

## 3. Project Structure

```
├── apps/
│   ├── bserve_main.cc     # Multi-threaded static file daemon
│   └── bcurl_main.cc      # Reference client with sequential stream pipeline
├── hooh/
│   ├── frame.h / .cc      # 7-byte fixed header codec & endianness helpers
│   ├── headerblock.h / .cc# Indexed static table (1..10) & literal header codec
│   ├── pathutil.h / .cc   # Path grammar, lexical normalizer & realpath confinement
│   ├── session.h / .cc    # §11 state machine, 1-stream concurrency, frame dispatch
│   ├── fileserve.h / .cc  # Chunked body streamer & standard error response builder
│   ├── hexdump.h / .cc    # -v wire tracing formatter
│   └── net_compat.h       # Cross-platform socket layer (POSIX & Winsock2)
├── scripts/
│   └── generate_annotated_hexdump.py # Deterministic socket sniffer & protocol dissector
├── tests/
│   ├── test_golden.cc     # §15 Worked Example byte-for-byte golden assertion
│   ├── test_unit.cc       # C++ unit tests for frames, headers, and paths
│   ├── conformance.py     # 31 raw TCP socket conformance test cases
│   └── test_bcurl.py      # 9 client reception and exit code severity tests
├── annotated_hexdump.md   # Deliverable 3: Deterministic annotated wire trace
├── spec.md                # Deliverable 1: Normative specification
├── WORKFLOW.md            # Comprehensive decision tree & verified Mermaid diagrams
├── Makefile               # Strict compilation targets (-Wall -Wextra -Werror -O2)
└── README.md              # Repository documentation
```

---

## 4. Building the Project

### Requirements
* C++17 conforming compiler (`g++` or `clang++`).
* GNU `make`.
* Python 3.8+ (for integration and conformance test suites).
* Works natively on Linux, macOS, and Windows (via MinGW / MSYS2).

### Build Commands
```bash
# Build both bserve and bcurl binaries
make

# Build individual targets
make bserve
make bcurl

# Build and run C++ tests
make test
```

---

## 5. Usage & Examples

### Running the Server (`bserve`)
```bash
# Syntax: bserve <root-directory> <port>
./bserve test_root 9000
```
* Serves files located within `test_root`.
* Maps directory requests (e.g. `/`) to `index.html`.
* Enforces single-stream concurrency and 60-second inactivity timeouts.

### Running the Client (`bcurl`)
```bash
# Fetch a single URL
./bcurl http://127.0.0.1:9000/index.html

# Fetch multiple URLs sequentially over a single persistent TCP connection
./bcurl http://127.0.0.1:9000/index.html http://127.0.0.1:9000/test.txt

# Enable verbose wire tracing (-v) to view both directions in wire order
./bcurl -v http://127.0.0.1:9000/index.html
```

### Exit Code Severity Hierarchy
`bcurl` computes its final process exit code using the worst severity observed:
$$\text{Exit Code} = \max(\text{severities seen}) \quad \text{where} \quad 4 > 3 > 2 > 1 > 0$$
* **`4`**: Command-line usage error (mismatched host:port, invalid URLs).
* **`3`**: Transport failure, preface mismatch, timeout, framing error, or RST_STREAM.
* **`2`**: Server error (`5xx` response status).
* **`1`**: Client error (`4xx` response status).
* **`0`**: Success (`2xx`/`3xx` responses on all URLs).

---

## 6. Comprehensive Testing Suite

All tests are verified and passing at **100%**:

```bash
# 1. Run §15 Golden byte-exact reference test
./test_golden.exe

# 2. Run C++ unit test suite
./test_unit.exe

# 3. Run 31 raw TCP socket conformance tests
python tests/conformance.py

# 4. Run 9 bcurl client tests
python tests/test_bcurl.py
```

### Conformance Highlights (31 Socket Tests)
* **Preface Handshake**: Exact echo, byte-1 mismatch silent close, byte-5 mismatch silent close, short EOF.
* **Stream Routing**: Stream 0 control rules, even stream ID rejection, stream ID reuse rejection, gap reuse rejection.
* **Concurrency**: Rejection of stream 3 while stream 1 is open (400), with stream 1 remaining fully operational.
* **Frame Limits**: Forward-skip of unknown types (`0x6..0xF`), 16 KiB oversize frame handling (`413`).
* **Shape & Flags**: Zero-length DATA rejected, DATA with `END_HEADERS` rejected, atomic headers enforced.
* **Request Semantics**: Method `405` (POST), `501` (unknown token), query string stripping, dotfile `404` hiding, directory `index.html` resolution, content-length mismatch `400`.

---

## 7. Implementation Traps & Protocol Architecture Design

### A. Code Bugs (Identified & Resolved in C++ Implementation)
1. **Active Stream State Wipeout**: Calling `close_stream(new_id)` on a rejected concurrent stream reset `current_stream_state_`, wiping the open stream's buffered headers. Scoped reset strictly to `if (open_stream_id_ == id)`.
2. **Client Stream Desync**: Client session failed to record `open_client_stream(id)` on request send, causing valid server responses to be rejected as unsolicited.
3. **Windows TCP RST 10054**: Server closing immediately on preface mismatch while client bytes were in-flight raised `WSAECONNRESET` instead of clean FIN. Handled cleanly in test harness.

### B. Protocol Design Invariants & Security Choices
1. **Handshake Silence Precedence (§3 vs §12)**: §3 explicitly commands silent close with no `GOAWAY` before the greeting completes, superseding §12's idle timeout rule during connection establishment.
2. **Existence-Hiding Security Policy & Reserved Status 500 (§10)**: Prevents oracle attacks probing internal file existence and disk permissions. Missing, unreadable, and escaping paths all return uniform `404`. Status 500 is reserved but intentionally unproduced in v1.
3. **Uniform Error Frame Wire Invariant (§10)**: Error responses (400, 404, 405, 413, 501) consist of exactly one HEADERS frame containing only `:status`, `ES|EH`, and zero body bytes.
4. **Lexical URL Normalization (§10(d))**: Lexical normalization collapses `/index.html/` to `/index.html`, standard for POSIX-like virtual URL file systems.
5. **bcurl Single-Connection Mandate (Appendix A)**: Enforces the assignment's strict "one socket per invocation" rule. Remaining URLs upon 24-bit stream ID exhaustion fail with severity 3.
6. **Keepalive Liveness Traffic Refresh (§8.4, §12)**: Outgoing and incoming PING/PONG frames constitute valid wire traffic, properly resetting the 60s idle timer to keep persistent connections alive.
7. **Receiver Acceptance Floor vs Sender Cap (§4)**: The 16 KiB sender cap was removed (senders can send up to the 16 MiB grammar ceiling). Conforming receivers MUST accept payloads up to *at least* 16,384 B without rejecting them, configuring `kImplLimit >= 16,384 B` for higher limits.

For full architectural diagrams and deep-dive analysis, refer to [`WORKFLOW.md`](WORKFLOW.md).
