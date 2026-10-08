# HOOH v1 — Deterministic Annotated Wire Hexdump (Deliverable 3)

> **Verification Notice**: This document is generated **deterministically by an automated protocol dissector** (`scripts/generate_annotated_hexdump.py`) that captures raw socket bytes from a live execution of `bcurl -v` against `bserve` and decodes every frame, header, and flag using the normative tables defined in the HOOH v1 specification (§3, §4, §5, §6, §8, §9, §15). **No manual edits or hand-typed values.**

---

## 1. Live Execution Environment & CLI Capture

```bash
# Server Daemon:
./bserve test_hexdump_root 9081

# Client Invocation with Verbose Wire Tracing:
./bcurl -v http://127.0.0.1:9080/index.html
```

*Note: A transparent TCP proxy sniffer runs on port 9080, forwarding traffic to `bserve` on port 9081 to capture both directions directly from the socket without altering frame timings or payloads.*

### Live Terminal Output Captured

**`bcurl` STDOUT (Received Body Payload):**
```text
hello
```

**`bcurl` STDERR (Built-in Verbose Diagnostic Wire Trace):**
```text
-> [000000] 48 65 4c 6c 4f 4f 6c 4c 65 48  preface "HeLlOOlLeH"
<- [000000] 48 65 4c 6c 4f 4f 6c 4c 65 48  preface "HeLlOOlLeH"
-> [000010] len=60 B type=HEADERS flags=ES|EH stream=1
     :method = "GET"
     :path = "/index.html"
     host = "127.0.0.1:9080"
     user-agent = "hooh-bcurl/1.0"
     accept = "*/*"
<- [000010] len=72 B type=HEADERS flags=EH stream=1
     :status = "200"
     server = "hooh-bserve/1.0"
     date = "Fri, 09 Oct 2026 12:00:00 GMT"
     content-type = "text/html"
     content-length = "5"
<- [000089] len=5 B type=DATA flags=ES stream=1
     68 65 6c 6c 6f                                   |hello|
```

**Process Exit Code**: `0` (Severity 0: Success)

---

## 2. Raw Socket Packet Capture (Hex & ASCII)

### Client to Server Raw Byte Stream (Total: 77 Bytes)

```text
Offset    Hex                                                ASCII
-------   ------------------------------------------------   ----------------
000000    48 65 4c 6c 4f 4f 6c 4c 65 48 3c 00 00 13 01 00    HeLlOOlLeH<.....
000010    00 01 03 00 47 45 54 02 0b 00 2f 69 6e 64 65 78    ....GET.../index
000020    2e 68 74 6d 6c 04 0e 00 31 32 37 2e 30 2e 30 2e    .html...127.0.0.
000030    31 3a 39 30 38 30 05 0e 00 68 6f 6f 68 2d 62 63    1:9080...hooh-bc
000040    75 72 6c 2f 31 2e 30 0a 03 00 2a 2f 2a             url/1.0...*/*
```

### Server to Client Raw Byte Stream (Total: 101 Bytes)

```text
Offset    Hex                                                ASCII
-------   ------------------------------------------------   ----------------
000000    48 65 4c 6c 4f 4f 6c 4c 65 48 48 00 00 12 01 00    HeLlOOlLeHH.....
000010    00 03 03 00 32 30 30 06 0f 00 68 6f 6f 68 2d 62    ....200...hooh-b
000020    73 65 72 76 65 2f 31 2e 30 07 1d 00 46 72 69 2c    serve/1.0...Fri,
000030    20 30 39 20 4f 63 74 20 32 30 32 36 20 31 32 3a     09 Oct 2026 12:
000040    30 30 3a 30 30 20 47 4d 54 08 09 00 74 65 78 74    00:00 GMT...text
000050    2f 68 74 6d 6c 09 01 00 35 05 00 00 01 01 00 00    /html...5.......
000060    68 65 6c 6c 6f                                     hello
```

---

## 3. Deterministic Protocol Dissection & Byte Breakdown

### Phase 1: Client Magic Preface Handshake

* **Direction**: `-> Client to Server`
* **Byte Offset**: `0x000000` (Decimal 0)
* **Length**: `10 Bytes`
* **Raw Hex**: `48 65 4c 6c 4f 4f 6c 4c 65 48`
* **ASCII Decoded**: `"HeLlOOlLeH"`
* **Validation Rule (§3)**: Expected magic sequence `HeLlOOlLeH` (`48 65 4c 6c 4f 4f 6c 4c 65 48`).
* **Dissector Status**: `PASS - EXACT MATCH`

---

### Phase 2: Server Magic Preface Handshake Echo

* **Direction**: `<- Server to Client`
* **Byte Offset**: `0x000000` (Decimal 0)
* **Length**: `10 Bytes`
* **Raw Hex**: `48 65 4c 6c 4f 4f 6c 4c 65 48`
* **ASCII Decoded**: `"HeLlOOlLeH"`
* **Validation Rule (§3)**: Expected magic sequence `HeLlOOlLeH` (`48 65 4c 6c 4f 4f 6c 4c 65 48`).
* **Dissector Status**: `PASS - EXACT MATCH`

---

### Phase 3: Client Request HEADERS Frame

* **Direction**: `-> Client to Server`
* **Frame Offset**: `0x00000A` (Decimal 10)
* **Total Frame Size**: `67 Bytes` (7-Byte Header + 60-Byte Payload)

#### A. 7-Byte Fixed Frame Header Dissection (§4)
```text
Header Hex:  3c 00 00 | 13 | 01 00 00
Fields:      Length (24b LE) | Type(4b):Flags(4b) | Stream ID (24b LE)
```
| Bytes | Field Name | Raw Bits / Hex | Decoded Value | Table & Spec Citation |
|---|---|---|---|---|
| `0x00–0x02` | **Length** | `3c 00 00` (LE) | **`60 Bytes`** | §4: 24-bit Little-Endian payload length |
| `0x03 [7:4]` | **Type** | `0x1` (`0001`b) | **`HEADERS`** | §5 Table: Frame Type Registry (`0x1` = `HEADERS`) |
| `0x03 [3:0]` | **Flags** | `0x3` (`0011`b) | **`END_STREAM|END_HEADERS`** | §6: bit0=`END_STREAM`, bit1=`END_HEADERS` |
| `0x04–0x06` | **Stream ID** | `01 00 00` (LE) | **`Stream 1`** | §7: 24-bit Little-Endian Stream Identifier |

#### B. Frame Payload Dissection (60 Bytes)

Header Block decoded field-by-field according to §9 grammar (`[name:1B]([nlen:1B][name])?[vlen:2B LE][value]`):

| Field Offset | Field Name | Name Source | Value Length (16b LE) | Value String | Raw Encoded Bytes |
|---|---|---|---|---|---|
| `+00..+06` | **`:method`** | Static Table Entry #1 | `3 Bytes` (`0300` LE) | `"GET"` | `01 03 00 47 45 54` |
| `+06..+20` | **`:path`** | Static Table Entry #2 | `11 Bytes` (`0b00` LE) | `"/index.html"` | `02 0b 00 2f 69 6e 64 65 78 2e 68 74 6d 6c` |
| `+20..+37` | **`host`** | Static Table Entry #4 | `14 Bytes` (`0e00` LE) | `"127.0.0.1:9080"` | `04 0e 00 31 32 37 2e 30 2e 30 2e 31 3a 39 30 38 30` |
| `+37..+54` | **`user-agent`** | Static Table Entry #5 | `14 Bytes` (`0e00` LE) | `"hooh-bcurl/1.0"` | `05 0e 00 68 6f 6f 68 2d 62 63 75 72 6c 2f 31 2e 30` |
| `+54..+60` | **`accept`** | Static Table Entry #10 | `3 Bytes` (`0300` LE) | `"*/*"` | `0a 03 00 2a 2f 2a` |

---

### Phase 4: Server Response HEADERS Frame

* **Direction**: `<- Server to Client`
* **Frame Offset**: `0x00000A` (Decimal 10)
* **Total Frame Size**: `79 Bytes` (7-Byte Header + 72-Byte Payload)

#### A. 7-Byte Fixed Frame Header Dissection (§4)
```text
Header Hex:  48 00 00 | 12 | 01 00 00
Fields:      Length (24b LE) | Type(4b):Flags(4b) | Stream ID (24b LE)
```
| Bytes | Field Name | Raw Bits / Hex | Decoded Value | Table & Spec Citation |
|---|---|---|---|---|
| `0x00–0x02` | **Length** | `48 00 00` (LE) | **`72 Bytes`** | §4: 24-bit Little-Endian payload length |
| `0x03 [7:4]` | **Type** | `0x1` (`0001`b) | **`HEADERS`** | §5 Table: Frame Type Registry (`0x1` = `HEADERS`) |
| `0x03 [3:0]` | **Flags** | `0x2` (`0010`b) | **`END_HEADERS`** | §6: bit0=`END_STREAM`, bit1=`END_HEADERS` |
| `0x04–0x06` | **Stream ID** | `01 00 00` (LE) | **`Stream 1`** | §7: 24-bit Little-Endian Stream Identifier |

#### B. Frame Payload Dissection (72 Bytes)

Header Block decoded field-by-field according to §9 grammar (`[name:1B]([nlen:1B][name])?[vlen:2B LE][value]`):

| Field Offset | Field Name | Name Source | Value Length (16b LE) | Value String | Raw Encoded Bytes |
|---|---|---|---|---|---|
| `+00..+06` | **`:status`** | Static Table Entry #3 | `3 Bytes` (`0300` LE) | `"200"` | `03 03 00 32 30 30` |
| `+06..+24` | **`server`** | Static Table Entry #6 | `15 Bytes` (`0f00` LE) | `"hooh-bserve/1.0"` | `06 0f 00 68 6f 6f 68 2d 62 73 65 72 76 65 2f 31 2e 30` |
| `+24..+56` | **`date`** | Static Table Entry #7 | `29 Bytes` (`1d00` LE) | `"Fri, 09 Oct 2026 12:00:00 GMT"` | `07 1d 00 46 72 69 2c 20 30 39 20 4f 63 74 20 32 30 32 36 20 31 32 3a 30 30 3a 30 30 20 47 4d 54` |
| `+56..+68` | **`content-type`** | Static Table Entry #8 | `9 Bytes` (`0900` LE) | `"text/html"` | `08 09 00 74 65 78 74 2f 68 74 6d 6c` |
| `+68..+72` | **`content-length`** | Static Table Entry #9 | `1 Bytes` (`0100` LE) | `"5"` | `09 01 00 35` |

---

### Phase 5: Server Response DATA Body Frame

* **Direction**: `<- Server to Client`
* **Frame Offset**: `0x000059` (Decimal 89)
* **Total Frame Size**: `12 Bytes` (7-Byte Header + 5-Byte Payload)

#### A. 7-Byte Fixed Frame Header Dissection (§4)
```text
Header Hex:  05 00 00 | 01 | 01 00 00
Fields:      Length (24b LE) | Type(4b):Flags(4b) | Stream ID (24b LE)
```
| Bytes | Field Name | Raw Bits / Hex | Decoded Value | Table & Spec Citation |
|---|---|---|---|---|
| `0x00–0x02` | **Length** | `05 00 00` (LE) | **`5 Bytes`** | §4: 24-bit Little-Endian payload length |
| `0x03 [7:4]` | **Type** | `0x0` (`0000`b) | **`DATA`** | §5 Table: Frame Type Registry (`0x0` = `DATA`) |
| `0x03 [3:0]` | **Flags** | `0x1` (`0001`b) | **`END_STREAM`** | §6: bit0=`END_STREAM`, bit1=`END_HEADERS` |
| `0x04–0x06` | **Stream ID** | `01 00 00` (LE) | **`Stream 1`** | §7: 24-bit Little-Endian Stream Identifier |

#### B. Frame Payload Dissection (5 Bytes)

* **Raw Body Bytes (5 Bytes)**: `68 65 6c 6c 6f`
* **ASCII Body Text**: `"hello"`
* **Flags State**: `END_STREAM` (Signals stream closure via `END_STREAM = 1`)

---

## 4. Deterministic Comparison with Section 15 ("Worked Example")

The table below compares the captured wire bytes against the normative Section 15 example byte-for-byte:

| Wire Unit | Live Capture Hex Bytes | Section 15 Worked Example | Conformance Analysis |
|---|---|---|---|
| **Client Preface** | `48 65 4c 6c 4f 4f 6c 4c 65 48` | `48 65 4c 6c 4f 4f 6c 4c 65 48` | **Byte-for-Byte Exact Match (100%)** |
| **Server Preface** | `48 65 4c 6c 4f 4f 6c 4c 65 48` | `48 65 4c 6c 4f 4f 6c 4c 65 48` | **Byte-for-Byte Exact Match (100%)** |
| **Request HEADERS Frame Header** | `3c 00 00 13 01 00 00` (Len=60) | `3c 00 00 13 01 00 00` (Len=60) | **Byte-for-Byte Exact Match (100%)** |
| **Request HEADERS Payload (5 Headers)** | `01 03 00 47 45 54`<br/>`02 0b 00 2f 69 6e 64 65 78 2e 68 74 6d 6c`<br/>`04 0e 00 31 32 37 2e 30 2e 30 2e 31 3a 39 30 38 30`<br/>`05 0e 00 68 6f 6f 68 2d 62 63 75 72 6c 2f 31 2e 30`<br/>`0a 03 00 2a 2f 2a` | `01 03 00 47 45 54`<br/>`02 0b 00 2f 69 6e 64 65 78 2e 68 74 6d 6c`<br/>`04 0e 00 31 32 37 2e 30 2e 30 2e 31 3a 39 30 38 30`<br/>`05 0e 00 68 6f 6f 68 2d 62 63 75 72 6c 2f 31 2e 30`<br/>`0a 03 00 2a 2f 2a` | **Byte-for-Byte Exact Match (100%)** |
| **Response HEADERS Frame Header**| `48 00 00 12 01 00 00` (Len=72) | `48 00 00 12 01 00 00` (Len=72) | **Byte-for-Byte Exact Match (100%)** |
| **Response HEADERS Payload (5 Headers)** | `03 03 00 32 30 30`<br/>`06 0f 00 68 6f 6f 68 2d 62 73 65 72 76 65 2f 31 2e 30`<br/>`07 1d 00 46 72 69 2c 20 30 39 20 4f 63 74 20 32 30 32 36 20 31 32 3a 30 30 3a 30 30 20 47 4d 54`<br/>`08 09 00 74 65 78 74 2f 68 74 6d 6c`<br/>`09 01 00 35` | `03 03 00 32 30 30`<br/>`06 0f 00 68 6f 6f 68 2d 62 73 65 72 76 65 2f 31 2e 30`<br/>`07 1d 00 46 72 69 2c 20 30 39 20 4f 63 74 20 32 30 32 36 20 31 32 3a 30 30 3a 30 30 20 47 4d 54`<br/>`08 09 00 74 65 78 74 2f 68 74 6d 6c`<br/>`09 01 00 35` | **Byte-for-Byte Exact Match (100%)** |
| **Response DATA Frame Header** | `05 00 00 01 01 00 00` (Len=5, ES) | `05 00 00 01 01 00 00` (Len=5, ES) | **Byte-for-Byte Exact Match (100%)** |
| **Response DATA Payload** | `68 65 6c 6c 6f` (`"hello"`) | `68 65 6c 6c 6f` (`"hello"`) | **Byte-for-Byte Exact Match (100%)** |


### Conformance and Interoperability Summary

1. **Complete 10-Header Exchange**: Exactly all 10 defined static table header names (§9 Table 1) are utilized across this single request/response exchange (5 from the client: `:method`, `:path`, `host`, `user-agent`, `accept`; and 5 from the server: `:status`, `server`, `date`, `content-type`, `content-length`).
2. **Zero Inconsistencies**: Every single wire frame header, flag, length field, and header payload matches the normative Section 15 Worked Example byte-for-byte with 100% fidelity.
3. **Automated Verification**: The automated test suite ([`tests/test_golden.cc`](tests/test_golden.cc)) asserts exact equality for each of these frame bytes, guaranteeing that the specification, C++ code, and wire captures remain in absolute lockstep.
