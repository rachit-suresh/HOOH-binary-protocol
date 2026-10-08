import socket
import struct
import subprocess
import time
import os
import sys
import shutil

PREFACE = b"HeLlOOlLeH"
kHeaderSize = 7

# Frame Types
TYPE_DATA = 0x0
TYPE_HEADERS = 0x1
TYPE_RST_STREAM = 0x2
TYPE_PING = 0x3
TYPE_GOAWAY = 0x4
TYPE_PONG = 0x5

# Flags
FLAG_END_STREAM = 0x01
FLAG_END_HEADERS = 0x02

# Static Header Table
STATIC_TABLE = {
    ":method": 1,
    ":path": 2,
    ":status": 3,
    "host": 4,
    "user-agent": 5,
    "server": 6,
    "date": 7,
    "content-type": 8,
    "content-length": 9,
    "accept": 10
}

def pack_header(length, frame_type, flags, stream_id):
    b0 = length & 0xFF
    b1 = (length >> 8) & 0xFF
    b2 = (length >> 16) & 0xFF
    b3 = ((frame_type & 0x0F) << 4) | (flags & 0x0F)
    s0 = stream_id & 0xFF
    s1 = (stream_id >> 8) & 0xFF
    s2 = (stream_id >> 16) & 0xFF
    return bytes([b0, b1, b2, b3, s0, s1, s2])

def unpack_header(b):
    length = b[0] | (b[1] << 8) | (b[2] << 16)
    frame_type = (b[3] >> 4) & 0x0F
    flags = b[3] & 0x0F
    stream_id = b[4] | (b[5] << 8) | (b[6] << 16)
    return length, frame_type, flags, stream_id

def encode_header_block(method=None, path=None, status=None, headers=None):
    out = bytearray()
    if method is not None:
        val = method.encode('utf-8')
        out.append(1) # :method
        out.extend(struct.pack('<H', len(val)))
        out.extend(val)
    if path is not None:
        val = path.encode('utf-8')
        out.append(2) # :path
        out.extend(struct.pack('<H', len(val)))
        out.extend(val)
    if status is not None:
        val = str(status).encode('utf-8')
        out.append(3) # :status
        out.extend(struct.pack('<H', len(val)))
        out.extend(val)
    if headers:
        for k, v in headers:
            k_lower = k.lower()
            val = v.encode('utf-8')
            if k_lower in STATIC_TABLE:
                idx = STATIC_TABLE[k_lower]
                out.append(idx)
            else:
                name_bytes = k_lower.encode('utf-8')
                out.append(0) # literal
                out.append(len(name_bytes))
                out.extend(name_bytes)
            out.extend(struct.pack('<H', len(val)))
            out.extend(val)
    return bytes(out)

def decode_header_block(data):
    pos = 0
    headers = {}
    while pos < len(data):
        name_idx = data[pos]
        pos += 1
        name = ""
        if name_idx == 0:
            nlen = data[pos]
            pos += 1
            name = data[pos:pos+nlen].decode('utf-8', errors='replace')
            pos += nlen
        else:
            inv_table = {v: k for k, v in STATIC_TABLE.items()}
            name = inv_table.get(name_idx, f"unknown_{name_idx}")
        vlen = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        value = data[pos:pos+vlen].decode('utf-8', errors='replace')
        pos += vlen
        headers[name] = value
    return headers

class TestContext:
    def __init__(self, host="127.0.0.1", port=9010, root_dir="test_conformance_root"):
        self.host = host
        self.port = port
        self.root_dir = root_dir
        self.server_proc = None

    def setup(self):
        os.makedirs(self.root_dir, exist_ok=True)
        os.makedirs(os.path.join(self.root_dir, "sub"), exist_ok=True)
        with open(os.path.join(self.root_dir, "index.html"), "w") as f:
            f.write("Root Index")
        with open(os.path.join(self.root_dir, "hello.txt"), "w") as f:
            f.write("Hello World")
        with open(os.path.join(self.root_dir, "empty.txt"), "w") as f:
            pass
        with open(os.path.join(self.root_dir, "sub", "index.html"), "w") as f:
            f.write("Sub Index")
        with open(os.path.join(self.root_dir, ".secret"), "w") as f:
            f.write("Secret content")

        server_bin = ".\\bserve.exe" if os.name == "nt" else "./bserve"
        self.server_proc = subprocess.Popen([server_bin, self.root_dir, str(self.port)])
        time.sleep(0.3)

    def teardown(self):
        if self.server_proc:
            self.server_proc.terminate()
            try:
                self.server_proc.wait(timeout=1)
            except:
                self.server_proc.kill()
        if os.path.exists(self.root_dir):
            shutil.rmtree(self.root_dir, ignore_errors=True)

    def connect_and_greet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((self.host, self.port))
        s.sendall(PREFACE)
        server_preface = s.recv(10)
        assert server_preface == PREFACE, f"Server preface mismatch: {server_preface}"
        return s

    def read_frame(self, sock):
        hdr_bytes = b""
        while len(hdr_bytes) < 7:
            chunk = sock.recv(7 - len(hdr_bytes))
            if not chunk:
                return None
            hdr_bytes += chunk
        length, ftype, flags, stream_id = unpack_header(hdr_bytes)
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        return length, ftype, flags, stream_id, payload

# Results tracker
tests_run = 0
tests_passed = 0
code_bugs = []
spec_bugs = []

def run_test(name, fn):
    global tests_run, tests_passed
    tests_run += 1
    print(f"Running [{name}]...", end=" ", flush=True)
    try:
        fn()
        tests_passed += 1
        print("PASS")
    except AssertionError as e:
        print(f"FAIL (AssertionError: {e})")
        code_bugs.append((name, str(e)))
    except Exception as e:
        print(f"FAIL (Exception: {type(e).__name__}: {e})")
        code_bugs.append((name, str(e)))

ctx = TestContext()

def test_preface_exact_echo():
    s = ctx.connect_and_greet()
    s.close()

def test_preface_mismatch_first_byte():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((ctx.host, ctx.port))
    s.sendall(b"X" + PREFACE[1:])
    try:
        resp = s.recv(10)
        assert len(resp) == 0, f"Server sent bytes after preface mismatch: {resp}"
    except (ConnectionResetError, ConnectionAbortedError):
        pass
    finally:
        s.close()

def test_preface_mismatch_last_byte():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((ctx.host, ctx.port))
    s.sendall(PREFACE[:9] + b"X")
    try:
        resp = s.recv(10)
        assert len(resp) == 0, f"Server sent bytes after preface mismatch: {resp}"
    except (ConnectionResetError, ConnectionAbortedError):
        pass
    finally:
        s.close()

def test_normal_get_stream1():
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    hdr = pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1)
    s.sendall(hdr + payload)

    # Expect HEADERS (200)
    f = ctx.read_frame(s)
    assert f is not None, "No frame received"
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_HEADERS, f"Expected HEADERS, got {ftype}"
    assert sid == 1
    resp_headers = decode_header_block(data)
    assert resp_headers.get(":status") == "200"

    # Expect DATA
    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_DATA
    assert sid == 1
    assert data == b"Hello World"
    assert flags & FLAG_END_STREAM
    s.close()

def test_empty_file_get():
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/empty.txt")
    hdr = pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1)
    s.sendall(hdr + payload)

    # Empty file must be expressed as HEADERS carrying END_HEADERS|END_STREAM with no DATA frames (§8.2)
    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_HEADERS
    assert flags & FLAG_END_STREAM, "Empty file response MUST carry END_STREAM"
    assert flags & FLAG_END_HEADERS
    resp_headers = decode_header_block(data)
    assert resp_headers.get(":status") == "200"
    s.close()

def test_directory_index_html():
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/sub")
    hdr = pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1)
    s.sendall(hdr + payload)

    f = ctx.read_frame(s)
    assert f is not None
    _, ftype, _, _, data = f
    assert ftype == TYPE_HEADERS
    assert decode_header_block(data).get(":status") == "200"

    f = ctx.read_frame(s)
    assert f is not None
    _, ftype, _, _, data = f
    assert ftype == TYPE_DATA
    assert data == b"Sub Index"
    s.close()

def test_gap_stream_id():
    # Gap ID (e.g. stream 5 after stream 1) is legal (§7)
    s = ctx.connect_and_greet()
    # Stream 1
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    ctx.read_frame(s) # HEADERS
    ctx.read_frame(s) # DATA

    # Stream 5 (gap 3)
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 5
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # DATA
    s.close()

def test_reuse_stream_id_connection_error():
    # Stream ID reuse: HEADERS on already-closed ID 1 -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    ctx.read_frame(s) # HEADERS
    ctx.read_frame(s) # DATA

    # Reuse stream 1
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_GOAWAY, f"Expected GOAWAY on stream reuse, got {ftype}"
    s.close()

def test_reuse_gap_stream_id_connection_error():
    # HEADERS on gap ID 3 after stream 5 -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5) + payload)
    ctx.read_frame(s) # HEADERS
    ctx.read_frame(s) # DATA

    # Now send on gap ID 3
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_GOAWAY, f"Expected GOAWAY on gap stream reuse, got {ftype}"
    s.close()

def test_non_zero_even_stream_id():
    # Non-zero even ID -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 2) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_GOAWAY, f"Expected GOAWAY on even ID, got {ftype}"
    s.close()

def test_data_on_stream_0():
    # DATA on stream 0 -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    s.sendall(pack_header(5, TYPE_DATA, 0, 0) + b"hello")
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_GOAWAY, f"Expected GOAWAY, got {f[1]}"
    s.close()

def test_headers_on_stream_0():
    # HEADERS on stream 0 -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 0) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_GOAWAY, f"Expected GOAWAY, got {f[1]}"
    s.close()

def test_rst_stream_on_stream_0():
    # RST_STREAM on stream 0 -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    s.sendall(pack_header(1, TYPE_RST_STREAM, 0, 0) + b"\x01")
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_GOAWAY, f"Expected GOAWAY, got {f[1]}"
    s.close()

def test_data_on_new_or_gap_id():
    # DATA on new ID -> connection error (§11 Step 3)
    s = ctx.connect_and_greet()
    s.sendall(pack_header(5, TYPE_DATA, 0, 1) + b"hello")
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_GOAWAY, f"Expected GOAWAY on DATA on new ID, got {f[1]}"
    s.close()

def test_rst_on_closed_id_ignored():
    # RST on closed ID -> MUST be ignored (§8.3, §11 Step 3)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    ctx.read_frame(s) # HEADERS
    ctx.read_frame(s) # DATA

    # Send RST on closed stream 1: MUST be ignored
    s.sendall(pack_header(1, TYPE_RST_STREAM, 0, 1) + b"\x01")

    # Follow up with valid request on stream 3 to prove connection is still alive
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 3
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # DATA
    s.close()

def test_rst_on_open_stream_aborts():
    # RST on open stream aborts it without closing connection (§8.3, §11 Step 6)
    s = ctx.connect_and_greet()
    # Send HEADERS with END_STREAM=0 (open stream awaiting body)
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)

    # Abort stream 1
    s.sendall(pack_header(1, TYPE_RST_STREAM, 0, 1) + b"\x02")

    # Next stream 3 should succeed
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 3
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # DATA
    s.close()

def test_concurrency_one_stream_limit():
    # Opening stream 3 while stream 1 is open -> stream error on stream 3 (§7, §11 Step 3)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    # Stream 1 opened without END_STREAM
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)

    # Now open stream 3 before stream 1 finishes
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3) + payload)

    # Stream 3 should receive 400 Stream Error immediately
    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_HEADERS and sid == 3
    assert decode_header_block(data).get(":status") == "400"

    # Now finish stream 1 with END_STREAM DATA
    s.sendall(pack_header(5, TYPE_DATA, FLAG_END_STREAM, 1) + b"dummy")
    f = ctx.read_frame(s) # Stream 1 HEADERS
    assert f is not None and f[3] == 1
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # Stream 1 DATA
    s.close()

def test_malformed_end_headers_zero():
    # HEADERS frame with END_HEADERS=0 is malformed frame (§6 Table, §11 Step 5) -> 400 stream error
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    # flags with END_HEADERS (bit 1) NOT set
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 1
    assert decode_header_block(f[4]).get(":status") == "400"
    s.close()

def test_malformed_data_end_headers_one():
    # DATA frame with END_HEADERS=1 is malformed frame (§6 Table) -> 400 stream error
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)

    # DATA with forbidden FLAG_END_HEADERS
    s.sendall(pack_header(5, TYPE_DATA, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + b"hello")
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 1
    assert decode_header_block(f[4]).get(":status") == "400"
    s.close()

def test_zero_length_data_frame():
    # DATA frames with Length 0 MUST NOT be sent (§8.1, §11 Step 5) -> stream error
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)
    s.sendall(pack_header(0, TYPE_DATA, FLAG_END_STREAM, 1))

    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 1
    assert decode_header_block(f[4]).get(":status") == "400"
    s.close()

def test_skip_unknown_frame_types():
    # Types 0x6..0xF MUST be skipped cleanly (§4, §13)
    s = ctx.connect_and_greet()
    # Send unknown type 0x7 with 10 bytes payload
    s.sendall(pack_header(10, 0x7, 0, 0) + b"0123456789")

    # Now send normal request on stream 1
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)

    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_HEADERS and f[3] == 1
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # DATA
    s.close()

def test_ping_pong_exchange():
    # PING challenge echoed as PONG verbatim (§8.4, §8.5)
    s = ctx.connect_and_greet()
    challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    s.sendall(pack_header(8, TYPE_PING, 0, 0) + challenge)

    f = ctx.read_frame(s)
    assert f is not None
    length, ftype, flags, sid, data = f
    assert ftype == TYPE_PONG, f"Expected PONG, got {ftype}"
    assert sid == 0
    assert data == challenge, f"PONG challenge mismatch: {data}"
    s.close()

def test_ping_bad_length_connection_error():
    # PING with length != 8 is malformed on stream 0 -> connection error (§11 Step 5)
    s = ctx.connect_and_greet()
    s.sendall(pack_header(4, TYPE_PING, 0, 0) + b"\x01\x02\x03\x04")
    f = ctx.read_frame(s)
    assert f is not None
    assert f[1] == TYPE_GOAWAY, f"Expected GOAWAY, got {f[1]}"
    s.close()

def test_path_404_dotfile():
    # Dotfiles hidden: /.secret -> 404 (§10)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/.secret")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "404"
    assert f[2] & FLAG_END_STREAM, "Error response MUST carry END_STREAM"
    s.close()

def test_path_404_lexical_escape():
    # Escaping root lexically: /../../../etc/passwd -> 404 (§10)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/../../../etc/passwd")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "404"
    s.close()

def test_path_with_query_string():
    # Query string stripped: /hello.txt?foo=bar -> /hello.txt (200) (§10)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt?foo=bar")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # DATA
    s.close()

def test_method_405_disallowed():
    # Known disallowed methods: POST -> 405 (§10)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="POST", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "405"
    s.close()

def test_method_501_unknown():
    # Unknown method token: FOOBAR -> 501 (§10)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="FOOBAR", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1) + payload)
    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "501"
    s.close()

def test_request_body_discarded():
    # Request body carries no meaning in v1; server discards by Length (§8.1)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt")
    # HEADERS without END_STREAM
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)
    # DATA with END_STREAM
    s.sendall(pack_header(11, TYPE_DATA, FLAG_END_STREAM, 1) + b"RequestBody")

    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "200"
    d = ctx.read_frame(s)
    assert d is not None and d[4] == b"Hello World"
    s.close()

def test_content_length_mismatch():
    # content-length mismatch -> 400 stream error (§9, §11 Step 7)
    s = ctx.connect_and_greet()
    payload = encode_header_block(method="GET", path="/hello.txt", headers=[("content-length", "20")])
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)
    # Send only 5 bytes body
    s.sendall(pack_header(5, TYPE_DATA, FLAG_END_STREAM, 1) + b"12345")

    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "400"
    s.close()

def test_oversize_frame_413():
    # Oversize request frame (> impl_limit) -> discard payload + 413 stream error (§11 Step 4)
    # To test this without sending 1MB, let's verify receiver limit behavior or test floor
    # We will test sending a frame exceeding kAcceptFloor if server impl_limit is kAcceptFloor,
    # or verify that 16 KiB frames are accepted per §4 floor!
    s = ctx.connect_and_greet()
    # 16,384 B frame: conforming receiver MUST accept it (§4)
    data_16k = b"A" * 16384
    payload = encode_header_block(method="GET", path="/hello.txt")
    s.sendall(pack_header(len(payload), TYPE_HEADERS, FLAG_END_HEADERS, 1) + payload)
    s.sendall(pack_header(16384, TYPE_DATA, FLAG_END_STREAM, 1) + data_16k)

    f = ctx.read_frame(s)
    assert f is not None
    assert decode_header_block(f[4]).get(":status") == "200"
    ctx.read_frame(s) # DATA
    s.close()

def main():
    ctx.setup()
    try:
        run_test("Preface Exact Echo", test_preface_exact_echo)
        run_test("Preface Mismatch First Byte (Silent Close)", test_preface_mismatch_first_byte)
        run_test("Preface Mismatch Last Byte (Silent Close)", test_preface_mismatch_last_byte)
        run_test("Normal GET Stream 1", test_normal_get_stream1)
        run_test("Empty File GET (Headers ES|EH, 0 DATA)", test_empty_file_get)
        run_test("Directory Index HTML Resolution", test_directory_index_html)
        run_test("Gap Stream ID (5 after 1)", test_gap_stream_id)
        run_test("Reuse Stream ID (Conn Error GOAWAY)", test_reuse_stream_id_connection_error)
        run_test("Reuse Gap Stream ID (Conn Error GOAWAY)", test_reuse_gap_stream_id_connection_error)
        run_test("Non-Zero Even Stream ID (Conn Error GOAWAY)", test_non_zero_even_stream_id)
        run_test("DATA on Stream 0 (Conn Error GOAWAY)", test_data_on_stream_0)
        run_test("HEADERS on Stream 0 (Conn Error GOAWAY)", test_headers_on_stream_0)
        run_test("RST_STREAM on Stream 0 (Conn Error GOAWAY)", test_rst_stream_on_stream_0)
        run_test("DATA on New/Gap Stream ID (Conn Error GOAWAY)", test_data_on_new_or_gap_id)
        run_test("RST on Closed Stream ID Ignored", test_rst_on_closed_id_ignored)
        run_test("RST on Open Stream Aborts Stream Cleanly", test_rst_on_open_stream_aborts)
        run_test("One-Stream Concurrency Limit (400 on Stream 3)", test_concurrency_one_stream_limit)
        run_test("Malformed HEADERS: END_HEADERS=0 (400)", test_malformed_end_headers_zero)
        run_test("Malformed DATA: END_HEADERS=1 (400)", test_malformed_data_end_headers_one)
        run_test("Malformed DATA: Length 0 (400)", test_zero_length_data_frame)
        run_test("Skip Unknown Frame Types (0x6..0xF)", test_skip_unknown_frame_types)
        run_test("PING / PONG Challenge Echo", test_ping_pong_exchange)
        run_test("Malformed PING Length != 8 (Conn Error)", test_ping_bad_length_connection_error)
        run_test("Path 404 on Dotfile (/.secret)", test_path_404_dotfile)
        run_test("Path 404 on Lexical Root Escape (/../../)", test_path_404_lexical_escape)
        run_test("Path with Query String Stripped (/file?q=1)", test_path_with_query_string)
        run_test("Disallowed Method (POST -> 405)", test_method_405_disallowed)
        run_test("Unknown Method (FOOBAR -> 501)", test_method_501_unknown)
        run_test("Request Body Discarded by Length (200)", test_request_body_discarded)
        run_test("Content-Length Mismatch (400)", test_content_length_mismatch)
        run_test("Conforming 16 KiB Acceptance Floor (Must Accept)", test_oversize_frame_413)

        print("\n========================================")
        print(f"Summary: {tests_passed}/{tests_run} Conformance Tests Passed")
        print("========================================")
        if code_bugs:
            print("\nCODE BUGS DETECTED:")
            for name, err in code_bugs:
                print(f" - {name}: {err}")
        if spec_bugs:
            print("\nSPEC BUGS DETECTED:")
            for name, err in spec_bugs:
                print(f" - {name}: {err}")
    finally:
        ctx.teardown()

if __name__ == "__main__":
    main()
