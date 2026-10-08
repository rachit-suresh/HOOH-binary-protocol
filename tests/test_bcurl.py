import socket
import subprocess
import time
import os
import sys
import threading
import struct

PREFACE = b"HeLlOOlLeH"
bcurl_bin = ".\\bcurl.exe" if os.name == "nt" else "./bcurl"

def pack_header(length, frame_type, flags, stream_id):
    b0 = length & 0xFF
    b1 = (length >> 8) & 0xFF
    b2 = (length >> 16) & 0xFF
    b3 = ((frame_type & 0x0F) << 4) | (flags & 0x0F)
    s0 = stream_id & 0xFF
    s1 = (stream_id >> 8) & 0xFF
    s2 = (stream_id >> 16) & 0xFF
    return bytes([b0, b1, b2, b3, s0, s1, s2])

def encode_status_headers(status, stream_id, end_stream=True):
    val = str(status).encode('utf-8')
    payload = bytearray()
    payload.append(3) # :status
    payload.extend(struct.pack('<H', len(val)))
    payload.extend(val)
    flags = 0x02 # FLAG_END_HEADERS
    if end_stream:
        flags |= 0x01 # FLAG_END_STREAM
    hdr = pack_header(len(payload), 1, flags, stream_id)
    return hdr + bytes(payload)

def run_mock_server_once(port, handler_fn):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)

    result = {}
    def srv():
        try:
            client, _ = server.accept()
            client.settimeout(2.0)
            handler_fn(client)
            time.sleep(0.05)
            client.close()
        except Exception as e:
            result['error'] = e
        finally:
            server.close()

    t = threading.Thread(target=srv)
    t.daemon = True
    t.start()
    time.sleep(0.1)
    return t, result

def test_bcurl_exit_4_mismatched_hosts():
    print("Testing bcurl exit code 4 on mismatched hosts...", end=" ", flush=True)
    res = subprocess.run([bcurl_bin, "localhost:9000/a", "127.0.0.1:9000/b"], capture_output=True)
    assert res.returncode == 4, f"Expected 4, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_4_mismatched_ports():
    print("Testing bcurl exit code 4 on mismatched ports...", end=" ", flush=True)
    res = subprocess.run([bcurl_bin, "localhost:9000/a", "localhost:9001/b"], capture_output=True)
    assert res.returncode == 4, f"Expected 4, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_4_no_urls():
    print("Testing bcurl exit code 4 on no URLs...", end=" ", flush=True)
    res = subprocess.run([bcurl_bin], capture_output=True)
    assert res.returncode == 4, f"Expected 4, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_1_on_404():
    print("Testing bcurl exit code 1 on 404 response...", end=" ", flush=True)
    port = 9021
    def handler(c):
        pref = c.recv(10)
        assert pref == PREFACE
        c.sendall(PREFACE)
        req = c.recv(1024)
        c.sendall(encode_status_headers(404, 1, end_stream=True))

    t, _ = run_mock_server_once(port, handler)
    res = subprocess.run([bcurl_bin, f"127.0.0.1:{port}/notfound"], capture_output=True)
    assert res.returncode == 1, f"Expected 1, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_2_on_501():
    print("Testing bcurl exit code 2 on 501 response...", end=" ", flush=True)
    port = 9022
    def handler(c):
        pref = c.recv(10)
        assert pref == PREFACE
        c.sendall(PREFACE)
        req = c.recv(1024)
        c.sendall(encode_status_headers(501, 1, end_stream=True))

    t, _ = run_mock_server_once(port, handler)
    res = subprocess.run([bcurl_bin, f"127.0.0.1:{port}/bad"], capture_output=True)
    assert res.returncode == 2, f"Expected 2, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_3_on_server_rst():
    print("Testing bcurl exit code 3 on server RST_STREAM...", end=" ", flush=True)
    port = 9023
    def handler(c):
        pref = c.recv(10)
        c.sendall(PREFACE)
        req = c.recv(1024)
        # Send RST_STREAM with error 1
        rst = pack_header(1, 2, 0, 1) + b"\x01"
        c.sendall(rst)

    t, _ = run_mock_server_once(port, handler)
    res = subprocess.run([bcurl_bin, f"127.0.0.1:{port}/rst"], capture_output=True)
    assert res.returncode == 3, f"Expected 3, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_3_on_bad_preface():
    print("Testing bcurl exit code 3 on bad server preface...", end=" ", flush=True)
    port = 9024
    def handler(c):
        pref = c.recv(10)
        c.sendall(b"BADPREFACE")

    t, _ = run_mock_server_once(port, handler)
    res = subprocess.run([bcurl_bin, f"127.0.0.1:{port}/test"], capture_output=True)
    assert res.returncode == 3, f"Expected 3, got {res.returncode}"
    print("PASS")

def test_bcurl_exit_3_on_server_disconnect():
    print("Testing bcurl exit code 3 on unexpected EOF...", end=" ", flush=True)
    port = 9025
    def handler(c):
        pref = c.recv(10)
        c.sendall(PREFACE)
        req = c.recv(1024)
        c.close()

    t, _ = run_mock_server_once(port, handler)
    res = subprocess.run([bcurl_bin, f"127.0.0.1:{port}/eof"], capture_output=True)
    assert res.returncode == 3, f"Expected 3, got {res.returncode}"
    print("PASS")

def test_bcurl_verbose_trace():
    print("Testing bcurl -v wire tracing output...", end=" ", flush=True)
    port = 9026
    def handler(c):
        pref = c.recv(10)
        c.sendall(PREFACE)
        req = c.recv(1024)
        c.sendall(encode_status_headers(200, 1, end_stream=True))

    t, _ = run_mock_server_once(port, handler)
    res = subprocess.run([bcurl_bin, "-v", f"127.0.0.1:{port}/hello"], capture_output=True, text=True)
    assert res.returncode == 0
    stderr_lines = [l.strip() for l in res.stderr.strip().split("\n") if l.strip()]
    assert len(stderr_lines) >= 2, "Expected at least 2 lines in stderr"
    assert "preface \"HeLlOOlLeH\"" in stderr_lines[0], f"Line 0 not preface: {stderr_lines[0]}"
    assert "preface \"HeLlOOlLeH\"" in stderr_lines[1], f"Line 1 not preface: {stderr_lines[1]}"
    print("PASS")

def main():
    print("========================================")
    print("       bcurl Client Test Suite          ")
    print("========================================")
    test_bcurl_exit_4_no_urls()
    test_bcurl_exit_4_mismatched_hosts()
    test_bcurl_exit_4_mismatched_ports()
    test_bcurl_exit_1_on_404()
    test_bcurl_exit_2_on_501()
    test_bcurl_exit_3_on_server_rst()
    test_bcurl_exit_3_on_bad_preface()
    test_bcurl_exit_3_on_server_disconnect()
    test_bcurl_verbose_trace()
    print("========================================")
    print(" All bcurl Client Tests Passed!         ")
    print("========================================")

if __name__ == "__main__":
    main()
