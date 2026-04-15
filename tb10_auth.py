#!/usr/bin/env python3
"""
TB10 Plus authentication flow:
1. Send AVON UDP broadcast to get device info + auth token (bytes 20-23 of response)
2. POST /api/v1/login with credentials to get Bearer token
3. Probe available API endpoints

TB10 Plus: 192.168.0.10
Mac en9:   192.168.0.100
"""

import socket
import struct
import json
import ssl
import urllib.request
import urllib.error
import time
import binascii

TB10_IP   = '192.168.0.10'
LOCAL_IP  = '192.168.0.100'
AVON_PORT = 16601   # TB10 listens here
AVON_SRC  = 16600   # we send from here, TB10 responds to here
HTTPS_PORT = 16674

# Exact AVON broadcast packet captured from Viplex
AVON_PKT = bytes.fromhex('41564f4effffffff55888100010000000000000000008f00')


def get_avon_token(timeout=5.0):
    """Send AVON broadcast, return (token_bytes, full_json_dict)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    try:
        sock.bind((LOCAL_IP, AVON_SRC))
        print(f'[AVON] Bound to {LOCAL_IP}:{AVON_SRC}')

        # Try both broadcast and unicast to be safe
        sock.sendto(AVON_PKT, ('255.255.255.255', AVON_PORT))
        print(f'[AVON] Sent broadcast ({len(AVON_PKT)} bytes)')
        sock.sendto(AVON_PKT, (TB10_IP, AVON_PORT))
        print(f'[AVON] Sent unicast to {TB10_IP}:{AVON_PORT}')

        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            sock.settimeout(max(remaining, 0.1))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            print(f'[AVON] Response from {addr}: {len(data)} bytes')
            print(f'  hex: {data[:32].hex()}...')

            if data[:4] == b'AVON' and len(data) >= 24:
                token_bytes = data[20:24]
                print(f'  token bytes (20-23): {token_bytes.hex()}')
                # Parse JSON body
                json_start = data.find(b'{')
                if json_start >= 0:
                    try:
                        info = json.loads(data[json_start:].decode('utf-8', errors='replace'))
                        print(f'  device: {info.get("productName")} sn={info.get("sn")}')
                        print(f'  logined: {info.get("logined")}')
                        return token_bytes, info
                    except Exception as e:
                        print(f'  JSON parse error: {e}')
                return token_bytes, {}
        print('[AVON] Timeout — no response received')
        return None, {}
    finally:
        sock.close()


def make_ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def https_request(path, method='GET', body=None, headers=None, token=None):
    """Make an HTTPS request to the TB10 Plus API."""
    url = f'https://{TB10_IP}:{HTTPS_PORT}{path}'
    hdrs = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if token:
        hdrs['Authorization'] = f'Basic {token}'
    if headers:
        hdrs.update(headers)

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    ctx = make_ssl_ctx()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return None, str(e)


def try_login(username='admin', password='123456', token_hex=None):
    """Try various login endpoint formats."""
    endpoints = [
        '/api/v1/login',
        '/api/login',
        '/login',
        '/api/v1/user/login',
        '/v1/login',
    ]
    body = {'username': username, 'password': password}
    if token_hex:
        body['token'] = token_hex

    print(f'\n[LOGIN] Trying login with {username}/{password}')
    for ep in endpoints:
        code, resp = https_request(ep, method='POST', body=body)
        if code is not None:
            print(f'  POST {ep} → {code}: {str(resp)[:200]}')
            if code < 400:
                return code, resp
    return None, None


def probe_api(auth_header=None):
    """Probe common API paths to map available endpoints."""
    paths = [
        '/api/v1/device/info',
        '/api/v1/screen',
        '/api/v1/screen/list',
        '/api/v1/brightness',
        '/api/v1/testmode',
        '/api/v1/player',
        '/api/v1/player/info',
        '/api/v1/user',
        '/api/v1/user/info',
        '/api/v1/terminal',
        '/api/v1/terminal/info',
        '/api/v1/system/info',
        '/v1/terminal/info',
        '/',
        '/index.html',
    ]
    headers = {}
    if auth_header:
        headers['Authorization'] = auth_header

    print(f'\n[PROBE] Scanning API endpoints...')
    for path in paths:
        code, resp = https_request(path, headers=headers)
        status = f'{code}: {str(resp)[:120]}' if code else f'ERROR: {resp}'
        print(f'  GET {path:<35} → {status}')


def main():
    print('=== TB10 Plus Authentication Probe ===\n')

    # Step 1: AVON discovery
    print('── Step 1: AVON Discovery ──')
    token_bytes, device_info = get_avon_token()

    auth_token = None
    if token_bytes:
        token_hex = token_bytes.hex()
        token_int = struct.unpack('<I', token_bytes)[0]
        print(f'\n[AUTH] Token: hex={token_hex} int={token_int} (0x{token_int:08X})')

        # Try token as Basic auth (common Novastar pattern)
        auth_token = token_hex

    print()

    # Step 2: Try HTTPS with various auth approaches
    print('── Step 2: No-auth probe ──')
    code, resp = https_request('/api/v1/device/info')
    print(f'  GET /api/v1/device/info (no auth) → {code}: {str(resp)[:200]}')

    if auth_token:
        print(f'\n── Step 3: Token-as-Basic-auth probe ──')
        code, resp = https_request('/api/v1/device/info', token=auth_token)
        print(f'  GET /api/v1/device/info (Basic {auth_token}) → {code}: {str(resp)[:200]}')

        # Token as Bearer
        print(f'\n── Step 4: Token-as-Bearer probe ──')
        code, resp = https_request('/api/v1/device/info',
                                   headers={'Authorization': f'Bearer {auth_token}'})
        print(f'  GET /api/v1/device/info (Bearer {auth_token}) → {code}: {str(resp)[:200]}')

        # Token as integer bearer
        token_int_str = str(struct.unpack('<I', token_bytes)[0])
        code, resp = https_request('/api/v1/device/info',
                                   headers={'Authorization': f'Bearer {token_int_str}'})
        print(f'  GET /api/v1/device/info (Bearer {token_int_str}) → {code}: {str(resp)[:200]}')

    # Step 5: Try login
    try_login('admin', '123456', token_hex=auth_token)
    try_login('admin', '')

    # Step 6: Full probe with whatever we have
    probe_api(auth_header=f'Bearer {auth_token}' if auth_token else None)


if __name__ == '__main__':
    main()
