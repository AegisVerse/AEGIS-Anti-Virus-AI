import os
import sys
import json
import struct
import time
import subprocess

def get_pipe_name():
    username = os.environ.get('USERNAME', 'user').lower()
    safe_user = ''.join(c if c.isalnum() else '_' for c in username)[:40]
    return rf'\\.\pipe\aegis-ai-security.user.{safe_user}'

def ensure_engine_running():
    pipe_path = get_pipe_name()
    # Check if pipe already exists
    try:
        f = open(pipe_path, 'r+b', buffering=0)
        f.close()
        return None
    except Exception:
        pass

    # Start engine in background
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    service_exe = os.path.join(root_dir, 'target', 'release', 'aegis-service.exe')
    if not os.path.exists(service_exe):
        service_exe = os.path.join(root_dir, 'release', 'aegis-service.exe')

    print(f"[*] Starting AEGIS User Engine: {service_exe} --run-user")
    proc = subprocess.Popen([service_exe, '--run-user'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for pipe to be available
    for _ in range(30):
        time.sleep(0.1)
        try:
            f = open(pipe_path, 'r+b', buffering=0)
            f.close()
            print("[+] AEGIS Security Engine connected successfully.")
            return proc
        except Exception:
            pass
    print("[-] Timeout waiting for AEGIS named pipe.")
    return proc

def send_frame(pipe, data_bytes):
    length_prefix = struct.pack('<I', len(data_bytes))
    pipe.write(length_prefix + data_bytes)
    pipe.flush()

def read_frame(pipe):
    raw_len = pipe.read(4)
    if len(raw_len) < 4:
        raise ConnectionResetError("Connection closed by peer")
    msg_len = struct.unpack('<I', raw_len)[0]
    payload = b''
    while len(payload) < msg_len:
        chunk = pipe.read(msg_len - len(payload))
        if not chunk:
            break
        payload += chunk
    return payload

def call_ipc(pipe, command, payload=None, req_id="cli-1"):
    req = {
        "id": req_id,
        "command": command,
        "payload": payload
    }
    send_frame(pipe, json.dumps(req).encode('utf-8'))
    resp_bytes = read_frame(pipe)
    return json.loads(resp_bytes.decode('utf-8'))

def main():
    print("=" * 60)
    print("       AEGIS AI Security - Live Endpoint Scanner       ")
    print("=" * 60)

    proc = ensure_engine_running()
    pipe_path = get_pipe_name()

    try:
        pipe = open(pipe_path, 'r+b', buffering=0)
    except Exception as e:
        print(f"[-] Could not open pipe {pipe_path}: {e}")
        return

    # Handshake
    hello = {
        "protocol_version": 1,
        "client_name": "aegis-cli-scanner",
        "client_version": "0.1.0"
    }
    send_frame(pipe, json.dumps(hello).encode('utf-8'))
    ack_bytes = read_frame(pipe)
    ack = json.loads(ack_bytes.decode('utf-8'))
    print(f"[+] Handshake established with AEGIS Server (Session: {ack.get('session_id', 'ok')})")

    # 1. Check System Audit & Coexistence
    print("\n[*] Auditing Operating System Security...")
    audit_resp = call_ipc(pipe, "audit_system", req_id="audit-1")
    if audit_resp.get("ok"):
        d = audit_resp["data"]
        defender = d.get("defender", {})
        fw = d.get("firewall", {})
        print(f"    - Microsoft Defender: {'AKTIF' if defender.get('enabled') else 'PASIF'} (Guncel: {defender.get('up_to_date', False)})")
        print(f"    - Windows Firewall:   {'AKTIF' if fw.get('enabled') else 'PASIF'}")
        print(f"    - UAC Seviyesi:       {d.get('uac_level', 'Bilinmiyor')}")
        print(f"    - Secure Boot:        {'AKTIF' if d.get('secure_boot') else 'PASIF'}")

    # 2. Check Module Status
    print("\n[*] Checking Protection Modules...")
    status_resp = call_ipc(pipe, "get_status", req_id="status-1")
    if status_resp.get("ok"):
        modules = status_resp["data"].get("modules", [])
        for m in modules:
            st = m.get("status", "unknown")
            print(f"    - [{st.upper()}] {m.get('name')}: {m.get('details', '')}")

    # 3. Start Quick Scan
    print("\n[*] Starting Active File & Memory Scan (Quick Scan)...")
    scan_resp = call_ipc(pipe, "start_scan", {"scan_type": "quick", "custom_paths": None}, req_id="scan-start")
    if not scan_resp.get("ok"):
        print(f"[-] Scan could not be started: {scan_resp.get('error')}")
        pipe.close()
        return

    job_id = scan_resp["data"]["job_id"]
    print(f"[+] Scan Job Created: {job_id}")
    print("[*] Scanning system files, downloads, running processes, startup keys...")

    start_time = time.time()
    last_count = 0
    while True:
        time.sleep(0.3)
        prog_resp = call_ipc(pipe, "get_scan_progress", {"job_id": job_id}, req_id=f"prog-{time.time()}")
        if not prog_resp.get("ok"):
            break
        p = prog_resp["data"]
        status = p.get("status")
        scanned = p.get("scanned_files", 0)
        threats = p.get("threats_found", 0)
        current = p.get("current_path", "")

        if scanned != last_count or threats > 0:
            last_count = scanned
            sys.stdout.write(f"\r[>] Taranan Dosya: {scanned} | Bulunan Tehdit: {threats} | {current[:50]:<50}")
            sys.stdout.flush()

        if status in ["completed", "failed", "cancelled"]:
            print(f"\n[+] Scan {status.upper()} in {time.time() - start_time:.2f} seconds.")
            break

    # 4. Display Scan Results & Detections
    res_resp = call_ipc(pipe, "get_scan_result", {"job_id": job_id}, req_id="result-1")
    if res_resp.get("ok"):
        res = res_resp["data"]
        print("\n" + "=" * 60)
        print("                  SCAN RESULTS SUMMARY                      ")
        print("=" * 60)
        print(f"  Toplam Taranan Dosya:  {res.get('scanned_files', 0)}")
        print(f"  Gecen Sure:            {res.get('duration_seconds', 0):.2f} saniye")
        print(f"  Tespit Edilen Tehdit:  {res.get('threats_found', 0)}")

        detections = res.get("detections", [])
        if not detections:
            print("\n  [GUVENLI] Bilgisayarinizda herhangi bir aktif tehdit veya zararli yazilim bulunamadi!")
        else:
            print("\n  [TEHLIKE] ASAGIDAKI TEHDITLER TESPIT EDILDI:")
            for d in detections:
                print(f"   ! [{d.get('severity', 'HIGH').upper()}] {d.get('threat_name')}")
                print(f"     Dosya: {d.get('target_path')}")
                print(f"     Kaynak: {d.get('source')} | Ozet: {d.get('sha256', '')[:16]}...")
        print("=" * 60)

    pipe.close()

if __name__ == '__main__':
    main()

