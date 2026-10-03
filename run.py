"""Start the cafe locally, or on the cafe's Wi-Fi with --mobile."""
import argparse
import socket
import subprocess
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mobile', action='store_true')
    parser.add_argument('--address', help='Reachable LAN IP or hostname for mobile QR codes')
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    command = [sys.executable, '-u', str(root / 'server.py'), '--port', str(args.port)]
    address = '127.0.0.1'
    if args.mobile:
        address = args.address or socket.gethostbyname(socket.gethostname())
        command.extend(['--host', '0.0.0.0', '--public-url', f'http://{address}:{args.port}'])
    print(f'Customer menu: http://{address}:{args.port}', flush=True)
    print(f'Staff console: http://127.0.0.1:{args.port}/admin', flush=True)
    print('Keep this window open. Press Ctrl+C to stop.', flush=True)
    try:
        return subprocess.call(command, cwd=root)
    except KeyboardInterrupt:
        return 0

if __name__ == '__main__':
    raise SystemExit(main())
