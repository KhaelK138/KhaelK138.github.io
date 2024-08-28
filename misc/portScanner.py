import socket
import threading
import sys

# List of top 20 most common network ports
top_ports = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
    49155, 49156, 49157
]

open_ports = []

# Function to scan a specific port on the given IP
def scan_port(ip, port):
    with lock:
        print(f"Scanning {ip}:{port}...")
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout to 1 second
        # Try to connect to the IP and port
        result = sock.connect_ex((ip, port))
        if result == 0:
            with lock:
                open_ports.append(port)
        sock.close()
    except Exception as e:
        with lock:
            print(f"Error scanning {ip}:{port} - {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python scan_ports.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]

    # Create a list to hold threads
    threads = []
    global lock
    lock = threading.Lock()

    # Create and start a thread for each port
    for port in top_ports:
        thread = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print("Scanning complete.")

if __name__ == "__main__":
    main()
    print("Open ports:", open_ports)
