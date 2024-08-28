import subprocess
import concurrent.futures

# Define the IP fragment
ip_fragment = "10.159.154."

# Define the function to ping an IP address
def ping_ip(ip):
    try:
        # Run the ping command with a timeout of 1 second
        result = subprocess.run(f"powershell -c \"Test-Connection {ip} -Count 1\"")
        # Check the return code to determine success
        if result.returncode == 0:
            return f"{ip} is reachable"
        else:
            return f"{ip} is not reachable"
    except subprocess.TimeoutExpired:
        return f"{ip} is not reachable (timeout)"
    except Exception as e:
        return f"{ip} error: {str(e)}"

# Main function to ping a range of IP addresses using threading
def main():
    ip_range = range(1, 256)
    ips = [f"{ip_fragment}{i}" for i in ip_range]

    # Use ThreadPoolExecutor to ping IPs concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(ping_ip, ips)

    # Print results
    for result in results:
        print(result)

if __name__ == "__main__":
    main()
