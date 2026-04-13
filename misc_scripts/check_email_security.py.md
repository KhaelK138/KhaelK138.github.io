---
layout: blank
pagetitle: 
---

```py

#!/usr/bin/env python3
"""
Check email security (SPF, DMARC, DKIM) for a list of domains.

Reads domains from domains.txt (comma-separated) and queries DNS for:
  - SPF: TXT record on the domain containing "v=spf1"
  - DMARC: TXT record at _dmarc.<domain> containing "v=DMARC1"
  - DKIM: TXT records at <selector>._domainkey.<domain> for common selectors
"""

import subprocess
import sys
import re
from dataclasses import dataclass, field

# Common DKIM selectors used by major email providers
DKIM_SELECTORS = [
    "default",          # Generic default
    "google",           # Google Workspace
    "selector1",        # Microsoft 365
    "selector2",        # Microsoft 365
    "s1",               # SendGrid / generic
    "s2",               # SendGrid / generic
    "k1",               # Mailchimp
    "k2",               # Mailchimp
    "k3",               # Mailchimp
    "mandrill",         # Mandrill (Mailchimp transactional)
    "smtp",             # Generic SMTP
    "mail",             # Generic
    "dkim",             # Generic
    "mimecast",         # Mimecast
    "protonmail",       # ProtonMail
    "protonmail2",      # ProtonMail
    "protonmail3",      # ProtonMail
    "zendesk1",         # Zendesk
    "zendesk2",         # Zendesk
    "cm",               # Campaign Monitor
    "everlytickey1",    # Everlytic
    "everlytickey2",    # Everlytic
    "pic",              # Postmark
    "fm1",              # Fastmail
    "fm2",              # Fastmail
    "fm3",              # Fastmail
    "hse1",             # HubSpot
    "hse2",             # HubSpot
    "sig1",             # SignalHire / misc
    "smtpapi",          # SendGrid legacy
]


@dataclass
class DomainResult:
    domain: str
    spf: str | None = None
    dmarc: str | None = None
    dkim_selectors: dict[str, str] = field(default_factory=dict)

    @property
    def has_spf(self) -> bool:
        return self.spf is not None

    @property
    def has_dmarc(self) -> bool:
        return self.dmarc is not None

    @property
    def has_dkim(self) -> bool:
        return len(self.dkim_selectors) > 0

    @property
    def dmarc_policy(self) -> str:
        if not self.dmarc:
            return "none (missing)"
        match = re.search(r"p=(\w+)", self.dmarc)
        return match.group(1) if match else "unknown"

    @property
    def is_secure(self) -> bool:
        return self.has_spf and self.has_dmarc and self.has_dkim


def dig_txt(name: str) -> list[str]:
    """Query TXT records for a DNS name using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []
        # dig returns quoted strings, sometimes split across lines for long records
        # Reassemble multi-part TXT records
        lines = result.stdout.strip().splitlines()
        records = []
        for line in lines:
            # Remove surrounding quotes and join split parts
            parts = re.findall(r'"([^"]*)"', line)
            if parts:
                records.append("".join(parts))
        return records
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def check_spf(domain: str) -> str | None:
    """Check for SPF record on the domain."""
    records = dig_txt(domain)
    for record in records:
        if record.startswith("v=spf1"):
            return record
    return None


def check_dmarc(domain: str) -> str | None:
    """Check for DMARC record at _dmarc.<domain>."""
    records = dig_txt(f"_dmarc.{domain}")
    for record in records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def check_dkim(domain: str, selectors: list[str]) -> dict[str, str]:
    """Check DKIM records for each selector. Returns {selector: record}."""
    found = {}
    for selector in selectors:
        records = dig_txt(f"{selector}._domainkey.{domain}")
        for record in records:
            if "p=" in record:
                found[selector] = record
                break
            # CNAME-based DKIM (e.g., SendGrid) shows as a hostname
            if "domainkey" in record.lower():
                found[selector] = f"(CNAME -> {record})"
                break
    return found


def load_domains(path: str) -> list[str]:
    """Load domains from a comma-separated file."""
    with open(path) as f:
        content = f.read()
    domains = [d.strip() for d in content.replace("\n", ",").split(",")]
    return [d for d in domains if d]


def check_domain(domain: str) -> DomainResult:
    """Run all email security checks on a domain."""
    result = DomainResult(domain=domain)
    result.spf = check_spf(domain)
    result.dmarc = check_dmarc(domain)
    result.dkim_selectors = check_dkim(domain, DKIM_SELECTORS)
    return result


def print_result(r: DomainResult) -> None:
    spf_icon = "+" if r.has_spf else "X"
    dmarc_icon = "+" if r.has_dmarc else "X"
    dkim_icon = "+" if r.has_dkim else "X"

    print(f"\n{'='*60}")
    print(f"  {r.domain}")
    print(f"{'='*60}")
    print(f"  [{spf_icon}] SPF:   {r.spf or 'MISSING'}")
    print(f"  [{dmarc_icon}] DMARC: {r.dmarc or 'MISSING'} (policy: {r.dmarc_policy})")
    if r.dkim_selectors:
        print(f"  [{dkim_icon}] DKIM:  {len(r.dkim_selectors)} selector(s) found")
        for sel, val in r.dkim_selectors.items():
            display = val if len(val) < 80 else val[:77] + "..."
            print(f"           - {sel}: {display}")
    else:
        print(f"  [{dkim_icon}] DKIM:  MISSING (checked {len(DKIM_SELECTORS)} common selectors)")


def print_summary(results: list[DomainResult]) -> None:
    secure = [r for r in results if r.is_secure]
    missing_spf = [r for r in results if not r.has_spf]
    missing_dmarc = [r for r in results if not r.has_dmarc]
    missing_dkim = [r for r in results if not r.has_dkim]
    weak_dmarc = [r for r in results if r.has_dmarc and r.dmarc_policy == "none"]

    print(f"\n\n{'#'*60}")
    print(f"  SUMMARY: {len(results)} domains checked")
    print(f"{'#'*60}")
    print(f"  Fully secured (SPF + DMARC + DKIM): {len(secure)}/{len(results)}")
    print()

    if missing_spf:
        print(f"  Missing SPF ({len(missing_spf)}):")
        for r in missing_spf:
            print(f"    - {r.domain}")

    if missing_dmarc:
        print(f"\n  Missing DMARC ({len(missing_dmarc)}):")
        for r in missing_dmarc:
            print(f"    - {r.domain}")

    if weak_dmarc:
        print(f"\n  Weak DMARC policy=none ({len(weak_dmarc)}):")
        for r in weak_dmarc:
            print(f"    - {r.domain}")

    if missing_dkim:
        print(f"\n  No DKIM selectors found ({len(missing_dkim)}):")
        for r in missing_dkim:
            print(f"    - {r.domain}")

    # Domains with no email security at all
    no_security = [r for r in results if not r.has_spf and not r.has_dmarc and not r.has_dkim]
    if no_security:
        print(f"\n  NO EMAIL SECURITY AT ALL ({len(no_security)}):")
        for r in no_security:
            print(f"    - {r.domain}")


def main():
    domains_file = sys.argv[1] if len(sys.argv) > 1 else "domains.txt"

    try:
        domains = load_domains(domains_file)
    except FileNotFoundError:
        print(f"Error: {domains_file} not found")
        sys.exit(1)

    print(f"Checking email security for {len(domains)} domains...")
    print(f"DKIM selectors to check: {len(DKIM_SELECTORS)}")

    results = []
    for domain in domains:
        print(f"\n  Checking {domain}...", end="", flush=True)
        result = check_domain(domain)
        results.append(result)
        status = "SECURE" if result.is_secure else "ISSUES"
        print(f" {status}")

    for r in results:
        print_result(r)

    print_summary(results)


if __name__ == "__main__":
    main()

```