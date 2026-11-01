#!/usr/bin/env python3
"""
Builds the domain catalog NetWatcher shows next to domains: which company owns a domain and whether it
is mainly used for ads, analytics or Windows telemetry.

Sources (downloaded by .github/workflows/data-mirror.yml and build.yml):
  - DuckDuckGo Tracker Blocklists, web/v6/extension-tds.json
    https://github.com/duckduckgo/tracker-blocklists — CC BY-NC-SA 4.0, (c) Duck Duck Go, Inc.
  - WindowsSpyBlocker, data/hosts/spy.txt
    https://github.com/crazy-max/WindowsSpyBlocker — MIT, (c) CrazyMax

The output is an adapted database and is shared under CC BY-NC-SA 4.0 as well.

Output: gzip TSV, one line per domain: domain, company, tag, categories, source.
  tag: tracker | malware | telemetry | "" (company only)

Usage: build-catalog.py TDS_JSON SPY_TXT OUT_GZ
"""
import gzip
import json
import sys

MALWARE = {"Malware"}
# A domain with any of these is also a service people open on purpose (a social network, a login page,
# payments, a CDN): it gets only the company, so visiting the service is not called tracking.
SERVICE = {"Social Network", "Federated Login", "SSO", "Online Payment", "Content Delivery"}
# Blocked by DuckDuckGo only when embedded in other sites, but in Windows mostly opened directly.
DIRECT_SERVICES = {"bing.com"}
# Current diagnostic data endpoints named by Microsoft (WindowsSpyBlocker's list dates from 2022):
# "Manage connection endpoints for Windows 11 Enterprise" and "Configure Windows diagnostic data in your
# organization", learn.microsoft.com/windows/privacy.
MICROSOFT_TELEMETRY = ["v10.events.data.microsoft.com", "settings-win.data.microsoft.com"]


def clean(s):
    return (s or "").replace("\t", " ").replace("\n", " ").strip()


def tag_of(domain, tracker):
    cats = set(tracker.get("categories") or [])
    if cats & MALWARE:
        return "malware"
    # "block" by default: DuckDuckGo treats the whole domain as a tracker, not only some of its paths.
    if tracker.get("default") != "block" or cats & SERVICE or domain in DIRECT_SERVICES:
        return ""
    return "tracker"


def main(tds_path, spy_path, out_path):
    tds = json.load(open(tds_path, encoding="utf-8"))
    entities = tds.get("entities", {})

    def company(entity):
        e = entities.get(entity) or {}
        return clean(e.get("displayName") or entity)

    rows = {}
    for domain, entity in tds.get("domains", {}).items():
        rows[domain.lower()] = [company(entity), "", "", "ddg"]
    for domain, t in tds.get("trackers", {}).items():
        owner = (t.get("owner") or {})
        name = clean(owner.get("displayName") or owner.get("name") or "")
        row = rows.setdefault(domain.lower(), [name, "", "", "ddg"])
        if not row[0]:
            row[0] = name
        row[1] = tag_of(domain.lower(), t)
        row[2] = ",".join(sorted(t.get("categories") or []))

    telemetry = 0
    for line in open(spy_path, encoding="utf-8"):
        parts = line.split("#", 1)[0].split()
        if len(parts) != 2 or parts[0] not in ("0.0.0.0", "127.0.0.1"):
            continue
        host = parts[1].lower().strip(".")
        row = rows.setdefault(host, ["", "", "", ""])
        if row[1] == "":  # DuckDuckGo's tracker or malware mark is more specific
            row[1] = "telemetry"
        row[3] = "wsb" if row[3] in ("", "wsb") else row[3] + "+wsb"
        telemetry += 1

    for host in MICROSOFT_TELEMETRY:
        row = rows.setdefault(host, ["", "", "", ""])
        if row[1] == "":
            row[1] = "telemetry"
        row[3] = "ms" if row[3] == "" else row[3] + "+ms"
        telemetry += 1

    trackers = sum(1 for r in rows.values() if r[1] in ("tracker", "malware"))
    with gzip.open(out_path, "wt", encoding="utf-8", newline="\n") as out:
        out.write("# NetWatcher domain catalog. Sources: DuckDuckGo Tracker Blocklists (CC BY-NC-SA 4.0), "
                  "WindowsSpyBlocker (MIT). This file: CC BY-NC-SA 4.0.\n")
        for domain in sorted(rows):
            c, tag, cats, src = rows[domain]
            out.write(f"{domain}\t{c}\t{tag}\t{cats}\t{src}\n")
    print(f"domains: {len(rows)}, trackers: {trackers}, telemetry hosts: {telemetry}")
    if len(rows) < 1000 or telemetry < 50:
        sys.exit("catalog looks too small")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
