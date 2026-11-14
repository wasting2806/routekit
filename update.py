"""Merge maintained domain lists into a Tailscale-aware Shadowrocket profile."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import urllib.request

UPSTREAM = "Johnshall/Shadowrocket-ADBlock-Rules-Forever"
DOMAIN_UPSTREAM = "v2fly/domain-list-community"
DOMAIN_LISTS = ("openai", "anthropic", "google-deepmind", "github")
PROFILE = "sr_top500_banlist_ad.conf"
OUTPUT = Path(__file__).resolve().with_name(PROFILE)
UPDATE_URL = f"https://raw.githubusercontent.com/wasting2806/routekit/main/{PROFILE}"
ROUTES = ("10.10.10.30/32", "192.168.1.0/24")
EXCLUSIONS_TO_REMOVE = {"10.0.0.0/8", "192.168.0.0/16"}
RULES = [f"IP-CIDR,{network},TAILSCALE,no-resolve" for network in ROUTES]
DOMAIN_LICENSE = Path(__file__).resolve().parent / "licenses" / "v2fly-MIT.txt"


def section(lines, name):
    positions = [i for i, line in enumerate(lines) if line.strip() == f"[{name}]"]
    if len(positions) != 1:
        raise ValueError(f"Expected exactly one [{name}] section")
    start = positions[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("[")), len(lines))
    return start, end


def assignment(lines, key):
    start, end = section(lines, "General")
    matches = [i for i in range(start, end) if lines[i].split("=", 1)[0].strip() == key]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {key} setting")
    i = matches[0]
    return i, lines[i].split("=", 1)[1].strip()


def validate(text):
    lines = text.splitlines()
    start, end = section(lines, "Rule")
    active = [line.strip() for line in lines[start:end] if line.strip() and not line.lstrip().startswith("#")]
    if active[:len(RULES)] != RULES or any(active.count(rule) != 1 for rule in RULES):
        raise ValueError("Required Tailscale rules must occur once, before upstream rules")
    if len(active) < 1000 or active[-1].lower() != "final,direct" or sum(line.upper().startswith("FINAL,") for line in active) != 1:
        raise ValueError("Upstream rules are truncated or their final policy changed")
    if len(active) != len(set(active)):
        raise ValueError("Duplicate rules remain")
    allowed_sections = {"[General]", "[Rule]", "[URL Rewrite]", "[MITM]"}
    if any(line.strip().startswith("[") and line.strip() not in allowed_sections for line in lines):
        raise ValueError("Unexpected upstream section; review before publishing")
    if any(line.split("=", 1)[0].strip().lower() in {"ca-p12", "ca-passphrase"} for line in lines):
        raise ValueError("Do not distribute certificates or certificate passwords")
    _, bypass = assignment(lines, "bypass-tun")
    excluded = [ipaddress.ip_network(item.strip()) for item in bypass.split(",")]
    for route in map(ipaddress.ip_network, ROUTES):
        if any(route.version == network.version and route.overlaps(network) for network in excluded):
            raise ValueError(f"A TUN exclusion still covers {route}")
    if assignment(lines, "update-url")[1] != UPDATE_URL:
        raise ValueError("Updates must use this customized profile")


def merge_rules(lines, extra):
    """Keep first-match behavior; add only uncovered domains before FINAL."""
    start, end = section(lines, "Rule")
    unique, seen = [], set()
    covered = {"DOMAIN": set(), "DOMAIN-SUFFIX": set(), "DOMAIN-KEYWORD": set()}
    duplicates = 0
    for line in lines[start:end]:
        rule = line.strip()
        if rule and not rule.startswith("#"):
            if rule in seen:
                duplicates += 1
                continue
            seen.add(rule)
            fields = [field.strip() for field in rule.split(",")]
            if fields[0].upper() in covered:
                covered[fields[0].upper()].add(fields[1].lower())
        unique.append(line)
    additions = []
    for kind, domain in sorted(set(extra), key=lambda item: (item[0] != "DOMAIN-SUFFIX", item[1].count("."), item[1])):
        labels = domain.split(".")
        parents = {".".join(labels[i:]) for i in range(len(labels))}
        if parents & covered["DOMAIN-SUFFIX"] or any(word in domain for word in covered["DOMAIN-KEYWORD"]):
            continue
        if kind == "DOMAIN" and domain in covered["DOMAIN"]:
            continue
        additions.append(f"{kind},{domain},PROXY")
        covered[kind].add(domain)
    final = [i for i, line in enumerate(unique) if line.strip().upper().startswith("FINAL,")]
    if len(final) != 1 or unique[final[0]].strip().lower() != "final,direct":
        raise ValueError("Upstream FINAL policy changed")
    if additions:
        unique[final[0]:final[0]] = ["# Routekit: additional AI and GitHub domains", *additions, ""]
    lines[start:end] = unique
    return duplicates, len(additions)


def customize(text, revision, extra=(), provenance=()):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid upstream commit")
    lines = text.splitlines()
    section(lines, "Rule")
    index, bypass = assignment(lines, "bypass-tun")
    entries = [item.strip() for item in bypass.split(",")]
    lines[index] = "bypass-tun = " + ",".join(item for item in entries if item not in EXCLUSIONS_TO_REMOVE)
    start, end = section(lines, "General")
    if any(line.split("=", 1)[0].strip() in {"update-url", "tun-excluded-routes"} for line in lines[start:end]):
        raise ValueError("Upstream update/exclusion format changed; review before publishing")
    lines.insert(start, "update-url = " + UPDATE_URL)
    start, _ = section(lines, "Rule")
    lines[start:start] = RULES
    duplicates, added = merge_rules(lines, extra)
    header = [
        "# Routekit: sr_top500_banlist_ad with Tailscale, AI and GitHub routing",
        f"# Upstream: https://github.com/{UPSTREAM}/blob/{revision}/{PROFILE}",
        f"# Upstream SHA-256: {hashlib.sha256(text.encode()).hexdigest()}",
        "# Original authors: Moshel, h2y, Johnshall and upstream contributors.",
        "# Changes: TUN exclusions, two priority routes, update URL and domain merge.",
        f"# Merge: removed {duplicates} exact duplicates; added {added} uncovered domain rules.",
        "# License: CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/",
        *provenance,
        "",
    ]
    result = "\n".join(header + lines) + "\n"
    validate(result)
    return result


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "routekit-updater"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Upstream response exceeds 8 MiB")
    return data.decode("utf-8")


def current_revision(repo, branch):
    revision = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/{branch}"))["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid upstream commit")
    return revision


def load_domains(revision):
    root = f"https://raw.githubusercontent.com/{DOMAIN_UPSTREAM}/{revision}"
    license_text = fetch(root + "/LICENSE")
    if license_text != DOMAIN_LICENSE.read_text(encoding="utf-8"):
        raise ValueError("Domain source license changed; review before publishing")
    rules, provenance, loaded, visiting = [], [], set(), set()
    skipped_tracking = skipped_patterns = 0

    def visit(name):
        nonlocal skipped_tracking, skipped_patterns
        if not re.fullmatch(r"[a-z0-9-]+", name) or name in visiting:
            raise ValueError("Invalid or cyclic domain include")
        if name in loaded:
            return
        if len(loaded | visiting) >= 16:
            raise ValueError("Domain includes grew unexpectedly")
        visiting.add(name)
        source = fetch(f"{root}/data/{name}")
        if not source.strip() or len(source.splitlines()) > 2000:
            raise ValueError(f"Unexpected domain list size: {name}")
        provenance.extend([
            f"# Domains: https://github.com/{DOMAIN_UPSTREAM}/blob/{revision}/data/{name}",
            f"# SHA-256: {hashlib.sha256(source.encode()).hexdigest()}",
        ])
        before = len(rules)
        for raw in source.splitlines():
            fields = raw.split("#", 1)[0].split()
            if not fields:
                continue
            entry, *attributes = fields
            if any(not re.fullmatch(r"[@&][a-zA-Z0-9_!-]+", attr) for attr in attributes):
                raise ValueError(f"Unsupported domain attributes: {raw}")
            kind, sep, value = entry.partition(":")
            if not sep:
                kind, value = "domain", entry
            if kind == "include":
                if attributes:
                    raise ValueError("Filtered includes need review")
                visit(value)
                continue
            if kind not in {"domain", "full", "regexp", "keyword"}:
                raise ValueError(f"Unsupported domain entry: {raw}")
            if {"@ads", "@telemetry"} & set(attributes):
                skipped_tracking += 1
                continue
            # shortcut: domain-only supplement; review patterns if a service needs them.
            if kind in {"regexp", "keyword"}:
                skipped_patterns += 1
                continue
            if len(value) > 253 or "." not in value or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
                raise ValueError(f"Invalid domain: {value}")
            rules.append(("DOMAIN" if kind == "full" else "DOMAIN-SUFFIX", value))
        if len(rules) == before:
            raise ValueError(f"No usable domains in {name}")
        visiting.remove(name)
        loaded.add(name)

    for name in DOMAIN_LISTS:
        visit(name)
    provenance.append(f"# Supplement exclusions: {skipped_tracking} ads/telemetry; {skipped_patterns} regex/keyword patterns.")
    provenance.extend(["# Supplemental domain source license:", *[("# " + line).rstrip() for line in license_text.splitlines()]])
    return rules, provenance


def refresh():
    revision = current_revision(UPSTREAM, "release")
    source = fetch(f"https://raw.githubusercontent.com/{UPSTREAM}/{revision}/{PROFILE}")
    extra, provenance = load_domains(current_revision(DOMAIN_UPSTREAM, "master"))
    result = customize(source, revision, extra, provenance)
    if OUTPUT.exists():
        previous_size = len(OUTPUT.read_text(encoding="utf-8").splitlines())
        if not previous_size * 0.8 <= len(result.splitlines()) <= previous_size * 1.25:
            raise ValueError("Profile size changed substantially; review before publishing")
    temporary = OUTPUT.with_suffix(".tmp")
    temporary.write_text(result, encoding="utf-8")
    temporary.replace(OUTPUT)
    print(f"Updated from {revision}; {len(result.splitlines())} lines")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="Download upstream and regenerate; otherwise check offline")
    args = parser.parse_args()
    if args.update:
        refresh()
    else:
        validate(OUTPUT.read_text(encoding="utf-8"))
        print("Profile checks passed")


if __name__ == "__main__":
    main()
