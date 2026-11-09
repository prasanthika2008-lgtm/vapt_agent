"""Scope enforcement: every target/asset is checked here before any action."""
import ipaddress
import re
from urllib.parse import urlparse


def _host(t: str) -> str:
    t = t.strip()
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split("/")[0].split(":")[0] if not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", t) else t


class Scope:
    def __init__(self, targets, exclusions=()):
        self.targets = [x.strip() for x in targets if x.strip()]
        self.exclusions = [x.strip() for x in exclusions if x.strip()]

    @staticmethod
    def _match(host: str, rule: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return ip in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return host.lower() == rule.lower()

    def check(self, target: str):
        """Returns (allowed: bool, reason: str)."""
        host = _host(target)
        if not host:
            return False, "Could not parse a host from the target."
        for ex in self.exclusions:
            if self._match(host, ex):
                return False, f"{host} is explicitly EXCLUDED ({ex})."
        for t in self.targets:
            if self._match(host, t):
                return True, f"{host} matches authorised scope entry {t}."
        return False, f"{host} is NOT in the authorised lab scope {self.targets}."


def extract_target(text: str):
    """Pull first IPv4 / URL / hostname out of a natural-language request."""
    m = re.search(r"https?://[^\s]+", text)
    if m:
        return m.group(0)
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b", text)
    if m:
        return m.group(0)
    m = re.search(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b", text)
    return m.group(0) if m else None
