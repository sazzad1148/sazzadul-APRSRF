from __future__ import annotations

import re

from . import normalize as norm

_SPLIT_RE = re.compile(r"[a-z0-9]+")

COMMON_WORDS = {
    "dev", "staging", "stage", "test", "qa", "uat", "prod", "production",
    "api", "app", "apps", "admin", "portal", "internal", "int", "vpn",
    "mail", "smtp", "webmail", "login", "sso", "auth", "gateway", "gw",
    "beta", "alpha", "demo", "sandbox", "preview", "cdn", "static",
    "assets", "media", "img", "images", "docs", "help", "support",
    "status", "monitor", "grafana", "kibana", "jenkins", "gitlab",
    "git", "ci", "cd", "build", "deploy", "k8s", "kube", "cluster",
    "us", "eu", "asia", "east", "west", "north", "south", "www",
}


def extract_words(hosts, domain: str) -> set:
    domain_labels = set(domain.split("."))
    words = set(COMMON_WORDS)
    for h in hosts:
        prefix = h[: -(len(domain) + 1)] if h.endswith("." + domain) else h
        for label in prefix.split("."):
            for word in _SPLIT_RE.findall(label):
                if word and word not in domain_labels and len(word) > 1:
                    words.add(word)
    return words


def generate_deep_permutations(bases, domain: str, words, max_depth: int, limit_per_level: int):
    perms = set()
    words = list(words)
    for base in bases:
        depth = norm.depth_of(base, domain)
        if depth < 0 or depth >= max_depth:
            continue
        for w in words[:limit_per_level]:
            perms.add(f"{w}.{base}")
    return perms
