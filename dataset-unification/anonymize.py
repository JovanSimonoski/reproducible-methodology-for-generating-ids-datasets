"""
anonymize.py  -  Consistent pseudonymization of public IP addresses in a dataset release.

Every public address (globally routable unicast) is replaced by an address from the
documentation ranges: RFC 5737 for IPv4 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and RFC 3849 for IPv6 (2001:db8::/32). Addresses on a keep list stay as they are.
Private, link-local, multicast and other special-purpose addresses are never changed, so
the lab topology, attacker/target roles and labels stay intact, and the derived address
flags (src_is_private, dst_is_multicast, ...) remain correct for the new values.

The mapping is random but persistent: it lives in a private CSV (real_ip,pseudonym) that
is read before and extended after every build, so an address keeps its pseudonym across
builds and captures. That file is the de-anonymization key: keep it out of every release
and out of version control.

Used by build_dataset.py; pure standard library.
"""

import csv
import ipaddress
import os
import secrets

DOC_V4 = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
DOC_V6 = ipaddress.ip_network("2001:db8::/32")


def canonical_key(src_ip, src_port, dst_ip, dst_port, protocol):
    """Same direction-independent key as flow-extraction/common.py."""
    a = f"{src_ip}:{src_port}"
    b = f"{dst_ip}:{dst_port}"
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{lo}|{hi}|{protocol}"


def is_documentation(addr):
    return addr in DOC_V6 if addr.version == 6 else any(addr in n for n in DOC_V4)


class PublicIpAnonymizer:
    def __init__(self, map_path, keep=()):
        self.map_path = map_path
        self.keep = {str(ipaddress.ip_address(k)) for k in keep}
        self.mapping = {}                 # real public address -> pseudonym
        if os.path.exists(map_path):
            with open(map_path, newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    self.mapping[row["real_ip"]] = row["pseudonym"]
        if len(set(self.mapping.values())) != len(self.mapping):
            raise ValueError(f"{map_path}: two addresses share a pseudonym")
        self.loaded = len(self.mapping)
        used = set(self.mapping.values())
        self.free_v4 = [str(h) for n in DOC_V4 for h in n.hosts() if str(h) not in used]
        self.used_v6 = {p for p in used if ":" in p}
        self.rng = secrets.SystemRandom()
        self.cache = {}                   # any string -> replacement (itself if unchanged)
        self.seen = set()                 # public addresses replaced in this build
        self.kept_seen = set()            # keep-list addresses met in this build
        self.rows_changed = 0

    # -- single values -------------------------------------------------------
    def _assign(self, real):
        if ":" in real:
            while True:
                p = str(DOC_V6.network_address + self.rng.randrange(1, DOC_V6.num_addresses))
                if p not in self.used_v6:
                    self.used_v6.add(p)
                    break
        else:
            if not self.free_v4:
                raise ValueError("IPv4 documentation ranges exhausted (762 addresses)")
            p = self.free_v4.pop(self.rng.randrange(len(self.free_v4)))
        self.mapping[real] = p
        return p

    def ip(self, value):
        """Pseudonym if value is a public address not on the keep list, else value."""
        out = self.cache.get(value)
        if out is not None:
            return out
        out = value
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            addr = None
        if addr is not None:
            real = str(addr)
            if is_documentation(addr):
                raise ValueError(f"input already contains documentation address {value}; "
                                 "pseudonyms could collide with it")
            if addr.is_global and not addr.is_multicast:
                if real in self.keep:
                    self.kept_seen.add(real)
                else:
                    out = self.mapping.get(real) or self._assign(real)
                    self.seen.add(real)
        self.cache[value] = out
        return out

    def host(self, value):
        """Like ip(), but also handles an 'ipv4:port' literal (e.g. an HTTP Host header)."""
        if not value or not (value[0].isdigit() or value[0] == "["):
            return value
        out = self.ip(value)
        if out == value and value.count(":") == 1:
            addr, port = value.split(":")
            out = f"{self.ip(addr)}:{port}"
        return out

    # -- structures ----------------------------------------------------------
    def walk(self, obj):
        """Apply ip() to every string (and dict key) of a JSON-like structure."""
        if isinstance(obj, dict):
            return {(self.ip(k) if isinstance(k, str) else k): self.walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk(v) for v in obj]
        if isinstance(obj, str):
            return self.ip(obj)
        return obj

    def flow_row(self, row, cols):
        """Anonymize one flow row; cols maps column name -> index. Returns the row
        unchanged (same object) when it holds no public address."""
        s, d = row[cols["src_ip"]], row[cols["dst_ip"]]
        s2, d2 = self.ip(s), self.ip(d)
        rsn = row[cols["requested_server_name"]]
        rsn2 = self.host(rsn)
        if s2 == s and d2 == d and rsn2 == rsn:
            return row
        sp, dp, proto = row[cols["src_port"]], row[cols["dst_port"]], row[cols["protocol"]]
        if row[cols["canonical_key"]] != canonical_key(s, sp, d, dp, proto):
            raise ValueError(f"canonical_key {row[cols['canonical_key']]!r} does not follow the "
                             "flow-extraction format; cannot rewrite it safely")
        row = list(row)
        row[cols["src_ip"]], row[cols["dst_ip"]] = s2, d2
        row[cols["requested_server_name"]] = rsn2
        row[cols["canonical_key"]] = canonical_key(s2, sp, d2, dp, proto)
        self.rows_changed += 1
        return row

    # -- persistence / reporting ---------------------------------------------
    def save(self):
        """Write the (possibly extended) mapping atomically."""
        os.makedirs(os.path.dirname(os.path.abspath(self.map_path)), exist_ok=True)
        tmp = self.map_path + ".tmp"
        with open(tmp, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["real_ip", "pseudonym"])
            for real in sorted(self.mapping, key=lambda a: ipaddress.ip_address(a).packed):
                w.writerow([real, self.mapping[real]])
        os.replace(tmp, self.map_path)

    def summary(self):
        return {
            "method": "public IPs -> random, persistent pseudonyms in documentation ranges "
                      "(RFC 5737 / RFC 3849); private, multicast and special-purpose addresses unchanged",
            "public_ips_pseudonymized": len(self.seen),
            "public_ips_kept": sorted(self.kept_seen),
            "flows_changed": self.rows_changed,
            "new_mappings_this_build": len(self.mapping) - self.loaded,
        }
