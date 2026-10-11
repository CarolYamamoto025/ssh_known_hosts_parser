# ssh_known_hosts_parser

Parses lines from an OpenSSH `known_hosts` file into `(hostnames, key_type, key)` tuples, handling hashed hostnames and `@cert-authority` / `@revoked` marker fields.

```python
import base64
from ssh_known_hosts_parser import parse_line, parse_lines, KnownHostsEntry

# A minimal ssh-ed25519 public key blob: 4-byte len, "ssh-ed25519", 4-byte
# len, 32 raw key bytes.
alg = b"ssh-ed25519"
pub = bytes(range(32))
blob = len(alg).to_bytes(4, "big") + alg + len(pub).to_bytes(4, "big") + pub
key_b64 = base64.b64encode(blob).decode("ascii")

entry = parse_line(f"git.example.com ssh-ed25519 {key_b64}")
print(entry.hostnames, entry.key_type, len(entry.key))

for e in parse_lines("git.example.com ssh-ed25519 " + key_b64 + "\n"):
    print(e.hostnames, e.key_type)

assert entry.matches("git.example.com")
```

`parse_line` returns `None` for blank lines and comments, raises `ValueError` for structurally malformed lines, and returns a `KnownHostsEntry(hostnames, key_type, key)` for everything else. `parse_lines` applies the same logic to a full string and returns a list. `KnownHostsEntry.matches(host)` tests whether a given host is covered by the entry, including HMAC-SHA1 verification for hashed (`|1|...`) hostnames.

## Why this exists

Working with `known_hosts` programmatically means dealing with three persistent annoyances: optional marker prefixes (`@cert-authority`, `@revoked`), hashed hostname fields that cannot be reversed, and base64 key blobs whose internal structure must agree with the declared key type. This library handles all three so callers can iterate entries without re-implementing the same splitting and validation each time.

The trade-off: markers are stripped rather than surfaced. If you need to distinguish a certificate authority entry from a regular one, inspect the raw line for the leading `@cert-authority` token yourself before calling `parse_line`.

## Edge you will hit

Hashed hostnames are stored verbatim in `entry.hostnames` (the literal `|1|<salt>|<hash>` string). There is no way to recover the original hostname — that is the point of hashing. Use `entry.matches("candidate.example.com")` to test a specific host against a hashed entry; it recomputes the HMAC and compares in constant time.

Plain hostname fields support comma-separated patterns with `*` and `?` globs and `!`-prefixed negations. Bracket character classes (`[abc]`) are intentionally not implemented, matching OpenSSH's own treatment of them as literal characters in known_hosts patterns.
