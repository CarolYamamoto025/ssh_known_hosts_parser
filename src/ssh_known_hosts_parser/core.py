"""Parser for OpenSSH known_hosts lines."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Iterator, List, Optional


@dataclass(frozen=True)
class KnownHostsEntry:
    """A single parsed entry from a known_hosts file.

    Attributes:
        hostnames: Raw hostnames field. For hashed entries this is the
            literal "|1|<salt>|<hash>" string from the file; the parser does
            not reverse one-way hashes. Callers who need to match a candidate
            host against a hashed entry should use ``matches`` instead.
        key_type: The public key algorithm identifier (e.g. ``ssh-ed25519``).
        key: The decoded binary public key, as ``bytes``.
    """

    hostnames: str
    key_type: str
    key: bytes

    def matches(self, host: str) -> bool:
        """Return whether ``host`` is covered by this entry's hostnames field.

        For plain entries the field may contain comma-separated names, any of
        which may itself be a glob pattern (``*``, ``?``) or a negation
        prefixed with ``!``. For hashed entries the salt and hash are used to
        compute an HMAC-SHA1 of ``host`` and compared in constant time.
        """
        field = self.hostnames
        if field.startswith("|1|"):
            return self._matches_hashed(host)
        return _matches_plain(field, host)

    def _matches_hashed(self, host: str) -> bool:
        parts = self.hostnames.split("|")
        # field looks like "|1|<salt-b64>|<hash-b64>"; split on "|" yields
        # ["", "1", salt, hash].
        if len(parts) != 4:
            return False
        try:
            salt = base64.b64decode(parts[2], validate=True)
            digest = base64.b64decode(parts[3], validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        computed = hmac.new(salt, host.encode("utf-8"), hashlib.sha1).digest()
        return hmac.compare_digest(computed, digest)


def _matches_plain(field: str, host: str) -> bool:
    matched = False
    for token in field.split(","):
        if not token:
            continue
        negated = token.startswith("!")
        pattern = token[1:] if negated else token
        if _glob_match(pattern, host):
            if negated:
                return False
            matched = True
    return matched


def _glob_match(pattern: str, host: str) -> bool:
    """Match ``host`` against an ssh-style glob pattern.

    Supports ``*`` (any sequence) and ``?`` (exactly one character), matching
    OpenSSH's ``match_pattern`` semantics for these metacharacters. Bracket
    expressions are intentionally not supported because OpenSSH itself treats
    them literally in known_hosts patterns.
    """
    return _glob_rec(pattern, 0, host, 0)


def _glob_rec(pat: str, pi: int, txt: str, ti: int) -> bool:
    while pi < len(pat):
        c = pat[pi]
        if c == "*":
            # Collapse consecutive stars; try every remaining suffix of txt.
            while pi < len(pat) and pat[pi] == "*":
                pi += 1
            if pi == len(pat):
                return True
            for j in range(ti, len(txt) + 1):
                if _glob_rec(pat, pi, txt, j):
                    return True
            return False
        if c == "?":
            if ti >= len(txt):
                return False
            pi += 1
            ti += 1
            continue
        if ti >= len(txt) or txt[ti] != c:
            return False
        pi += 1
        ti += 1
    return ti == len(txt)


_MARKER_CERT = "@cert-authority"
_MARKER_REVOKED = "@revoked"


def parse_line(line: str) -> Optional[KnownHostsEntry]:
    """Parse a single known_hosts line.

    Returns ``None`` for blank lines and comments (lines whose first
    non-whitespace character is ``#``). Lines beginning with a marker
    (``@cert-authority`` or ``@revoked``) are returned with the marker stripped;
    callers who need to distinguish marked entries must inspect the raw input.

    A ``ValueError`` is raised when the line has content but is structurally
    malformed: fewer than three fields after marker removal, non-base64 key
    data, or a base64-decoded body too short to contain the embedded algorithm
    name.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    fields = stripped.split()
    if fields and fields[0] in (_MARKER_CERT, _MARKER_REVOKED):
        fields = fields[1:]

    if len(fields) < 3:
        raise ValueError(f"expected >= 3 fields, got {len(fields)}: {line!r}")

    hostnames = fields[0]
    key_type = fields[1]
    key_b64 = fields[2]

    try:
        raw = base64.b64decode(key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"invalid base64 key: {exc}") from exc

    _verify_key_type_in_blob(raw, key_type)

    return KnownHostsEntry(hostnames=hostnames, key_type=key_type, key=raw)


def _verify_key_type_in_blob(blob: bytes, declared_type: str) -> None:
    """Check that the decoded key blob begins with the declared algorithm.

    Every SSH public key blob starts with a 4-byte big-endian length prefix
    followed by the algorithm name as ASCII. Requiring the embedded name to
    agree with the field on the line catches trivial corruption early and
    gives a better error than a downstream mismatch. RSA certificate keys
    carry a ``-cert`` suffix in their type name that the blob also includes.
    """
    if len(blob) < 4:
        raise ValueError("key blob too short to contain a length prefix")
    name_len = int.from_bytes(blob[:4], "big")
    end = 4 + name_len
    if end > len(blob):
        raise ValueError("key blob truncated before algorithm name")
    try:
        embedded = blob[4:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII bytes in algorithm name") from exc
    if embedded != declared_type:
        raise ValueError(
            f"key type mismatch: field says {declared_type!r}, blob says {embedded!r}"
        )


def parse_lines(lines: str) -> List[KnownHostsEntry]:
    """Parse a multi-line string of known_hosts entries.

    Blank lines and comments are skipped; malformed content lines raise
    ``ValueError`` immediately rather than silently dropping them, because a
    half-parsed file is usually worse than no file at all.
    """
    return list(iter_lines(lines))


def iter_lines(lines: str) -> Iterator[KnownHostsEntry]:
    """Yield parsed entries from a multi-line string, skipping blanks/comments."""
    for raw in lines.splitlines():
        entry = parse_line(raw)
        if entry is not None:
            yield entry
