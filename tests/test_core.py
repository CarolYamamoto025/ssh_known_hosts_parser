import base64
import hashlib
import hmac
import unittest

from ssh_known_hosts_parser import KnownHostsEntry, parse_line, parse_lines


def _ed25519_key() -> str:
    # A real ssh-ed25519 public key blob: 4-byte len, "ssh-ed25519", 4-byte
    # len, 32 raw key bytes. Total 51 bytes.
    alg = b"ssh-ed25519"
    pub = bytes(range(32))
    blob = (
        len(alg).to_bytes(4, "big")
        + alg
        + len(pub).to_bytes(4, "big")
        + pub
    )
    return base64.b64encode(blob).decode("ascii")


ED25519_B64 = _ed25519_key()


def _rsa_key() -> str:
    alg = b"ssh-rsa"
    e = b"\x01\x00\x01"
    n = b"\x00" + bytes(range(1, 129))
    blob = (
        len(alg).to_bytes(4, "big")
        + alg
        + len(e).to_bytes(4, "big")
        + e
        + len(n).to_bytes(4, "big")
        + n
    )
    return base64.b64encode(blob).decode("ascii")


RSA_B64 = _rsa_key()


class TestParseLine(unittest.TestCase):
    def test_plain_ed25519(self):
        line = f"git.example.com ssh-ed25519 {ED25519_B64}"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.hostnames, "git.example.com")
        self.assertEqual(entry.key_type, "ssh-ed25519")
        self.assertIsInstance(entry.key, bytes)
        self.assertEqual(len(entry.key), 51)

    def test_comment_skipped(self):
        self.assertIsNone(parse_line("# this is a comment"))
        self.assertIsNone(parse_line("   # indented comment"))

    def test_blank_skipped(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("   \t  "))

    def test_marker_cert_authority_stripped(self):
        line = f"@cert-authority *.example.com ssh-ed25519 {ED25519_B64}"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.hostnames, "*.example.com")
        self.assertEqual(entry.key_type, "ssh-ed25519")

    def test_marker_revoked_stripped(self):
        line = f"@revoked bad.example.com ssh-ed25519 {ED25519_B64}"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.hostnames, "bad.example.com")

    def test_trailing_comment_ignored(self):
        line = f"host.example.com ssh-ed25519 {ED25519_B64} # trailing note"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.key_type, "ssh-ed25519")

    def test_multiple_hostnames(self):
        line = f"a.example.com,b.example.com ssh-rsa {RSA_B64}"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.hostnames, "a.example.com,b.example.com")
        self.assertEqual(entry.key_type, "ssh-rsa")

    def test_hashed_hostname_preserved_verbatim(self):
        line = f"|1|cVIAjUlJ7g8r98gdBWtwKg==|k2gGhTt8fHHM8Qp0OSp1gQ== ssh-ed25519 {ED25519_B64}"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.hostnames.startswith("|1|"))
        self.assertEqual(entry.key_type, "ssh-ed25519")

    def test_too_few_fields_raises(self):
        with self.assertRaises(ValueError):
            parse_line("only.example.com ssh-ed25519")

    def test_invalid_base64_raises(self):
        with self.assertRaises(ValueError):
            parse_line("host.example.com ssh-ed25519 not!!!base64!!!")

    def test_key_type_blob_mismatch_raises(self):
        # Declare ssh-rsa but the blob embeds ssh-ed25519.
        line = f"host.example.com ssh-rsa {ED25519_B64}"
        with self.assertRaises(ValueError):
            parse_line(line)

    def test_blob_too_short_raises(self):
        short = base64.b64encode(b"ab").decode("ascii")
        with self.assertRaises(ValueError):
            parse_line(f"host.example.com ssh-ed25519 {short}")


class TestParseLines(unittest.TestCase):
    def test_multi_line(self):
        text = (
            f"# header\n"
            f"\n"
            f"alpha.example.com ssh-ed25519 {ED25519_B64}\n"
            f"beta.example.com ssh-ed25519 {ED25519_B64}\n"
        )
        entries = parse_lines(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].hostnames, "alpha.example.com")
        self.assertEqual(entries[1].hostnames, "beta.example.com")

    def test_malformed_raises(self):
        text = f"good.example.com ssh-ed25519 {ED25519_B64}\nbad ssh-ed25519\n"
        with self.assertRaises(ValueError):
            parse_lines(text)


class TestMatches(unittest.TestCase):
    def _entry(self, hostnames: str) -> KnownHostsEntry:
        return KnownHostsEntry(hostnames=hostnames, key_type="ssh-ed25519", key=b"")

    def test_plain_exact(self):
        e = self._entry("git.example.com")
        self.assertTrue(e.matches("git.example.com"))
        self.assertFalse(e.matches("other.example.com"))

    def test_glob_star(self):
        e = self._entry("*.example.com")
        self.assertTrue(e.matches("a.example.com"))
        self.assertTrue(e.matches("anything.example.com"))
        self.assertFalse(e.matches("example.com"))

    def test_glob_question(self):
        e = self._entry("host?.example.com")
        self.assertTrue(e.matches("host1.example.com"))
        self.assertFalse(e.matches("host12.example.com"))
        self.assertFalse(e.matches("host.example.com"))

    def test_multiple_names(self):
        e = self._entry("a.example.com,b.example.com")
        self.assertTrue(e.matches("a.example.com"))
        self.assertTrue(e.matches("b.example.com"))
        self.assertFalse(e.matches("c.example.com"))

    def test_negation(self):
        e = self._entry("*.example.com,!bad.example.com")
        self.assertTrue(e.matches("good.example.com"))
        self.assertFalse(e.matches("bad.example.com"))

    def test_hashed_match_true(self):
        salt = base64.b64decode("cVIAjUlJ7g8r98gdBWtwKg==")
        host = "example.com"
        digest = hmac.new(salt, host.encode("utf-8"), hashlib.sha1).digest()
        field = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"
        e = self._entry(field)
        self.assertTrue(e.matches("example.com"))

    def test_hashed_match_false(self):
        salt = base64.b64decode("cVIAjUlJ7g8r98gdBWtwKg==")
        digest = hmac.new(salt, b"example.com", hashlib.sha1).digest()
        field = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"
        e = self._entry(field)
        self.assertFalse(e.matches("other.example.com"))


if __name__ == "__main__":
    unittest.main()
