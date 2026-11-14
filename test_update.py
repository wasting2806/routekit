import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from update import DOMAIN_LICENSE, EXCLUSIONS_TO_REMOVE, RULES, UPDATE_URL, customize, load_domains, refresh, validate

REVISION = "a" * 40
BASE = "\n".join([
    "# upstream attribution", "[General]", "ipv6 = false",
    "bypass-tun = 10.0.0.0/8,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10,::1/128",
    "skip-proxy = 10.0.0.0/8,192.168.0.0/16", "[Rule]",
    *[f"DOMAIN,ad{i}.example,REJECT" for i in range(1000)], "FINAL,direct",
    "[URL Rewrite]", "^https://example.invalid/ - reject", "[MITM]", "hostname = example.invalid", "",
])


class ProfileTests(unittest.TestCase):
    def test_only_declared_changes_and_attribution(self):
        result = customize(BASE, REVISION)
        validate(result)
        restored = result[result.index("# upstream attribution"):]
        restored = restored.replace("update-url = " + UPDATE_URL + "\n", "")
        for rule in RULES:
            restored = restored.replace(rule + "\n", "")
        restored = restored.replace("bypass-tun = ", "bypass-tun = 10.0.0.0/8,192.168.0.0/16,")
        self.assertEqual(restored, BASE)
        self.assertEqual(customize(BASE, REVISION), result)

    def test_rejects_incomplete_or_ambiguous_upstream(self):
        for text in ["<html>error</html>", BASE.replace("[Rule]", "[Rule]\n[Rule]"),
                     BASE.replace("[General]", "[General]\nupdate-url = https://example.invalid"),
                     BASE.replace("bypass-tun = ", "bypass-tun = 0.0.0.0/0,"),
                     BASE.replace("FINAL,direct", "FINAL,PROXY")]:
            with self.subTest(text=text[:60]), self.assertRaises(ValueError):
                customize(text, REVISION)

    def test_rejects_lost_customization(self):
        result = customize(BASE, REVISION)
        for text in [result.replace(RULES[0] + "\n", ""),
                     result.replace(UPDATE_URL, "https://example.invalid"),
                     *[result.replace("bypass-tun = ", "bypass-tun = " + item + ",") for item in EXCLUSIONS_TO_REMOVE]]:
            with self.subTest(text=text[:60]), self.assertRaises(ValueError):
                validate(text)

    def test_merge_preserves_rejections_and_first_match_order(self):
        source = BASE.replace("[Rule]\n", "[Rule]\nDOMAIN-SUFFIX,covered.test,Proxy\nDOMAIN,blocked.new.test,REJECT\n")
        source = source.replace("FINAL,direct", "DOMAIN,ad0.example,REJECT\nFINAL,direct")
        extra = [("DOMAIN-SUFFIX", "new.test"), ("DOMAIN", "sub.new.test"),
                 ("DOMAIN-SUFFIX", "sub.covered.test"), ("DOMAIN", "ad0.example"),
                 ("DOMAIN-SUFFIX", "new.test"), ("DOMAIN-SUFFIX", "notcovered.test")]
        result = customize(source, REVISION, extra)
        self.assertEqual(result.count("DOMAIN,ad0.example,REJECT"), 1)
        self.assertNotIn("DOMAIN,ad0.example,PROXY", result)
        self.assertNotIn("DOMAIN,sub.new.test,PROXY", result)
        self.assertNotIn("DOMAIN-SUFFIX,sub.covered.test,PROXY", result)
        self.assertIn("DOMAIN-SUFFIX,notcovered.test,PROXY", result)
        self.assertEqual(result.count("DOMAIN-SUFFIX,new.test,PROXY"), 1)
        self.assertLess(result.index("DOMAIN,blocked.new.test,REJECT"), result.index("DOMAIN-SUFFIX,new.test,PROXY"))
        self.assertLess(result.index("DOMAIN-SUFFIX,new.test,PROXY"), result.index("FINAL,direct"))
        self.assertEqual(result, customize(source, REVISION, reversed(extra)))

    def test_domain_includes_filtering_and_exact_match_semantics(self):
        sources = {"LICENSE": DOMAIN_LICENSE.read_text(),
                   "ai": "include:cdn\nai.test\nfull:auth.test\ntracking.test @telemetry\nads.test @ads\nregexp:^a.*$\n",
                   "cdn": "domain:assets.test # comment\n"}
        with patch("update.DOMAIN_LISTS", ("ai",)), patch("update.fetch", side_effect=lambda url: sources[url.rsplit("/", 1)[-1]]):
            rules, provenance = load_domains(REVISION)
        self.assertEqual(rules, [("DOMAIN-SUFFIX", "assets.test"), ("DOMAIN-SUFFIX", "ai.test"), ("DOMAIN", "auth.test")])
        self.assertIn("2 ads/telemetry; 1 regex/keyword", "\n".join(provenance))
        self.assertIn("Copyright (c) 2018-2019 V2Ray", "\n".join(provenance))

    def test_rejects_bad_domain_sources(self):
        for source in ["include:ai", "include:../secrets", "include:cdn @cn", "ai.test\nunknown:evil.test",
                       "<html>error</html>", "", "domain:invalid_domain.test", "ai.test,DIRECT", "full:*.test"]:
            with self.subTest(source=source), patch("update.DOMAIN_LISTS", ("ai",)), patch("update.fetch", side_effect=lambda url: DOMAIN_LICENSE.read_text() if url.endswith("/LICENSE") else source):
                with self.assertRaises(ValueError):
                    load_domains(REVISION)
        with patch("update.fetch", return_value="license changed"), self.assertRaises(ValueError):
            load_domains(REVISION)

    def test_failed_refresh_preserves_previous_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "profile.conf"
            output.write_text(customize(BASE, REVISION))
            original = output.read_bytes()
            with patch("update.OUTPUT", output), patch("update.current_revision", return_value=REVISION), patch("update.fetch", return_value=BASE):
                with patch("update.load_domains", side_effect=OSError("download failed")), self.assertRaises(OSError):
                    refresh()
                self.assertEqual(output.read_bytes(), original)
                truncated = BASE.replace("FINAL,direct", "FINAL,PROXY")
                with patch("update.load_domains", return_value=([], [])), patch("update.fetch", return_value=truncated), self.assertRaises(ValueError):
                    refresh()
                self.assertEqual(output.read_bytes(), original)
                expanded = BASE.replace("FINAL,direct", "\n".join(f"DOMAIN,new{i}.test,REJECT" for i in range(500)) + "\nFINAL,direct")
                with patch("update.load_domains", return_value=([], [])), patch("update.fetch", return_value=expanded), self.assertRaises(ValueError):
                    refresh()
                self.assertEqual(output.read_bytes(), original)
                with patch("update.load_domains", return_value=([("DOMAIN-SUFFIX", "ai.test")], [])):
                    refresh()
                self.assertIn("DOMAIN-SUFFIX,ai.test,PROXY", output.read_text())
                self.assertFalse(output.with_suffix(".tmp").exists())


if __name__ == "__main__":
    unittest.main()
