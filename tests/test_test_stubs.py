"""Build 96 (issue #27): guards on the test-only stubs in tests/stubs.

- Every stub Java file carries the TEST-ONLY STUB header, except the
  verbatim SimpleJson copy, which must equal the factory's framework copy
  byte for byte when the factory tree is reachable (a clone under
  content/sdk-adapters/<name>/ in the factory). In CI the factory is not
  checked out: the comparison is skipped and says so.
- No adapter source under src/ uses a stub test hook, so nothing in the
  pak can depend on a member the real SDK or framework does not have.
Run from the repo root: python3 tests/test_test_stubs.py
"""
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUBS = ROOT / "tests" / "stubs"
SIMPLE_JSON = STUBS / "com/vcfcf/adapter/json/SimpleJson.java"
FACTORY_SIMPLE_JSON = (ROOT.parent.parent.parent / "src/vcfcf_managementpacks"
                       "/adapter_framework/src/com/vcfcf/adapter/json"
                       "/SimpleJson.java")
HOOKS = ("testConfDir", "testMonitoringIntervalSec", "testFields",
         "testIntervalSec", "testLog", "testAbort", "testFactory")


class StubGuards(unittest.TestCase):

    def test_header_on_every_stub(self):
        files = sorted(STUBS.rglob("*.java"))
        self.assertTrue(files, "no stub files found")
        for f in files:
            if f == SIMPLE_JSON:
                continue
            head = f.read_text(encoding="utf-8").splitlines()[0]
            self.assertTrue(head.startswith("// TEST-ONLY STUB"),
                            f"{f.relative_to(ROOT)} lacks the header")

    def test_simple_json_is_the_framework_copy(self):
        if not FACTORY_SIMPLE_JSON.is_file():
            print("SKIPPED: factory framework SimpleJson.java not found "
                  "beside this repo; the vendored copy was not compared")
            return
        self.assertEqual(FACTORY_SIMPLE_JSON.read_bytes(),
                         SIMPLE_JSON.read_bytes(),
                         "tests/stubs SimpleJson.java differs from the "
                         "framework copy: re-copy it and update the README")

    def test_src_uses_no_test_hook(self):
        for f in sorted((ROOT / "src").rglob("*.java")):
            text = f.read_text(encoding="utf-8")
            for hook in HOOKS:
                self.assertNotIn(hook, text,
                                 f"{f.relative_to(ROOT)} uses stub hook {hook}")


if __name__ == "__main__":
    os.chdir(ROOT)
    unittest.main()
