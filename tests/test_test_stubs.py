"""Build 96 (issue #27): guards on the test-only stubs in tests/stubs.

- Every stub Java file carries the TEST-ONLY STUB header, except the
  verbatim SimpleJson copy. Its sha256 must equal the pinned sha256 of the
  factory framework copy (review N4: this runs everywhere, CI included, so
  an edit to the vendored copy fails). When the factory tree is reachable
  (a clone under content/sdk-adapters/<name>/ in the factory), the copy is
  also compared byte for byte with it, which catches a framework change
  the pin has not followed.
- No adapter source under src/ uses a stub test hook, so nothing in the
  pak can depend on a member the real SDK or framework does not have.
Run from the repo root: python3 tests/test_test_stubs.py
"""
import hashlib
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUBS = ROOT / "tests" / "stubs"
SIMPLE_JSON = STUBS / "com/vcfcf/adapter/json/SimpleJson.java"
FACTORY_SIMPLE_JSON = (ROOT.parent.parent.parent / "src/vcfcf_managementpacks"
                       "/adapter_framework/src/com/vcfcf/adapter/json"
                       "/SimpleJson.java")
# sha256 of src/vcfcf_managementpacks/adapter_framework/src/com/vcfcf/adapter/
# json/SimpleJson.java at factory commit 6045435 (sdk-buildkit-v1.0.11).
FRAMEWORK_SIMPLE_JSON_SHA256 = (
    "501451fe843d426af70a96ac4d6ae8993b55d455b144b268f3c82211acfda2fe")
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

    def test_simple_json_matches_the_pinned_framework_sha256(self):
        self.assertEqual(FRAMEWORK_SIMPLE_JSON_SHA256,
                         hashlib.sha256(SIMPLE_JSON.read_bytes()).hexdigest(),
                         "tests/stubs SimpleJson.java is not the pinned "
                         "framework copy: re-copy it from the factory, or "
                         "update the pin and the README together")

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
