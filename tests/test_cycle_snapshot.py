"""Guard: review N13, W12, W13 and N16 (build 95). One holder per configuration.

configureAdapter builds one Configured holder (account, clients, the
state a cycle hands to the next) and publishes it with one write to the
`configured` field; collectWorld copies that reference once, at the
start of the cycle, into `cycle`, and the cycle code works only through
the copy. So an instance edit during a cycle never switches that cycle
to the new vCenter part-way (where a moRef such as host-12 could name a
different object), and what the old cycle records stays in the old
holder. The adapter needs the VCF Ops SDK, which the plain-main Java
tests do not load, so this pins the source shape (SnapshotHolderTest
runs the holder itself).

Review W13: every check runs on the code with comments and string
literals removed, and pins where a name may appear, not only how often
it is assigned, so a read that bypasses the copy fails (this.config.x,
a bare config.x, configured.<client> after the copy). Standard library
only. Run from the repo root:
    python3 tests/test_cycle_snapshot.py
"""

import re
import unittest
from pathlib import Path

PATH = (Path(__file__).resolve().parents[1] / "src/com/vcfcf/adapters/"
        "compliance/ComplianceAdapter.java")


def strip(src):
    """Java source without comments; string and char literals emptied."""
    out = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                raise ValueError("unterminated comment")
            out.append(" ")
            i = j + 2
        elif src[i] in "\"'":
            q = src[i]
            j = i + 1
            while src[j] != q:
                j += 2 if src[j] == "\\" else 1
            out.append(q + q)
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


MEMBER = re.compile(r"^\t(?:@Override|private |protected |public )", re.M)


def span(code, signature):
    """(start, end) of a member, from its signature to the next member."""
    i = code.index(signature)
    m = MEMBER.search(code, i + len(signature))
    return i, (m.start() if m else len(code))


# An assignment operator (plain or compound), not a comparison.
ASSIGN = r"(?:=(?!=)|[-+*/%&|^]=|<<=|>>>?=)"

# A class-level declaration (one tab in, any or no access modifier) of a
# non-static field: a type, then the name, then `=` or `;`.
FIELD = re.compile(r"^\t(?![^;=(){}]*\bstatic\b)[A-Za-z][^;=(){}]*?\s"
                   r"(\w+)\s*[=;]", re.M)


def fields(code):
    """Names of the instance (non-static) fields declared in the class."""
    return set(FIELD.findall(code))


def check(src):
    """Problems with the snapshot shape of src; empty when it holds."""
    code = strip(src)
    bad = []

    # The holder field and the per-cycle copy are declared once each.
    decl = re.search(r"private volatile Configured<SuiteApiStitcher, "
                     r"ComplianceStitcher>\s+configured;", code)
    if not decl:
        return ["no `configured` holder field declaration"]
    if not re.search(r"private volatile Configured<SuiteApiStitcher, "
                     r"ComplianceStitcher>\s+cycle;", code):
        bad.append("no `cycle` copy field declaration")

    known = fields(code)
    if not {"configured", "cycle", "cycleConfDir"} <= known:
        bad.append("field scan missed known fields: %s" % sorted(known))
    conf = span(code, "protected void configureAdapter(")
    world = span(code, "private void collectWorld(")
    head = (world[0], code.index("try {", world[0]))
    discard = span(code, "public void onDiscard()")

    def inside(pos, s):
        return s[0] <= pos < s[1]

    # `configured` only in its declaration, configureAdapter, the copy
    # block and onDiscard.
    for m in re.finditer(r"\bconfigured\b", code):
        p = m.start()
        if not (decl.start() <= p < decl.end() or inside(p, conf)
                or inside(p, head) or inside(p, discard)):
            line = code.count("\n", 0, p) + 1
            bad.append("`configured` outside declaration, configure, copy "
                       "block and discard (stripped line %d)" % line)

    # configure publishes the holder with exactly one write and assigns
    # no other instance field (declared here or inherited, such as the
    # platform's this.config), so no account or client can live outside
    # the holder (review N16).
    body = code[conf[0]:conf[1]]
    writes = re.findall(r"\bthis\.configured\s*=(?!=)", body)
    if len(writes) != 1:
        bad.append("configure writes `configured` %d times, not once"
                   % len(writes))
    for name in sorted(set(re.findall(r"\bthis\.(\w+)\s*" + ASSIGN, body))
                       - {"configured"}):
        bad.append("configure assigns this.%s" % name)
    for name in sorted(fields(code) - {"configured"}):
        if re.search(r"[\w>\]]\s+%s\s*[=;:,)]" % name, body):
            continue  # a local of the same name shadows the field
        if re.search(r"(?<![\w.])%s\s*%s" % (name, ASSIGN), body) or \
                re.search(r"(?:\+\+|--)\s*%s\b|(?<![\w.])%s\s*(?:\+\+|--)"
                          % (name, name), body):
            bad.append("configure assigns field `%s`" % name)
    if re.search(r"(?<![\w.])(?:this\.)?config\s*=(?!=)", code):
        bad.append("this.config is assigned")
    if re.search(r"(?<![\w.])(?:this\.)?cycle\s*=(?!=)", body):
        bad.append("configure writes `cycle`")

    # The copy block reads the holder once and copies it.
    h = code[head[0]:head[1]]
    if len(re.findall(r"\bconfigured\b", h)) != 1 or \
            "c = configured;" not in h or "cycle = c;" not in h:
        bad.append("copy block is not `c = configured; ... cycle = c;`")
    cycle_writes = re.findall(r"(?<![\w.])(?:this\.)?cycle\s*=(?!=)", code)
    if len(cycle_writes) != 1:
        bad.append("`cycle` is written %d times, not once (the copy block)"
                   % len(cycle_writes))

    # From collectWorld through onDiscard: no platform config at all.
    region = code[world[0]:discard[1]]
    if re.search(r"\bthis\.config\b", region):
        bad.append("this.config read in the cycle or discard")
    if re.search(r"(?<![\w.])config\s*\.", region):
        bad.append("bare config. read in the cycle or discard")

    # onDiscard releases the holder's clients.
    if "releaseClients(c.vsphere, c.suite)" not in code[discard[0]:discard[1]]:
        bad.append("onDiscard does not release the holder's clients")
    return bad


class CycleSnapshotTest(unittest.TestCase):

    def test_adapter_has_the_snapshot_shape(self):
        self.assertEqual(check(PATH.read_text(encoding="utf-8")), [])

    def test_bypasses_fail(self):
        """The review's bypasses, applied to a copy, each fail the check."""
        src = PATH.read_text(encoding="utf-8")
        mutations = {
            "M1 this.config in collectVCenter": (
                "String resourceName = cycle.account.vcenterHost;",
                "String resourceName = this.config.vcenterHost;"),
            "M2 configured.stitcher in collectVCenter": (
                "ComplianceStitcher.HostEntry he = "
                "cycle.stitcher.matchVCenterAdapterInstance(",
                "ComplianceStitcher.HostEntry he = "
                "configured.stitcher.matchVCenterAdapterInstance("),
            "M3 bare config. in skipInForce": (
                "cycleUnadjusted.get(d.profileName), r.skipped,\n"
                "\t\t\t\tcycle.account.overridesFile);",
                "cycleUnadjusted.get(d.profileName), r.skipped,\n"
                "\t\t\t\tconfig.overridesFile);"),
            "M4 configured.vsphere.ensureConnected": (
                "cycle.vsphere.ensureConnected();",
                "configured.vsphere.ensureConnected();"),
            "M5 VAMI client from this.config": (
                "cycle.account.baseUrl(), cycle.account.username,",
                "this.config.baseUrl(), cycle.account.username,"),
            "M6 configure also writes this.config": (
                "ComplianceConfig account = new ComplianceConfig(",
                "ComplianceConfig account = this.config = "
                "new ComplianceConfig("),
            "M7 configured.loader after the copy": (
                "cycle.loader.loadAll(confDir);",
                "configured.loader.loadAll(confDir);"),
            "M8 second copy mid-cycle": (
                "cycle.vsphere.beginCycle();",
                "cycle = configured; cycle.vsphere.beginCycle();"),
            "M9 configure publishes twice": (
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;",
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured; this.configured = null;"),
            "M10 configure assigns another field via this.": (
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;",
                "this.cycleConfDir = account.vcenterHost;\n\t\t"
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;"),
            "M11 configure assigns a bare field": (
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;",
                "bulkShadow = true;\n\t\t"
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;"),
            "M12 configure assigns a new package-private field": (
                "\t@Override\n"
                "\tprotected void configureAdapter(ResourceStatus status,\n"
                "\t\t\tResourceConfig resourceConfig) {\n",
                "\tString lastHost;\n\n\t@Override\n"
                "\tprotected void configureAdapter(ResourceStatus status,\n"
                "\t\t\tResourceConfig resourceConfig) {\n"
                "\t\tlastHost = null;\n"),
            "M13 configure compound-assigns a bare field": (
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;",
                "cycleSkippedInForce += 1;\n\t\t"
                "Configured<SuiteApiStitcher, ComplianceStitcher> old = "
                "this.configured;"),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(name):
                self.assertEqual(src.count(old), 1, "anchor: " + name)
                self.assertNotEqual(
                    check(src.replace(old, new)), [], name + " passed")


if __name__ == "__main__":
    unittest.main(verbosity=1)
