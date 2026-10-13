package com.vcfcf.adapters.compliance;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 90: the overrides file (the factory's
 * knowledge/designs/sdk-adapters/compliance-overrides-file.md). Parser,
 * Override value checks per value_type and comparison mode, resolution
 * against the REAL bundled profiles, the store's last-good discipline, Skip
 * routing to the stale-key path, and Profile pin precedence over Auto. Run
 * from the repo root.
 */
public final class OverridesTest {

	static final String LOCKOUT = "esx.account-lockout-max-attempts";

	public static void main(String[] args) throws Exception {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		parseEntryTypes();
		parseRejections();
		parseRefusesMalformedAndDoctype();
		template();
		valueChecks(all);
		resolveAgainstProfiles(all);
		overrideScoring(all);
		siteOverrideProps();
		skipRoutesToStaleKeyPath(all);
		pinPrecedence(all);
		store();
		System.out.println("OverridesTest: all assertions passed");
	}

	static ComplianceOverrides.Parsed parse(String body) throws Exception {
		return ComplianceOverrides.parse("<ComplianceOverrides>" + body
				+ "</ComplianceOverrides>");
	}

	// ----- parser -----------------------------------------------------------

	static void parseEntryTypes() throws Exception {
		ComplianceOverrides.Parsed p = parse(
				"<!-- a comment is ignored -->"
				+ "<Skip control=\"esx.a\"/>"
				+ "<Override control=\"esx.b\" expected=\" 5 \"/>"
				+ "<Profile version=\"SCG 9.0\"/>"
				+ "<Profile kind=\"VirtualMachine\" version=\"SCG 8.0\"/>");
		T.eq(0, p.rejected.size(), "no rejections: " + p.rejected);
		T.eq(4, p.entries.size(), "four entries");
		ComplianceOverrides.Entry skip = p.entries.get(0);
		T.eq(ComplianceOverrides.Type.SKIP, skip.type, "skip type");
		T.eq("esx.a", skip.control, "skip control");
		ComplianceOverrides.Entry ovr = p.entries.get(1);
		T.eq(ComplianceOverrides.Type.OVERRIDE, ovr.type, "override type");
		T.eq("5", ovr.expected, "override value trimmed");
		ComplianceOverrides.Entry inst = p.entries.get(2);
		T.eq("VMware_SCG_9.0", inst.profileName, "instance pin");
		T.eq(null, inst.kind, "instance pin has no kind");
		ComplianceOverrides.Entry vm = p.entries.get(3);
		T.eq("VMware_SCG_8.0", vm.profileName, "VM pin");
		T.eq(BenchmarkSelector.Kind.VM, vm.kind, "VM pin kind");
		T.eq("<Skip control=\"esx.a\"/>", skip.text, "entry text for logs");

		// Version and kind spellings.
		for (String v : new String[] {"SCG 9.1", "SCG_9.1", "VMware_SCG_9.1",
				"9.1", "scg 9.1"}) {
			T.eq("VMware_SCG_9.1", ComplianceOverrides.resolveVersion(v), v);
		}
		T.eq(null, ComplianceOverrides.resolveVersion("SCG 10.0"), "10.0");
		T.eq(null, ComplianceOverrides.resolveVersion("latest"), "latest");
		T.eq(BenchmarkSelector.Kind.HOST,
				ComplianceOverrides.resolveKind("HostSystem"), "HostSystem");
		T.eq(BenchmarkSelector.Kind.VCENTER,
				ComplianceOverrides.resolveKind("VMwareAdapter Instance"),
				"VCF Ops vCenter kind key");
		T.eq(BenchmarkSelector.Kind.VDS,
				ComplianceOverrides.resolveKind("VmwareDistributedVirtualSwitch"),
				"VCF Ops vDS kind key");
		T.eq(BenchmarkSelector.Kind.PORTGROUP,
				ComplianceOverrides.resolveKind("DistributedVirtualPortgroup"),
				"portgroup");
		T.eq(null, ComplianceOverrides.resolveKind("Datastore"), "Datastore");

		// An empty file (root only, or everything commented) parses to
		// nothing: a successful read with no overrides.
		T.check(parse("<!-- <Skip control=\"x\"/> -->").isEmpty(),
				"all commented out is empty");
	}

	static void parseRejections() throws Exception {
		ComplianceOverrides.Parsed p = parse(
				"<Disable control=\"esx.a\"/>"                    // unknown element
				+ "<Skip contorl=\"esx.a\"/>"                      // unknown attribute
				+ "<Skip/>"                                        // missing control
				+ "<Override control=\"esx.b\"/>"                  // missing expected
				+ "<Profile/>"                                     // missing version
				+ "<Profile version=\"SCG 10.0\"/>"                // unknown version
				+ "<Profile kind=\"Datastore\" version=\"SCG 9.0\"/>" // unknown kind
				+ "<Skip control=\"esx.c\"/><Skip control=\"esx.c\"/>"   // dup
				+ "<Override control=\"esx.d\" expected=\"1\"/>"
				+ "<Override control=\"esx.d\" expected=\"2\"/>"   // dup
				+ "<Profile version=\"SCG 9.0\"/><Profile version=\"9.1\"/>" // dup
				+ "<Profile kind=\"vm\" version=\"8.0\"/>"
				+ "<Profile kind=\"VirtualMachine\" version=\"9.0\"/>"); // dup
		T.eq(11, p.rejected.size(), "eleven rejected: " + p.rejected);
		T.eq(4, p.entries.size(), "four accepted (first of each duplicate)");
		T.check(p.rejected.get(0).contains("unknown entry type"),
				"unknown element message");
		T.check(p.rejected.get(1).contains("unknown attribute 'contorl'"),
				"unknown attribute message");
		T.check(p.rejected.get(5).contains("unknown version 'SCG 10.0'")
				&& p.rejected.get(5).contains("SCG 6.7, SCG 7.0, SCG 8.0, "
						+ "SCG 9.0, SCG 9.1"),
				"unknown version lists the valid names: " + p.rejected.get(5));
		T.check(p.rejected.get(6).contains("unknown kind 'Datastore'"),
				"unknown kind message");
		ComplianceOverrides.Entry firstOverride = null;
		for (ComplianceOverrides.Entry e : p.entries) {
			if (e.type == ComplianceOverrides.Type.OVERRIDE) firstOverride = e;
		}
		T.eq("1", firstOverride.expected, "first duplicate Override is kept");
	}

	static void parseRefusesMalformedAndDoctype() {
		mustFail("<ComplianceOverrides><Skip control=\"x\">",
				"unclosed element");
		mustFail("", "empty file");
		mustFail("<Overrides/>", "wrong root");
		// No DOCTYPE, so no external entity can be resolved.
		mustFail("<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM "
				+ "\"file:///etc/passwd\">]><ComplianceOverrides>"
				+ "<Skip control=\"&x;\"/></ComplianceOverrides>", "XXE");
	}

	static void mustFail(String xml, String what) {
		try {
			ComplianceOverrides.parse(xml);
		} catch (ComplianceOverrides.ParseException expected) {
			return;
		}
		throw new AssertionError(what + ": parse should have failed");
	}

	/** The shipped template parses, applies nothing, rejects nothing. */
	static void template() throws Exception {
		String body = new String(Files.readAllBytes(Paths.get("content",
				"files", "solutionconfig",
				"compliance_overrides_template.xml")), StandardCharsets.UTF_8);
		ComplianceOverrides.Parsed p = ComplianceOverrides.parse(body);
		T.check(p.isEmpty(), "template has every entry commented out: "
				+ p.entries.size() + " entries, " + p.rejected);
	}

	// ----- Override value checks -------------------------------------------

	static void valueChecks(Map<String, BenchmarkProfile> all) {
		BenchmarkProfile p90 = all.get("VMware_SCG_9.0");
		BenchmarkProfile.Control intAdv = find(p90, LOCKOUT);
		BenchmarkProfile.Control boolAdv = find(p90, "esx.ad-admin-group-autoadd");
		BenchmarkProfile.Control boolVim = find(p90, "esx.deactivate-shell");
		BenchmarkProfile.Control strVim = find(p90, "esx.lockdown-mode");
		BenchmarkProfile.Control strAdvVm = find(p90, "vm.deactivate-console-copy");
		T.eq("integer", intAdv.valueType, "fixture: integer advanced setting");
		T.eq("boolean", boolAdv.valueType, "fixture: boolean advanced setting");
		T.eq("boolean", boolVim.valueType, "fixture: boolean vim property");
		T.eq("string", strVim.valueType, "fixture: string vim property");

		// integer
		ok(intAdv, "3");
		ok(intAdv, "-1");
		bad(intAdv, "three");
		bad(intAdv, "3.5");
		bad(intAdv, "");
		bad(intAdv, "N/A");
		ok(intAdv, "3 or Undefined");       // advanced setting
		bad(intAdv, "x or Undefined");
		ok(intAdv, "Not Present");
		ok(intAdv, "not:0");
		bad(intAdv, "not:zero");
		ok(intAdv, "(non-empty)");
		bad(intAdv, "vmx-19 or higher");    // string controls only
		// boolean
		ok(boolAdv, "true");
		ok(boolAdv, "FALSE");
		ok(boolAdv, "1");                   // advanced setting accepts 1/0
		bad(boolAdv, "yes");
		ok(boolAdv, "TRUE or Undefined");
		ok(boolVim, "false");
		bad(boolVim, "1");                  // not an advanced setting
		bad(boolVim, "Reject");
		bad(boolVim, "false or Undefined"); // advanced settings only
		bad(boolVim, "Not Present");
		// string
		ok(strVim, "lockdownStrict");
		ok(strVim, "not:lockdownDisabled");
		ok(strVim, "vmx-21 or higher");
		bad(strVim, "n/a");
		ok(strAdvVm, "FALSE or Undefined");
	}

	static void ok(BenchmarkProfile.Control c, String v) {
		String why = ComplianceOverrides.checkValue(c, v);
		T.check(why == null, c.controlId + " should accept '" + v + "': "
				+ why);
	}

	static void bad(BenchmarkProfile.Control c, String v) {
		T.check(ComplianceOverrides.checkValue(c, v) != null,
				c.controlId + " should reject '" + v + "'");
	}

	// ----- resolve ---------------------------------------------------------

	static void resolveAgainstProfiles(Map<String, BenchmarkProfile> all)
			throws Exception {
		ComplianceOverrides.Parsed p = parse(
				"<Skip control=\"esx.account-lockout-duration\"/>"
				+ "<Override control=\"" + LOCKOUT + "\" expected=\"3\"/>"
				+ "<Override control=\"esx.ad-admin-group-autoadd\" "
				+ "expected=\"maybe\"/>"                     // bad value
				+ "<Skip control=\"esx.no-such-control\"/>"  // unknown id
				+ "<Skip control=\"esx.hardware-boot\"/>"     // never scored
				+ "<Override control=\"esx.account-lockout-duration\" "
				+ "expected=\"600\"/>"                        // also skipped
				+ "<Disable/>");                              // parse-time
		ComplianceOverrides.Resolved r =
				ComplianceOverrides.resolve(p, all.values());
		T.eq(new TreeSet<>(Arrays.asList("esx.account-lockout-duration")),
				r.skipped, "one skip applied");
		T.eq(Collections.singletonMap(LOCKOUT, "3"), r.overridden,
				"one override applied");
		T.eq(5, r.rejected.size(), "five rejected: " + r.rejected);
		T.check(r.rejected.get(0).contains("unknown entry type"),
				"parse-time rejections come first");
		String all5 = String.join("\n", r.rejected);
		T.check(all5.contains("'maybe' is not true or false"),
				"bad value named");
		T.check(all5.contains("the guide's value is kept"),
				"bad value keeps the SCG value");
		T.check(all5.contains("unknown control id"), "unknown id named");
		T.check(all5.contains("does not check this control automatically"),
				"never-scored control named");
		T.check(all5.contains("also skipped"), "Skip wins over Override");
		T.eq(2, r.applied.size(), "two applied: " + r.applied);

		// The rejected Override leaves the SCG value in every profile.
		Map<String, BenchmarkProfile> eff = r.adjust(all);
		for (BenchmarkProfile prof : eff.values()) {
			BenchmarkProfile.Control orig = find(all.get(prof.name),
					"esx.ad-admin-group-autoadd");
			BenchmarkProfile.Control now = find(prof,
					"esx.ad-admin-group-autoadd");
			if (orig == null) continue;
			T.eq(orig.expectedValue, now.expectedValue,
					prof.name + " keeps the SCG value for a rejected Override");
			T.check(!now.siteOverride, prof.name + " not marked");
			// Skip removes the control from every profile.
			T.eq(null, find(prof, "esx.account-lockout-duration"),
					prof.name + " skipped control removed");
			BenchmarkProfile.Control lock = find(prof, LOCKOUT);
			if (lock != null) {
				T.eq("3", lock.expectedValue, prof.name + " override applied");
				T.check(lock.siteOverride, prof.name + " override marked");
				T.check(prof.siteOverriddenIds().contains(LOCKOUT),
						prof.name + " siteOverriddenIds");
			}
		}
		// Nothing to change: the same map comes back.
		ComplianceOverrides.Resolved pinsOnly = ComplianceOverrides.resolve(
				parse("<Profile version=\"SCG 9.0\"/>"), all.values());
		T.check(pinsOnly.adjust(all) == all, "pins only: profiles untouched");
		T.check(ComplianceOverrides.Resolved.EMPTY.adjust(all) == all,
				"empty: profiles untouched");
		T.check(ComplianceOverrides.resolve(null, all.values())
				== ComplianceOverrides.Resolved.EMPTY, "null parse is empty");
	}

	/** An overridden control is scored against the site value, both ways. */
	static void overrideScoring(Map<String, BenchmarkProfile> all)
			throws Exception {
		ComplianceOverrides.Resolved r = ComplianceOverrides.resolve(parse(
				"<Override control=\"" + LOCKOUT + "\" expected=\"3\"/>"),
				all.values());
		BenchmarkProfile p = r.adjust(all.get("VMware_SCG_9.0"));
		List<BenchmarkProfile.Control> one =
				Collections.singletonList(find(p, LOCKOUT));
		String param = find(p, LOCKOUT).parameter;
		ControlEvaluator.ComplianceResult atGuide = ControlEvaluator
				.evaluateControls(one, Collections.singletonMap(param, "5"), "h");
		T.eq(1, atGuide.failCount, "guide value 5 fails a site value of 3");
		ControlEvaluator.ComplianceResult atSite = ControlEvaluator
				.evaluateControls(one, Collections.singletonMap(param, "3"), "h");
		T.eq(1, atSite.passCount, "3 passes a site value of 3");
		// Unreadable is still never a pass under an override.
		ControlEvaluator.ComplianceResult unread = ControlEvaluator
				.evaluateControlsUnreadable(one, "h");
		T.eq(0, unread.passCount, "unreadable is not a pass");
		T.eq(1, unread.unreadableCount, "unreadable counted");
	}

	static void siteOverrideProps() {
		ControlEvaluator.ComplianceResult cr = new ControlEvaluator
				.ComplianceResult("h", 0, 1, 1, 1, 0.0, Arrays.asList(
						new ControlEvaluator.ControlResult(LOCKOUT, "5", "3",
								false, "d"),
						new ControlEvaluator.ControlResult("esx.other",
								"(unreadable)", "3", false, "d", true),
						new ControlEvaluator.ControlResult("esx.plain", "1",
								"1", true, "d")));
		Set<String> site = new TreeSet<>(Arrays.asList(LOCKOUT, "esx.other"));
		Map<String, String> props = ComplianceDecisions.complianceProps(cr,
				"VMware_SCG_9.0", site);
		String k = ComplianceDecisions.K;
		T.eq("5, expected 3 (site override)", props.get(k + LOCKOUT + "|Actual"),
				"actual carries the site value");
		T.eq("3 (site override)", props.get(k + LOCKOUT + "|Expected"),
				"expected marked");
		T.eq("(unreadable)", props.get(k + "esx.other|Actual"),
				"unreadable actual untouched");
		T.eq("3 (site override)", props.get(k + "esx.other|Expected"),
				"unreadable expected still marked");
		T.eq("1", props.get(k + "esx.plain|Actual"), "plain control untouched");
		T.eq("1", props.get(k + "esx.plain|Expected"), "plain expected");
		T.eq(props, ComplianceDecisions.complianceProps(cr, "VMware_SCG_9.0",
				site), "deterministic");
		// The two-arg form is unchanged.
		T.eq("5", ComplianceDecisions.complianceProps(cr, "x")
				.get(k + LOCKOUT + "|Actual"), "no overrides: plain actual");
	}

	/**
	 * A skipped control goes through the stale-key cleanup: any lingering 0
	 * OR 1 is set to -1 (so an open alert clears and a stale pass stops
	 * showing), with the "(skipped by override file <name>)" actual.
	 */
	static void skipRoutesToStaleKeyPath(Map<String, BenchmarkProfile> all)
			throws Exception {
		String skipId = "esx.account-lockout-duration";
		ComplianceOverrides.Resolved r = ComplianceOverrides.resolve(parse(
				"<Skip control=\"" + skipId + "\"/>"), all.values());
		BenchmarkProfile current = r.adjust(all.get("VMware_SCG_9.0"));
		Set<String> pushed = new TreeSet<>();
		for (BenchmarkProfile.Control c : current.hostControls()) {
			if (BenchmarkSelector.evaluatedFor(BenchmarkSelector.Kind.HOST, c)) {
				pushed.add(c.controlId);
			}
		}
		T.check(!pushed.contains(skipId), "skipped control is not pushed");

		ComplianceDecisions.CleanupPlan without = ComplianceDecisions
				.cleanupPlan(BenchmarkSelector.Kind.HOST, current, pushed,
						all.values());
		T.check(without.zeroOnly.contains(skipId),
				"fixture: without the skip set it would retire a 0 only");
		ComplianceDecisions.CleanupPlan plan = ComplianceDecisions.cleanupPlan(
				BenchmarkSelector.Kind.HOST, current, pushed, all.values(),
				r.skipped);
		T.check(plan.zeroOrOne.contains(skipId), "skip retires a 0 or a 1");
		T.check(!plan.zeroOnly.contains(skipId), "and is not zero-only");

		Map<String, Double> latest = new HashMap<>();
		latest.put(skipId, 1.0);   // a stale pass
		T.eq(new TreeSet<>(Arrays.asList(skipId)),
				ComplianceDecisions.staleControls(plan, latest),
				"a stale 1 on a skipped control is retired");
		latest.put(skipId, 0.0);   // an open alert
		T.eq(new TreeSet<>(Arrays.asList(skipId)),
				ComplianceDecisions.staleControls(plan, latest),
				"a stale 0 on a skipped control is retired");
		latest.put(skipId, -1.0);
		T.check(ComplianceDecisions.staleControls(plan, latest).isEmpty(),
				"an already not-evaluated key is left alone");
		T.check(ComplianceDecisions.staleControls(plan,
				new HashMap<String, Double>()).isEmpty(),
				"a key the object never had is never created");

		Map<String, String> props = ComplianceDecisions.orphanProps(
				new TreeSet<>(Arrays.asList(skipId, "esx.other")),
				"VMware_SCG_9.0", r.skipped, "site-a");
		T.eq("(skipped by override file site-a)",
				props.get(ComplianceDecisions.K + skipId + "|Actual"),
				"skipped actual text");
		T.eq("(not in applied benchmark: VMware_SCG_9.0)",
				props.get(ComplianceDecisions.K + "esx.other|Actual"),
				"other stale keys keep their text");
		T.eq(-1.0, ComplianceDecisions.orphanStats(
				new TreeSet<>(Arrays.asList(skipId))).get(
						ComplianceDecisions.compliantKey(skipId)),
				"Compliant -1 (not evaluated)");
	}

	/** Per-kind pin beats the instance pin, which beats Auto (by version). */
	static void pinPrecedence(Map<String, BenchmarkProfile> all)
			throws Exception {
		BenchmarkSelector auto = BenchmarkSelector.auto(all);
		BenchmarkSelector.Kind HOST = BenchmarkSelector.Kind.HOST;
		BenchmarkSelector.Kind VM = BenchmarkSelector.Kind.VM;
		BenchmarkSelector.Kind VC = BenchmarkSelector.Kind.VCENTER;

		ComplianceOverrides.Resolved vmOnly = ComplianceOverrides.resolve(parse(
				"<Profile kind=\"VirtualMachine\" version=\"SCG 8.0\"/>"),
				all.values());
		BenchmarkSelector s1 = auto.withPins(vmOnly.pins(all));
		T.check(s1.isAuto(), "pinned selector still reads versions");
		T.eq("VMware_SCG_8.0", s1.select(VM, "9.0.0").profileName,
				"VM pinned to 8.0 on a 9.0 host");
		T.eq("VMware_SCG_8.0", s1.select(VM, null).profileName,
				"a pinned kind needs no version");
		T.eq("VMware_SCG_9.0", s1.select(HOST, "9.0.0").profileName,
				"host still Auto");
		T.check(s1.select(HOST, "10.0.0").noBenchmark(),
				"host on an unmapped version is still no benchmark");

		ComplianceOverrides.Resolved both = ComplianceOverrides.resolve(parse(
				"<Profile version=\"SCG 9.1\"/>"
				+ "<Profile kind=\"vm\" version=\"SCG 8.0\"/>"), all.values());
		T.eq("VMware_SCG_9.1", both.pinFor(HOST), "instance pin for hosts");
		T.eq("VMware_SCG_8.0", both.pinFor(VM), "kind pin wins for VMs");
		BenchmarkSelector s2 = auto.withPins(both.pins(all));
		T.eq("VMware_SCG_9.1", s2.select(HOST, "8.0.3").profileName,
				"instance pin beats Auto");
		T.eq("VMware_SCG_9.1", s2.select(VC, "7.0.3").profileName,
				"instance pin covers the vCenter kind");
		T.eq("VMware_SCG_8.0", s2.select(VM, "9.1.0").profileName,
				"kind pin beats the instance pin");
		T.eq("SCG_8.0", s2.select(VM, "9.1.0").bucket, "pinned bucket");

		// A pin replaces a fixed choice too.
		BenchmarkSelector fixed = BenchmarkSelector.fixed(
				all.get("VMware_SCG_7.0")).withPins(vmOnly.pins(all));
		T.eq("VMware_SCG_8.0", fixed.select(VM, null).profileName,
				"pin beats the fixed profile");
		T.eq("VMware_SCG_7.0", fixed.select(HOST, null).profileName,
				"unpinned kinds keep the fixed profile");

		// Pins pick up the cycle's adjusted profiles (skips and overrides
		// apply under a pin too).
		ComplianceOverrides.Resolved withSkip = ComplianceOverrides.resolve(
				parse("<Profile version=\"SCG 9.0\"/><Skip control=\""
						+ LOCKOUT + "\"/>"), all.values());
		BenchmarkProfile pinned = withSkip.pins(withSkip.adjust(all)).get(HOST);
		T.eq(null, find(pinned, LOCKOUT), "skip applies under a pin");

		// No pins: the selector is unchanged.
		T.check(auto.withPins(Collections.<BenchmarkSelector.Kind,
				BenchmarkProfile>emptyMap()) == auto, "no pins, same selector");
	}

	// ----- store -----------------------------------------------------------

	static final class FakeFetcher implements OverridesStore.Fetcher {
		String body;
		Exception fail;
		int calls;
		String lastPath;

		@Override
		public String get(String path) throws Exception {
			calls++;
			lastPath = path;
			if (fail != null) throw fail;
			return body;
		}
	}

	static void store() {
		ZoneId zone = ZoneId.of("America/Chicago");
		Instant t1 = Instant.parse("2026-10-13T19:05:00Z");
		Instant t2 = Instant.parse("2026-10-13T19:10:00Z");
		OverridesStore st = new OverridesStore();
		FakeFetcher f = new FakeFetcher();

		// No name: no fetch, status none.
		OverridesStore.Snapshot s = st.refresh("  ", f, t1);
		T.eq(OverridesStore.Status.NONE, s.status, "none");
		T.eq(0, f.calls, "no fetch without a name");
		T.eq("none", s.statusText(0, zone), "none text");
		T.check(!s.notLoaded(), "none is not 'not loaded'");
		T.check(s.parsed == null, "no overrides");

		// Good file. The name is normalised, the path is the store path.
		f.body = "<ComplianceOverrides><Skip control=\"a\"/></ComplianceOverrides>";
		s = st.refresh(" site-a.xml ", f, t1);
		T.eq(OverridesStore.Status.OK, s.status, "ok");
		T.eq("site-a", s.fileName, ".xml stripped");
		T.eq("/api/configurations/files?path=SolutionConfig/site-a.xml",
				f.lastPath, "store path");
		T.eq("OK", s.statusText(0, zone), "OK text");
		T.eq("2 rejected", s.statusText(2, zone), "rejected text");
		T.eq(1, s.parsed.entries.size(), "parsed");

		// Malformed: previous parse kept, status says so, alert flag on.
		f.body = "<ComplianceOverrides><Skip control=\"b\">";
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.Status.PARSE_FAILED, s.status, "parse failed");
		T.eq("a", s.parsed.entries.get(0).control, "previous parse kept");
		T.eq("parse failed, last good from 2026-10-13 14:05 CDT",
				s.statusText(0, zone), "parse failed text, local time");
		T.check(s.notLoaded(), "parse failure raises the alert");

		// Transient fetch failure: previous parse kept, no alert.
		f.fail = new java.io.IOException(
				"Suite API GET https://localhost/suite-api/x HTTP 503");
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.Status.FETCH_FAILED, s.status, "fetch failed");
		T.eq("a", s.parsed.entries.get(0).control, "kept on fetch failure");
		T.eq("fetch failed, last good from 2026-10-13 14:05 CDT",
				s.statusText(0, zone), "fetch failed text");
		T.check(!s.notLoaded(), "a transient failure is not 'not loaded'");

		// Interrupted: the thread's interrupt flag is restored.
		f.fail = new InterruptedException("stop");
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.Status.FETCH_FAILED, s.status, "interrupted");
		T.check(Thread.interrupted(), "interrupt flag restored (and cleared)");

		// No Suite API channel: kept.
		s = st.refresh("site-a", null, t2);
		T.eq(OverridesStore.Status.FETCH_FAILED, s.status, "no channel");
		T.check(s.parsed != null, "kept without a channel");

		// Absent (HTTP 400 / 1501): no overrides, last good dropped.
		f.fail = new java.io.IOException(
				"Suite API GET https://localhost/suite-api/x HTTP 400");
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.Status.ABSENT, s.status, "absent");
		T.check(s.parsed == null, "absent runs with no overrides");
		T.eq("absent", s.statusText(0, zone), "absent text");
		T.check(s.notLoaded(), "absent raises the alert");
		f.fail = new java.io.IOException("x HTTP 503");
		s = st.refresh("site-a", f, t2);
		T.check(s.parsed == null, "the dropped copy does not come back");
		T.eq("fetch failed", s.statusText(0, zone), "fetch failed, no copy");

		// A new name never inherits another file's parse.
		f.fail = null;
		f.body = "<ComplianceOverrides><Skip control=\"a\"/></ComplianceOverrides>";
		st.refresh("site-a", f, t1);
		f.body = "not xml";
		s = st.refresh("site-b", f, t2);
		T.eq(OverridesStore.Status.PARSE_FAILED, s.status, "b parse failed");
		T.check(s.parsed == null, "site-a's parse not applied to site-b");
		T.eq("parse failed, no previous copy", s.statusText(0, zone),
				"no previous copy text");

		// A path in the name is refused without a fetch.
		int before = f.calls;
		s = st.refresh("SolutionConfig/site-a", f, t2);
		T.eq(OverridesStore.Status.ABSENT, s.status, "path refused");
		T.eq(before, f.calls, "no fetch for a path");

		// Status keys: prefix and values.
		Map<String, String> wp = ComplianceDecisions.overridesProps("",
				"site-a", "OK");
		T.eq("site-a", wp.get("Summary|overrides_file"), "world file key");
		T.eq("OK", wp.get("Summary|overrides_status"), "world status key");
		Map<String, Double> vs = ComplianceDecisions.overridesStats(
				ComplianceDecisions.K, 2, 1, true);
		Map<String, Double> want = new LinkedHashMap<>();
		want.put("VCF-CF Compliance|Summary|overrides_skipped", 2.0);
		want.put("VCF-CF Compliance|Summary|overrides_overridden", 1.0);
		want.put("VCF-CF Compliance|Summary|overrides_not_loaded", 1.0);
		T.eq(want, vs, "vCenter stat keys");
	}

	static BenchmarkProfile.Control find(BenchmarkProfile p, String id) {
		if (p == null) return null;
		for (BenchmarkProfile.Control c : p.controls) {
			if (c.controlId.equals(id)) return c;
		}
		return null;
	}
}
