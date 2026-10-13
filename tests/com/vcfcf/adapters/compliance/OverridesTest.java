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
		overrideDropsOrUndefined(all);
		inForceCounts(all);
		siteOverrideProps();
		skipRoutesToStaleKeyPath(all);
		skipPushedEveryCycle(all);
		pinPrecedence(all);
		store();
		fetchFailureAlert();
		adapterWiringSourcePins();
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
				+ "<Profile kind=\"VirtualMachine\" version=\"SCG 8.0\"/>");
		T.eq(0, p.rejected.size(), "no rejections: " + p.rejected);
		T.eq(3, p.entries.size(), "three entries");
		ComplianceOverrides.Entry skip = p.entries.get(0);
		T.eq(ComplianceOverrides.Type.SKIP, skip.type, "skip type");
		T.eq("esx.a", skip.control, "skip control");
		ComplianceOverrides.Entry ovr = p.entries.get(1);
		T.eq(ComplianceOverrides.Type.OVERRIDE, ovr.type, "override type");
		T.eq("5", ovr.expected, "override value trimmed");
		ComplianceOverrides.Entry vm = p.entries.get(2);
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
				+ "<Profile kind=\"vm\"/>"                         // missing version
				+ "<Profile kind=\"vm\" version=\"SCG 10.0\"/>"    // unknown version
				+ "<Profile kind=\"Datastore\" version=\"SCG 9.0\"/>" // unknown kind
				+ "<Skip control=\"esx.c\"/><Skip control=\"esx.c\"/>"   // dup
				+ "<Override control=\"esx.d\" expected=\"1\"/>"
				+ "<Override control=\"esx.d\" expected=\"2\"/>"   // dup
				+ "<Profile version=\"SCG 9.0\"/>"                 // instance-wide
				+ "<Profile/>"                                     // instance-wide
				+ "<Profile kind=\"vm\" version=\"8.0\"/>"
				+ "<Profile kind=\"VirtualMachine\" version=\"9.0\"/>"); // dup
		T.eq(12, p.rejected.size(), "twelve rejected: " + p.rejected);
		T.eq(3, p.entries.size(), "three accepted (first of each duplicate)");
		T.check(p.rejected.get(4).contains("missing version"),
				"missing version message: " + p.rejected.get(4));
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
		// Build 92: a Profile without kind is rejected with the design's
		// wording; the instance setting owns the instance-wide choice.
		T.eq("<Profile version=\"SCG 9.0\"/>: instance-wide pin: use the "
				+ "Compliance Profile setting", p.rejected.get(9),
				"instance-wide pin rejected");
		T.eq("<Profile/>: instance-wide pin: use the Compliance Profile "
				+ "setting", p.rejected.get(10), "bare Profile rejected");
		for (ComplianceOverrides.Entry e : p.entries) {
			if (e.type == ComplianceOverrides.Type.PROFILE) {
				T.check(e.kind != null, "every accepted pin has a kind");
			}
		}
		// Rejected, it pins nothing and the rest of the file applies.
		ComplianceOverrides.Resolved inst = ComplianceOverrides.resolve(
				parse("<Profile version=\"SCG 9.0\"/><Skip control=\""
						+ LOCKOUT + "\"/>"),
				new BenchmarkLoader().loadAll(".").values());
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			T.eq(null, inst.pinFor(k), "no pin for " + k);
		}
		T.eq(1, inst.rejected.size(), "reported once: " + inst.rejected);
		T.check(inst.skipped.contains(LOCKOUT), "the Skip still applies");
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
		// build 90 (N6): explicit-empty forms on a text advanced setting
		BenchmarkProfile.Control strAdv = find(p90, "esx.log-level");
		BenchmarkProfile.Control dvf = find(p90, "esx.network-dvfilter");
		T.eq("string", strAdv.valueType, "fixture: string advanced setting");
		T.eq("advanced_setting", dvf.parameterKind, "fixture: dvfilter advanced");
		ok(strAdv, "info");
		bad(strAdv, "NULL");
		bad(strAdv, "null");
		bad(strAdv, "Null");
		bad(strAdv, "\" \"");               // quoted blank
		bad(strAdv, "   ");                  // whitespace only
		bad(strAdv, "\"\"");                 // guide value is not empty
		bad(strAdv, "not:null");
		ok(dvf, "\"\"");                     // guide value is ""
		bad(dvf, "NULL");
		bad(dvf, "\"  \"");
		ok(dvf, "10.0.0.1");
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
				parse("<Profile kind=\"HostSystem\" version=\"SCG 9.0\"/>"),
				all.values());
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

	/**
	 * Review of build 90, W1 (DEF-022): an Override that drops "or
	 * Undefined" from an advanced setting makes the rule stricter, so an
	 * object with the key unset now FAILS with Actual "(undefined)". Before
	 * the DEF-022 fix it vanished from the control (pass 0, fail 0, total 0)
	 * and its old pass was retired to -1: a stricter rule, a higher score.
	 */
	static void overrideDropsOrUndefined(Map<String, BenchmarkProfile> all)
			throws Exception {
		String id = "vm.deactivate-console-copy";
		BenchmarkProfile guide = all.get("VMware_SCG_9.0");
		T.check(ControlEvaluator.allowsUndefined(find(guide, id).expectedValue),
				"fixture: the guide's value allows undefined");
		ComplianceOverrides.Resolved r = ComplianceOverrides.resolve(parse(
				"<Override control=\"" + id + "\" expected=\"TRUE\"/>"),
				all.values());
		T.eq(Collections.singletonMap(id, "TRUE"), r.overridden,
				"the stricter Override is accepted");
		Map<String, String> unset = new HashMap<>();   // a successful read
		ControlEvaluator.ComplianceResult atGuide = ControlEvaluator
				.evaluateControls(Collections.singletonList(find(guide, id)),
						unset, "vm1");
		T.eq(1, atGuide.passCount, "unset passes the guide's TRUE or Undefined");
		BenchmarkProfile site = r.adjust(guide);
		ControlEvaluator.ComplianceResult atSite = ControlEvaluator
				.evaluateControls(Collections.singletonList(find(site, id)),
						unset, "vm1");
		T.eq(0, atSite.passCount, "unset is not a pass under the site TRUE");
		T.eq(1, atSite.failCount, "unset FAILS under the site TRUE");
		T.eq(1, atSite.totalCount, "and stays in the denominator");
		T.eq("(undefined)", atSite.controlResults.get(0).actual,
				"Actual (undefined)");
		Map<String, String> set = new HashMap<>();
		set.put(find(site, id).parameter, "TRUE");
		T.eq(1, ControlEvaluator.evaluateControls(Collections.singletonList(
				find(site, id)), set, "vm1").passCount, "set TRUE passes");
	}

	/**
	 * Review of build 90, N1: overrides_skipped and overrides_overridden
	 * count entries in force for the instance's own profiles (its mode's,
	 * or the pinned one for a pinned kind), not entries accepted against
	 * any bundled profile.
	 */
	static void inForceCounts(Map<String, BenchmarkProfile> all)
			throws Exception {
		String old67 = "esx.account-lockout";   // 6.7 / 7.0 / 8.0, not 9.0
		BenchmarkProfile p90 = all.get("VMware_SCG_9.0");
		T.eq(null, find(p90, old67), "fixture: not in 9.0");
		T.check(find(all.get("VMware_SCG_8.0"), old67) != null,
				"fixture: in 8.0");
		T.eq(null, find(all.get("VMware_SCG_8.0"), LOCKOUT),
				"fixture: 9.0's lockout id is not in 8.0");
		ComplianceOverrides.Resolved r = ComplianceOverrides.resolve(parse(
				"<Skip control=\"" + old67 + "\"/>"
				+ "<Override control=\"" + LOCKOUT + "\" expected=\"3\"/>"),
				all.values());
		T.eq(2, r.applied.size(), "both accepted against the bundled set");
		Map<BenchmarkSelector.Kind, BenchmarkProfile> noPins =
				Collections.emptyMap();

		// Fixed to SCG 9.0: the Skip changes nothing here.
		List<BenchmarkProfile> fixed90 = Collections.singletonList(p90);
		T.check(r.skippedIn(fixed90, noPins).isEmpty(),
				"a skip of a control 9.0 lacks is not in force on 9.0");
		T.eq(new TreeSet<>(Arrays.asList(LOCKOUT)),
				r.overriddenIn(fixed90, noPins), "the 9.0 override is");

		// Hosts pinned to 8.0: 8.0 governs host controls, so the 8.0 skip
		// is in force and the 9.0-only override is not.
		ComplianceOverrides.Resolved pinned = ComplianceOverrides.resolve(
				parse("<Profile kind=\"HostSystem\" version=\"SCG 8.0\"/>"
						+ "<Skip control=\"" + old67 + "\"/>"
						+ "<Override control=\"" + LOCKOUT
						+ "\" expected=\"3\"/>"), all.values());
		Map<BenchmarkSelector.Kind, BenchmarkProfile> pins = pinned.pins(all);
		T.eq(new TreeSet<>(Arrays.asList(old67)),
				pinned.skippedIn(fixed90, pins), "pinned 8.0 skip in force");
		T.check(pinned.overriddenIn(fixed90, pins).isEmpty(),
				"9.0 host override not in force under an 8.0 host pin");

		// Auto: every bundled profile is the instance's own.
		T.eq(1, r.skippedIn(all.values(), noPins).size(), "Auto: skip counts");
		T.eq(1, r.overriddenIn(all.values(), noPins).size(),
				"Auto: override counts");
		T.check(ComplianceOverrides.Resolved.EMPTY.skippedIn(all.values(),
				noPins).isEmpty(), "empty: nothing in force");
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

	/**
	 * Build 92 (adapter issue #41): a Skip in force is pushed -1 with the
	 * skip Actual text on EVERY cycle, not once, so the symptom on the key
	 * sees its cancel cycles and the open alert cancels. Build 91 routed it
	 * through the read-back cleanup only, which pushed -1 on the first cycle
	 * and nothing after (the key already read -1). Removing the Skip resumes
	 * scoring on the next cycle.
	 */
	static void skipPushedEveryCycle(Map<String, BenchmarkProfile> all)
			throws Exception {
		BenchmarkSelector.Kind HOST = BenchmarkSelector.Kind.HOST;
		String skipId = "esx.account-lockout-duration";
		String file = "compliance_overrides_wld01";
		String key = ComplianceDecisions.compliantKey(skipId);
		BenchmarkProfile guide = all.get("VMware_SCG_9.0");
		ComplianceOverrides.Resolved r = ComplianceOverrides.resolve(parse(
				"<Skip control=\"" + skipId + "\"/>"), all.values());
		BenchmarkProfile current = r.adjust(guide);
		Set<String> scored = new TreeSet<>();
		for (BenchmarkProfile.Control c : current.hostControls()) {
			if (BenchmarkSelector.evaluatedFor(HOST, c)) scored.add(c.controlId);
		}
		T.check(!scored.contains(skipId), "fixture: skipped control not scored");

		// What VCF Ops holds on the key before each cycle: the open alert's
		// 0 before the first, then whatever the pack pushed last.
		Double held = 0.0;
		for (int cycle = 1; cycle <= 3; cycle++) {
			ComplianceDecisions.SkipPush sp = ComplianceDecisions.skipPush(
					HOST, guide, r.skipped, file);
			T.eq(new TreeSet<>(Arrays.asList(skipId)), sp.ids,
					"cycle " + cycle + ": the skipped control is pushed");
			T.eq(-1.0, sp.stats.get(key), "cycle " + cycle + ": Compliant -1");
			T.eq("(skipped by override file " + file + ")",
					sp.props.get(ComplianceDecisions.K + skipId + "|Actual"),
					"cycle " + cycle + ": skip Actual text");
			// The cleanup sees the pushed key as live: no read-back, no
			// second push of the same key.
			Set<String> live = new TreeSet<>(scored);
			live.addAll(sp.ids);
			T.check(!ComplianceDecisions.cleanupPlan(HOST, current, live,
					all.values(), r.skipped).queryIds().contains(skipId),
					"cycle " + cycle + ": cleanup leaves the pushed key alone");
			// The build 91 path, for contrast: the read-back cleanup pushed
			// only while the key still read 0 or 1, so cycles 2 and 3 sent
			// nothing and the alert never saw its cancel cycles.
			ComplianceDecisions.CleanupPlan old = ComplianceDecisions
					.cleanupPlan(HOST, current, scored, all.values(), r.skipped);
			Map<String, Double> latest = new HashMap<>();
			latest.put(skipId, held);
			T.eq(cycle == 1, ComplianceDecisions.staleControls(old, latest)
					.contains(skipId), "cycle " + cycle
							+ ": build 91 pushed on the first cycle only");
			held = sp.stats.get(key);
		}

		// Not in force on this object: nothing pushed.
		String old67 = "esx.account-lockout";   // 6.7 / 7.0 / 8.0, not 9.0
		ComplianceOverrides.Resolved r67 = ComplianceOverrides.resolve(parse(
				"<Skip control=\"" + old67 + "\"/>"), all.values());
		T.check(ComplianceDecisions.skipPush(HOST, guide, r67.skipped, file)
				.isEmpty(), "a skip only another SCG version carries");
		T.eq(new TreeSet<>(Arrays.asList(old67)), ComplianceDecisions.skipPush(
				HOST, all.get("VMware_SCG_8.0"), r67.skipped, file).ids,
				"and it is in force on an 8.0 host");
		T.check(ComplianceDecisions.skipPush(BenchmarkSelector.Kind.VM, guide,
				r.skipped, file).isEmpty(), "a host control on a VM");
		T.check(ComplianceDecisions.skipPush(HOST, null, r.skipped, file)
				.isEmpty(), "no benchmark");

		// Cycle 4: the Skip is removed. Nothing is pushed as skipped, the
		// control is back in the benchmark, and a real read scores it.
		ComplianceOverrides.Resolved none = ComplianceOverrides.resolve(
				parse(""), all.values());
		T.check(ComplianceDecisions.skipPush(HOST, guide, none.skipped, file)
				.isEmpty(), "Skip removed: no -1 push");
		BenchmarkProfile back = none.adjust(guide);
		BenchmarkProfile.Control c = find(back, skipId);
		T.check(c != null && BenchmarkSelector.evaluatedFor(HOST, c),
				"Skip removed: the control is scored again");
		List<BenchmarkProfile.Control> one = Collections.singletonList(c);
		T.eq(1.0, ComplianceDecisions.complianceStats(ControlEvaluator
				.evaluateControls(one, Collections.singletonMap(c.parameter,
						c.expectedValue), "h")).get(key),
				"Skip removed: a compliant host pushes 1");
		T.eq(0.0, ComplianceDecisions.complianceStats(ControlEvaluator
				.evaluateControls(one, Collections.singletonMap(c.parameter,
						"1"), "h")).get(key),
				"Skip removed: a non-compliant host pushes 0");
	}

	/** A per-kind pin beats Auto (by version) and the fixed choice. */
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
				"<Profile kind=\"HostSystem\" version=\"SCG 9.1\"/>"
				+ "<Profile kind=\"vm\" version=\"SCG 8.0\"/>"), all.values());
		T.eq("VMware_SCG_9.1", both.pinFor(HOST), "host pin");
		T.eq("VMware_SCG_8.0", both.pinFor(VM), "VM pin");
		T.eq(null, both.pinFor(VC), "an unpinned kind has no pin");
		BenchmarkSelector s2 = auto.withPins(both.pins(all));
		T.eq("VMware_SCG_9.1", s2.select(HOST, "8.0.3").profileName,
				"host pin beats Auto");
		T.eq("VMware_SCG_7.0", s2.select(VC, "7.0.3").profileName,
				"the vCenter kind stays Auto");
		T.eq("VMware_SCG_8.0", s2.select(VM, "9.1.0").profileName,
				"VM pin beats Auto");
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
				parse("<Profile kind=\"HostSystem\" version=\"SCG 9.0\"/>"
						+ "<Skip control=\"" + LOCKOUT + "\"/>"), all.values());
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

		// One fetch failure with a copy in force: kept, no alert yet.
		f.fail = new java.io.IOException(
				"Suite API GET https://localhost/suite-api/x HTTP 503");
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.Status.FETCH_FAILED, s.status, "fetch failed");
		T.eq("a", s.parsed.entries.get(0).control, "kept on fetch failure");
		T.eq("fetch failed: HTTP 503, last good from 2026-10-13 14:05 CDT",
				s.statusText(0, zone), "fetch failed text");
		T.check(!s.notLoaded(), "one failure with a copy in force: no alert");

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
		T.eq("fetch failed: HTTP 503, no copy in force", s.statusText(0, zone),
				"fetch failed, no copy");
		T.check(s.notLoaded(), "no copy in force raises the alert");

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

	/**
	 * Review of build 90, W2: a fetch failure raises overrides_not_loaded
	 * when no copy is in force (first cycle after a restart, or a failure
	 * from the start), and after 3 straight failures even with one. A 401
	 * or 403 is "refused", not "did not answer".
	 */
	static void fetchFailureAlert() {
		ZoneId zone = ZoneId.of("America/Chicago");
		Instant t1 = Instant.parse("2026-10-13T19:05:00Z");
		Instant t2 = Instant.parse("2026-10-13T19:10:00Z");
		String good =
				"<ComplianceOverrides><Skip control=\"a\"/></ComplianceOverrides>";

		// Refused from the start: no copy, alert on the first cycle.
		OverridesStore st = new OverridesStore();
		FakeFetcher f = new FakeFetcher();
		f.fail = new java.io.IOException(
				"Suite API GET https://localhost/suite-api/x HTTP 403");
		OverridesStore.Snapshot s = st.refresh("site-a", f, t1);
		T.eq(OverridesStore.Status.FETCH_FAILED, s.status, "403 fetch failed");
		T.check(s.parsed == null, "no copy");
		T.check(s.notLoaded(), "403 with no copy raises the alert");
		T.eq("fetch failed: refused (HTTP 403), no copy in force",
				s.statusText(0, zone), "403 says refused");
		f.fail = new java.io.IOException("x HTTP 401");
		T.eq("fetch failed: refused (HTTP 401), no copy in force",
				st.refresh("site-a", f, t1).statusText(0, zone),
				"401 says refused");

		// No channel and a timeout, with no copy: alert, reason named.
		s = new OverridesStore().refresh("site-a", null, t1);
		T.check(s.notLoaded(), "no channel, no copy: alert");
		T.eq("fetch failed: no Suite API channel, no copy in force",
				s.statusText(0, zone), "no channel text");
		FakeFetcher to = new FakeFetcher();
		to.fail = new java.net.SocketTimeoutException("Read timed out");
		s = new OverridesStore().refresh("site-a", to, t1);
		T.check(s.notLoaded(), "timeout, no copy: alert");
		T.eq("fetch failed: no answer (SocketTimeoutException), no copy in "
				+ "force", s.statusText(0, zone), "timeout text");

		// A copy in force: no alert for 2 failures, alert on the 3rd.
		st = new OverridesStore();
		f = new FakeFetcher();
		f.body = good;
		st.refresh("site-a", f, t1);
		f.fail = new java.io.IOException("x HTTP 503");
		s = st.refresh("site-a", f, t2);
		T.eq(1, s.fetchFailures, "1st failure");
		T.check(!s.notLoaded(), "1st failure, copy in force: no alert");
		s = st.refresh("site-a", f, t2);
		T.check(!s.notLoaded(), "2nd failure, copy in force: no alert");
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.FETCH_FAILURE_ALERT_CYCLES, s.fetchFailures,
				"3rd failure");
		T.check(s.parsed != null, "the copy stays in force");
		T.check(s.notLoaded(), "3rd straight failure raises the alert");
		T.eq("fetch failed 3 cycles: HTTP 503, last good from 2026-10-13 "
				+ "14:05 CDT", s.statusText(0, zone), "3 cycles text");
		s = st.refresh("site-a", null, t2);
		T.check(s.notLoaded(), "a 4th (no channel) still alerts");
		T.eq(4, s.fetchFailures, "and counts on");

		// A good fetch resets the run; a parse failure also ends it (the
		// fetch worked) and raises its own alert.
		f.fail = null;
		s = st.refresh("site-a", f, t2);
		T.eq(OverridesStore.Status.OK, s.status, "recovered");
		T.check(!s.notLoaded(), "recovered: no alert");
		f.fail = new java.io.IOException("x HTTP 503");
		s = st.refresh("site-a", f, t2);
		T.eq(1, s.fetchFailures, "the run starts over");
		T.check(!s.notLoaded(), "one failure after recovery: no alert");
		f.fail = null;
		f.body = "not xml";
		st.refresh("site-a", f, t2);
		f.fail = new java.io.IOException("x HTTP 503");
		T.eq(1, st.refresh("site-a", f, t2).fetchFailures,
				"a parse failure ends the run");

		// A new name starts the count over.
		st = new OverridesStore();
		f = new FakeFetcher();
		f.body = good;
		st.refresh("site-a", f, t1);
		f.fail = new java.io.IOException("x HTTP 503");
		st.refresh("site-a", f, t2);
		st.refresh("site-a", f, t2);
		f.fail = null;
		st.refresh("site-b", f, t2);
		f.fail = new java.io.IOException("x HTTP 503");
		T.eq(1, st.refresh("site-b", f, t2).fetchFailures,
				"a new name counts from 1");

		T.eq("refused (HTTP 403)", OverridesStore.fetchReason(
				new java.io.IOException("GET x HTTP 403")), "reason 403");
		T.eq("HTTP 500", OverridesStore.fetchReason(
				new java.io.IOException("GET x HTTP 500")), "reason 500");
	}

	/**
	 * Review of build 90, N5: the adapter wiring needs the SDK jar this
	 * runner leaves off the classpath, so it is pinned in the source (the
	 * build 88 idiom in ComplianceDecisionsTest). Without these, a skipped
	 * control could stop reaching the cleanup plan and keep a stale 0 or 1
	 * with every other test green.
	 */
	static void adapterWiringSourcePins() {
		String ca = readSrc(
				"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");

		// The file is fetched before the selector is built from it, and the
		// status is pushed after the rollup.
		inOrder(body(ca, "private void collectWorldCycle("),
				"collectWorldCycle",
				"cycleOverridesSnap = refreshOverrides();",
				"BenchmarkSelector selector = buildSelector(cycleConfDir, "
						+ "cycleOverridesSnap.parsed);",
				"pushRollup(vcEntry, rollup);",
				"pushOverridesStatus(vcEntry, out);");

		// The selector applies the resolved file and records it.
		inOrder(body(ca, "private BenchmarkSelector buildSelector("),
				"buildSelector",
				"ComplianceOverrides.resolve(parsed, known.values());",
				"cycleOverrides = r;",
				"r.adjust(baseProfiles);",
				"selector.withPins(pins);");

		// The skip list reaches the cleanup plan and the orphan text.
		String clean = body(ca, "private void cleanBatch(");
		inOrder(clean, "cleanBatch",
				"ComplianceDecisions.cleanupPlan(kind, p.profile, p.pushed, "
						+ "bundled, cycleOverrides.skipped);",
				"ComplianceDecisions.orphanProps(stale, p.profileName, "
						+ "cycleOverrides.skipped, config.overridesFile)");

		// Build 92 (issue #41): every object with a benchmark pushes its
		// skipped controls in force, every cycle, before it is queued for
		// cleanup, and the cleanup treats them as live.
		inOrder(body(ca, "private void afterPush("), "afterPush",
				"pushSkippedInForce(kind, d, resourceId, cs);",
				"live.addAll(skippedNow);",
				"new PendingCleanup(kind, resourceId, d.profile, "
						+ "d.profileName, live)");
		String skipPush = body(ca, "private java.util.Set<String> "
				+ "pushSkippedInForce(");
		inOrder(skipPush, "pushSkippedInForce",
				"ComplianceDecisions.skipPush(kind, "
						+ "cycleUnadjusted.get(d.profileName), r.skipped, "
						+ "config.overridesFile);",
				"stitcher.pushProperties(resourceId, sp.props, ts);",
				"stitcher.pushStats(resourceId, sp.stats, ts);");
		T.check(!skipPush.contains("latest"),
				"the skip push never depends on a read-back");
		inOrder(body(ca, "private BenchmarkSelector buildSelector("),
				"buildSelector unadjusted",
				"cycleUnadjusted = java.util.Collections.emptyMap();",
				"cycleUnadjusted = java.util.Collections.unmodifiableMap(known);");

		// The push marks site-overridden controls.
		inOrder(body(ca, "private void pushComplianceViaClient("),
				"pushComplianceViaClient",
				"ComplianceDecisions.complianceProps(cr, profileName, "
						+ "siteOverriddenFor(profileName))");

		// The counts are the in-force ones, and the alert flag is the
		// snapshot's (which covers fetch failures, W2).
		inOrder(body(ca, "private void pushOverridesStatus("),
				"pushOverridesStatus",
				"int skipped = cycleSkippedInForce;",
				"int overridden = cycleOverriddenInForce;",
				"boolean notLoaded = snap.notLoaded();",
				".overridesStats(\"\", skipped, overridden, notLoaded)",
				"ComplianceDecisions.overridesStats(ComplianceDecisions.K, "
						+ "skipped, overridden, notLoaded)");
	}

	/** Each fragment occurs in {@code src}, in this order. */
	static void inOrder(String src, String where, String... fragments) {
		int from = 0;
		for (String f : fragments) {
			int at = src.indexOf(f, from);
			T.check(at >= 0, where + ": expected, in order: " + f);
			from = at + f.length();
		}
	}

	static String readSrc(String path) {
		try {
			return new String(Files.readAllBytes(Paths.get(path)),
					StandardCharsets.UTF_8);
		} catch (java.io.IOException e) {
			throw new AssertionError("read " + path + ": " + e);
		}
	}

	/**
	 * The body of the first method whose declaration starts with
	 * {@code signature}, comments removed and whitespace collapsed.
	 */
	static String body(String src, String signature) {
		int at = src.indexOf(signature);
		T.check(at >= 0, "found " + signature);
		int open = src.indexOf('{', at);
		int depth = 0;
		int i = open;
		for (; i < src.length(); i++) {
			char ch = src.charAt(i);
			if (ch == '{') depth++;
			else if (ch == '}' && --depth == 0) break;
		}
		String b = src.substring(open + 1, i);
		b = b.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("//[^\\n]*", "");
		return b.replaceAll("\\s+", " ").trim();
	}

	static BenchmarkProfile.Control find(BenchmarkProfile p, String id) {
		if (p == null) return null;
		for (BenchmarkProfile.Control c : p.controls) {
			if (c.controlId.equals(id)) return c;
		}
		return null;
	}
}
