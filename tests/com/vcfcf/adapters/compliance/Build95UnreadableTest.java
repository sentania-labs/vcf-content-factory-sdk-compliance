package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Build 95, Scott's decision 2026-10-14 ("if we have missing data we just
 * don't log it - but flag the stale metric, and then that becomes an
 * alarm"): unreadable data is skipped and flagged per object. Each method
 * pins one point of the decision on the SDK-free classes the adapter
 * runs. Run from the repo root.
 */
public final class Build95UnreadableTest {

	private static final String K = "VCF-CF Compliance|";

	public static void main(String[] args) throws Exception {
		unreadableNotPushed();
		perObjectSignals();
		adapterWiring();
		objectKind();
		System.out.println("Build95UnreadableTest: all assertions passed");
	}

	/** Two read controls (one pass, one fail) and one unreadable. */
	static ControlEvaluator.ComplianceResult mixed() {
		List<ControlEvaluator.ControlResult> r = new ArrayList<>();
		r.add(new ControlEvaluator.ControlResult("esx.a", "1", "1", true, "da"));
		r.add(new ControlEvaluator.ControlResult("esx.b", "0", "1", false, "db"));
		r.add(new ControlEvaluator.ControlResult("esx.c", "(unreadable)", "1",
				false, "dc", true));
		return new ControlEvaluator.ComplianceResult("h", 1, 1, 2, 1,
				ControlEvaluator.score(1, 1, 1), r);
	}

	/**
	 * The result the adapter builds for a host vCenter reports
	 * notResponding (wholeUnreadable): every advanced_setting and every
	 * vim / esxcli control of the benchmark folded to UNREADABLE.
	 */
	static List<ControlEvaluator.ComplianceResult> notResponding(
			List<BenchmarkProfile.Control> hostControls) {
		ControlEvaluator.ComplianceResult adv =
				ControlEvaluator.evaluateControlsUnreadable(hostControls, "h");
		Map<String, Object> values = new HashMap<>();
		for (BenchmarkProfile.Control c : hostControls) {
			if (("vim_property".equals(c.parameterKind)
					|| "esxcli".equals(c.parameterKind)) && c.isEvaluable()) {
				values.put(c.configParameter, VSphereClient.UNREADABLE);
			}
		}
		ControlEvaluator.ComplianceResult vim =
				ControlEvaluator.evaluateVimProperties(hostControls, values,
						"h", VSphereClient.UNREADABLE);
		return Arrays.asList(adv, vim);
	}

	/**
	 * Point 1: an unreadable control is not pushed (no -1, no
	 * "(unreadable)" Actual), for every cause, including a host vCenter
	 * reports notResponding; the stale-key cleanup leaves it alone and the
	 * Skip push is unchanged.
	 */
	static void unreadableNotPushed() {
		ControlEvaluator.ComplianceResult cr = mixed();
		Map<String, Double> stats = ComplianceDecisions.complianceStats(cr);
		T.near(1, stats.get(K + "esx.a|Compliant"), "read pass pushed");
		T.near(0, stats.get(K + "esx.b|Compliant"), "read fail pushed");
		T.check(!stats.containsKey(K + "esx.c|Compliant"),
				"unreadable control: no Compliant value (no -1)");
		Map<String, String> props = ComplianceDecisions.complianceProps(cr,
				"VMware_SCG_9.1", new java.util.TreeSet<>(
						Arrays.asList("esx.c")));
		T.eq("1", props.get(K + "esx.a|Actual"), "read Actual pushed");
		for (String f : new String[] {"Actual", "Expected", "Description"}) {
			T.check(!props.containsKey(K + "esx.c|" + f),
					"unreadable control: no " + f + " overwrite");
		}
		for (String v : props.values()) {
			T.check(v == null || !v.contains("(unreadable)"),
					"no (unreadable) text: " + v);
		}

		// A host vCenter reports notResponding: nothing per control.
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkProfile p91 = all.get("VMware_SCG_9.1");
		List<ControlEvaluator.ComplianceResult> nr =
				notResponding(p91.hostControls());
		ControlEvaluator.ComplianceResult adv = nr.get(0);
		T.check(nr.get(0).unreadableCount > 0 && nr.get(1).unreadableCount > 0,
				"both channels unreadable");
		for (ControlEvaluator.ComplianceResult u : nr) {
			for (String key : ComplianceDecisions.complianceStats(u).keySet()) {
				T.check(!key.endsWith("|Compliant"),
						"notResponding host: no per-control push: " + key);
			}
			for (String key : ComplianceDecisions.complianceProps(u,
					"VMware_SCG_9.1").keySet()) {
				T.check(!key.endsWith("|Actual"),
						"notResponding host: no Actual push: " + key);
			}
		}

		// The stale-key cleanup: an unreadable control of the current
		// benchmark is in the held set, so it is never retired to -1 (its
		// last 0 or 1, and any alert on it, stay).
		String unread = adv.controlResults.get(0).scgId;
		Set<String> held = ComplianceDecisions.pushedIds(adv);
		T.check(held.contains(unread), "unreadable control is held");
		ComplianceDecisions.CleanupPlan plan = ComplianceDecisions.cleanupPlan(
				BenchmarkSelector.Kind.HOST, p91, held, all.values(),
				java.util.Collections.<String>emptySet());
		T.check(!plan.zeroOrOne.contains(unread)
				&& !plan.zeroOnly.contains(unread),
				"cleanup does not plan to retire an unreadable control");
		Map<String, Double> lastValues = new HashMap<>();
		lastValues.put(unread, 1.0);
		T.check(ComplianceDecisions.staleControls(plan, lastValues).isEmpty(),
				"its last 1 stays");
		lastValues.put(unread, 0.0);
		T.check(ComplianceDecisions.staleControls(plan, lastValues).isEmpty(),
				"its last 0 (and alert) stays");

		// The Skip push is unchanged: -1 and the skip text, every cycle.
		ComplianceDecisions.SkipPush skip = ComplianceDecisions.skipPush(
				BenchmarkSelector.Kind.HOST, p91,
				new java.util.TreeSet<>(Arrays.asList(unread)), "ovr");
		T.near(-1, skip.stats.get(K + unread + "|Compliant"), "skip still -1");
		T.check(skip.props.get(K + unread + "|Actual")
				.contains("skipped by override file ovr"), "skip text");
	}

	/**
	 * Point 2: has_unreadable every cycle, unreadable_count, the
	 * unreadable_reason property (plain words plus the logged detail, for
	 * every reason code), unreadable_controls (capped, "+N more"); an
	 * object with nothing readable pushes only its unreadable signals.
	 */
	static void perObjectSignals() {
		// has_unreadable on every payload.
		ControlEvaluator.ComplianceResult cr = mixed();
		Map<String, Double> stats = ComplianceDecisions.complianceStats(cr);
		T.near(1, stats.get(ComplianceDecisions.HAS_UNREADABLE), "mixed: 1");
		T.near(1, stats.get(K + "unreadable_count"), "mixed: count");
		ControlEvaluator.ComplianceResult clean =
				new ControlEvaluator.ComplianceResult("h", 1, 0, 1, 0, 100.0,
						Arrays.asList(new ControlEvaluator.ControlResult(
								"esx.a", "1", "1", true, "d")));
		T.near(0, ComplianceDecisions.complianceStats(clean)
				.get(ComplianceDecisions.HAS_UNREADABLE), "clean: 0");
		T.near(0, ComplianceDecisions.noBenchmarkStats()
				.get(ComplianceDecisions.HAS_UNREADABLE), "no benchmark: 0");
		T.near(0, ComplianceDecisions.nothingEvaluatedStats()
				.get(ComplianceDecisions.HAS_UNREADABLE), "nothing evaluated: 0");

		// The reason and controls properties.
		Map<String, String> props = ComplianceDecisions.complianceProps(cr,
				"VMware_SCG_9.1", null, "permission refused (soap-fault: x)");
		T.eq("permission refused (soap-fault: x)",
				props.get(ComplianceDecisions.UNREADABLE_REASON), "reason");
		T.eq("esx.c", props.get(ComplianceDecisions.UNREADABLE_CONTROLS),
				"controls");
		T.eq("VMware_SCG_9.1", props.get(K + "profile_name"), "profile kept");
		Map<String, String> cleanProps = ComplianceDecisions.complianceProps(
				clean, "VMware_SCG_9.1", null, null);
		T.eq("", cleanProps.get(ComplianceDecisions.UNREADABLE_REASON),
				"clean: reason cleared, never left from an earlier cycle");
		T.eq("", cleanProps.get(ComplianceDecisions.UNREADABLE_CONTROLS),
				"clean: controls cleared");
		T.eq("unknown cause (no reason recorded)",
				ComplianceDecisions.complianceProps(cr, "p", null, null)
						.get(ComplianceDecisions.UNREADABLE_REASON),
				"never an empty reason beside has_unreadable = 1");

		// Plain words for every reason code the adapter logs, with the
		// logged detail kept.
		String[][] codes = {
			{"esxcli-host-unreachable: system.ntp.get (connect timed out)",
				"host unreachable for esxcli"},
			{"esxcli-unavailable: no esxcli session", "esxcli unavailable"},
			{"soap-fault: NoPermission: Permission to perform this operation "
				+ "was denied. (config.option)", "permission refused"},
			{"soap-fault: InvalidProperty (config.x)",
				"vCenter returned a fault"},
			{"missing-element: config.network.dnsConfig not returned",
				"setting not returned by vCenter"},
			{"extraconfig-unreadable: ReadFault: NoPermission",
				"VM advanced settings unreadable"},
			{"vami-session: POST /api/session HTTP 401",
				"appliance session refused"},
			{"vami-http-403: GET access/ssh", "appliance permission refused"},
			{"vami-http-500: GET access/ssh", "appliance returned HTTP 500"},
			{"host-not-connected: connectionState=notResponding",
				"host not responding"},
			{"host-not-connected: connectionState=disconnected",
				"host disconnected"},
			{"response-too-large: over the 64 MB cap (RetrieveProperties)",
				"vCenter response over the size cap"},
			{"advanced-settings-unreadable: host flapped (x)",
				"host disconnected during the read"},
			{"vcenter-settings-unreadable: ReadFault: x",
				"vCenter advanced settings unreadable"},
			{"version-unreadable: benchmark unknown: ESX version unreadable",
				"product version unreadable"},
			{"brand-new-code: x", "could not be read (brand-new-code)"},
		};
		for (String[] c : codes) {
			T.eq(c[1], ObjectUnreadable.plainWords(c[0]), c[0]);
			ObjectUnreadable one = new ObjectUnreadable();
			one.record(c[0], 3);
			T.eq(c[1] + " (" + c[0] + ")", one.reasonText(3),
					"plain words plus the logged detail: " + c[0]);
		}

		// Several causes: most controls first, each with its count.
		ObjectUnreadable two = new ObjectUnreadable();
		two.record("esxcli-unavailable: no esxcli session", 1);
		two.record("soap-fault: NoPermission (a)", 2);
		two.record("soap-fault: NoPermission (b)", 1);
		T.eq("permission refused (soap-fault: NoPermission (a)), 3 controls; "
				+ "esxcli unavailable (esxcli-unavailable: no esxcli "
				+ "session), 1 control", two.reasonText(4), "two causes");

		// The reason is capped.
		ObjectUnreadable many = new ObjectUnreadable();
		StringBuilder longDetail = new StringBuilder();
		for (int i = 0; i < 300; i++) longDetail.append('x');
		for (int i = 0; i < 20; i++) {
			many.record("brand-" + i + ": " + longDetail, 20 - i);
		}
		String capped = many.reasonText(400);
		T.check(capped.length() <= ObjectUnreadable.REASON_CAP,
				"reason capped: " + capped.length());
		T.check(capped.matches("(?s).*\\(\\+\\d+ more causes?\\)$"),
				"cut reason ends with +N more causes: " + capped);
		ObjectUnreadable huge = new ObjectUnreadable();
		huge.record("brand-x: " + longDetail + longDetail + longDetail
				+ longDetail, 1);
		T.check(huge.reasonText(1).length() <= ObjectUnreadable.REASON_CAP,
				"one cause over the cap is cut");

		// The controls list is capped with "+N more".
		List<String> ids = new ArrayList<>();
		for (int i = 0; i < 25; i++) ids.add(String.format("esx.c%02d", i));
		String ct = ObjectUnreadable.controlsText(ids);
		T.check(ct.startsWith("esx.c00, esx.c01, "), "sorted: " + ct);
		T.check(ct.endsWith("esx.c19 (+5 more)"), "20 named, +5 more: " + ct);
		T.eq("", ObjectUnreadable.controlsText(new ArrayList<>()), "none");

		// Nothing readable: only the unreadable signals.
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		ControlEvaluator.ComplianceResult whole =
				ControlEvaluator.evaluateControlsUnreadable(
						all.get("VMware_SCG_9.1").hostControls(), "h");
		T.check(ComplianceDecisions.nothingReadable(whole), "nothing readable");
		Map<String, Double> ws = ComplianceDecisions.complianceStats(whole);
		T.eq(new java.util.TreeSet<>(Arrays.asList(
				ComplianceDecisions.HAS_UNREADABLE, K + "unreadable_count",
				K + "collection_failed")), new java.util.TreeSet<>(ws.keySet()),
				"nothing readable: flag family only (no score, no counters)");
		Map<String, String> wp = ComplianceDecisions.complianceProps(whole,
				"VMware_SCG_9.1", null, "host not responding (x)");
		T.eq(new java.util.TreeSet<>(Arrays.asList(
				ComplianceDecisions.UNREADABLE_REASON,
				ComplianceDecisions.UNREADABLE_CONTROLS)),
				new java.util.TreeSet<>(wp.keySet()),
				"nothing readable: reason and controls only");
		T.check(wp.get(ComplianceDecisions.UNREADABLE_CONTROLS)
				.contains("more)"), "a whole host is capped");

		// Version unreadable: flag and reason, controls not invented.
		Map<String, Double> vs = ComplianceDecisions.versionUnreadableStats();
		T.near(1, vs.get(ComplianceDecisions.HAS_UNREADABLE), "version: flag");
		T.check(!vs.containsKey(K + "unreadable_count"), "version: no count");
		Map<String, String> vp = ComplianceDecisions.versionUnreadableProps(
				"benchmark unknown: ESX version unreadable");
		T.eq("product version unreadable (version-unreadable: benchmark "
				+ "unknown: ESX version unreadable)",
				vp.get(ComplianceDecisions.UNREADABLE_REASON), "version reason");
		T.eq(ComplianceDecisions.VERSION_UNREADABLE_CONTROLS,
				vp.get(ComplianceDecisions.UNREADABLE_CONTROLS),
				"version: controls not invented");
	}

	/**
	 * Point 2 wiring (the adapter needs the SDK, so it is pinned from
	 * source): every per-object path starts a fresh reason record before
	 * its reads, every reason the adapter logs is also recorded for the
	 * object, the push carries the object's reason, and a version
	 * unreadable object pushes its flag and reason.
	 */
	static void adapterWiring() throws Exception {
		String ca = new String(java.nio.file.Files.readAllBytes(
				java.nio.file.Paths.get("src/com/vcfcf/adapters/compliance/"
						+ "ComplianceAdapter.java")),
				java.nio.charset.StandardCharsets.UTF_8);
		String[][] loops = {
			{"for (VSphereClient.HostInfo hostInfo : hosts) {",
				"getHostProductVersion"},
			{"for (VSphereClient.VmInfo vm : vms) {", "getVmExtraConfig"},
			{"private ComplianceStitcher.HostEntry collectVCenter(",
				"getVCenterAdvancedSettings"},
			{"private void collectVimObject(", "readAndEvaluateVim"},
		};
		for (String[] l : loops) {
			int at = ca.indexOf(l[0]);
			T.check(at >= 0, "loop: " + l[0]);
			int begin = ca.indexOf("beginObject(", at);
			int read = ca.indexOf(l[1], at);
			T.check(begin > at && begin < read,
					"beginObject() before the reads in " + l[0]);
		}
		for (String m : new String[] {"private void noteUnreadable(",
				"private void noteReadReasons(",
				"private void noteUnreadableControl("}) {
			int at = ca.indexOf(m);
			int end = ca.indexOf("\n\t}\n", at);
			T.check(at >= 0 && ca.substring(at, end)
					.contains("objectUnreadable.record("), m + " records");
		}
		T.check(ca.contains("objectUnreadable.reasonText(cr.unreadableCount)"),
				"the push carries the object's reason");
		T.check(ca.contains("ComplianceDecisions.versionUnreadableProps("),
				"version unreadable pushes its reason");
	}

	/**
	 * Point 4: the "Objects with unreadable controls" list shows each
	 * row's kind from VCF-CF Compliance|object_kind, pushed with every
	 * object payload (the push helpers add it; pinned from source).
	 */
	static void objectKind() throws Exception {
		String[][] want = {{"HOST", "ESX host"}, {"VM", "VM"},
				{"VCENTER", "vCenter"}, {"CLUSTER", "Cluster"},
				{"VDS", "Distributed switch"},
				{"PORTGROUP", "Distributed portgroup"}};
		for (String[] w : want) {
			BenchmarkSelector.Kind k = BenchmarkSelector.Kind.valueOf(w[0]);
			Map<String, String> props = ComplianceDecisions.withObjectKind(
					ComplianceDecisions.unreadableProps("r", "c"), k);
			T.eq(w[1], props.get(ComplianceDecisions.OBJECT_KIND), w[0]);
			T.eq("r", props.get(ComplianceDecisions.UNREADABLE_REASON),
					"the rest kept");
		}
		String ca = new String(java.nio.file.Files.readAllBytes(
				java.nio.file.Paths.get("src/com/vcfcf/adapters/compliance/"
						+ "ComplianceAdapter.java")),
				java.nio.charset.StandardCharsets.UTF_8);
		for (String m : new String[] {"private void pushComplianceViaClient(",
				"private void pushProfileNamePropertyOnly(",
				"private void pushNoBenchmark(",
				"private void recordVersionUnreadable("}) {
			int at = ca.indexOf(m);
			int end = ca.indexOf("\n\t}\n", at);
			T.check(at >= 0 && ca.substring(at, end)
					.contains("ComplianceDecisions.withObjectKind("),
					m + " pushes object_kind");
		}
	}
}
