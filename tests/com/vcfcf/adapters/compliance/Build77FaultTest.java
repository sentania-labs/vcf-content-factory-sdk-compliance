package com.vcfcf.adapters.compliance;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;

/**
 * Build 77 (review of build 76, BLOCKING): a SOAP fault on the option
 * reads must never look like "read OK, nothing set". Covers the three
 * fault cases (VM extraConfig fault, host OptionManager fault, missing
 * vCenter setting manager): the read throws, the controls come out
 * UNREADABLE (no pass), and the cleanup plan leaves the object's real
 * values alone. Run from the repo root.
 */
public final class Build77FaultTest {

	public static void main(String[] args) throws Exception {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkProfile p91 = all.get("VMware_SCG_9.1");

		// ---- the parsers: a failed call throws, a real empty read is empty
		expectFault(() -> VimOptions.fromQueryOptions(null,
				"QueryOptions on host-12", "HTTP 500 HostNotConnected"),
				"HostNotConnected");
		expectFault(() -> VimOptions.fromPropertyOptions(null,
				"config.extraConfig", "RetrieveProperties config.extraConfig",
				"HTTP 500 ManagedObjectNotFound"), "ManagedObjectNotFound");
		expectFault(() -> VimOptions.fromPropertyOptions(xml(
				"<Envelope><Body><RetrievePropertiesResponse/></Body></Envelope>"),
				"config.extraConfig", "RetrieveProperties", null),
				"no object");
		T.check(VimOptions.fromQueryOptions(xml(
				"<Envelope><Body><QueryOptionsResponse/></Body></Envelope>"),
				"QueryOptions", null).isEmpty(), "successful empty option list");
		Map<String, String> opts = VimOptions.fromQueryOptions(xml(
				"<Envelope><Body><QueryOptionsResponse>"
				+ "<returnval><key>Security.AccountLockFailures</key>"
				+ "<value>5</value></returnval>"
				+ "</QueryOptionsResponse></Body></Envelope>"), "QueryOptions", null);
		T.eq("5", opts.get("Security.AccountLockFailures"), "option parsed");
		T.check(VimOptions.fromPropertyOptions(xml(
				"<Envelope><Body><RetrievePropertiesResponse><returnval>"
				+ "<obj type=\"VirtualMachine\">vm-1</obj>"
				+ "</returnval></RetrievePropertiesResponse></Body></Envelope>"),
				"config.extraConfig", "R", null).isEmpty(),
				"object present, property unset: read OK, nothing set");
		Map<String, String> extra = VimOptions.fromPropertyOptions(xml(
				"<Envelope><Body><RetrievePropertiesResponse><returnval>"
				+ "<obj type=\"VirtualMachine\">vm-1</obj><propSet>"
				+ "<name>config.extraConfig</name><val>"
				+ "<OptionValue><key>isolation.tools.copy.disable</key>"
				+ "<value>true</value></OptionValue>"
				+ "</val></propSet></returnval></RetrievePropertiesResponse>"
				+ "</Body></Envelope>"), "config.extraConfig", "R", null);
		T.eq("true", extra.get("isolation.tools.copy.disable"), "extraConfig parsed");

		// ---- VM extraConfig fault: unreadable, no pass (was a false pass)
		List<BenchmarkProfile.Control> vm = p91.vmControls();
		ControlEvaluator.ComplianceResult oldBehaviour =
				ControlEvaluator.evaluateControls(vm, new HashMap<>(), "vm-1");
		T.check(oldBehaviour.passCount > 0,
				"fixture: an empty map passes 'or Undefined' controls (the bug)");
		assertUnreadableAndProtected("VM extraConfig fault",
				BenchmarkSelector.Kind.VM, p91, vm, all);

		// ---- host OptionManager (QueryOptions) fault
		assertUnreadableAndProtected("host OptionManager fault",
				BenchmarkSelector.Kind.HOST, p91, p91.hostControls(), all);

		// ---- missing vCenter setting manager
		assertUnreadableAndProtected("missing setting manager",
				BenchmarkSelector.Kind.VCENTER, p91, p91.vCenterControls(), all);

		System.out.println("Build77FaultTest: all assertions passed");
	}

	/**
	 * The adapter's handler for a thrown option read: every
	 * advanced_setting control of the slice is UNREADABLE. None passes, each
	 * is pushed as Compliant = -1, and the cleanup plan does not touch them
	 * (they were pushed this cycle), so real earlier 0s and 1s stay.
	 */
	private static void assertUnreadableAndProtected(String what,
			BenchmarkSelector.Kind kind, BenchmarkProfile profile,
			List<BenchmarkProfile.Control> slice,
			Map<String, BenchmarkProfile> all) {
		ControlEvaluator.ComplianceResult cr =
				ControlEvaluator.evaluateControlsUnreadable(slice, "obj");
		T.check(cr.unreadableCount > 0, what + ": controls unreadable");
		T.eq(0, cr.passCount, what + ": nothing passes");
		T.eq(0, cr.failCount, what + ": nothing is an evaluated failure");
		Map<String, Double> stats = ComplianceDecisions.complianceStats(cr);
		for (ControlEvaluator.ControlResult r : cr.controlResults) {
			T.near(-1, stats.get("VCF-CF Compliance|" + r.scgId + "|Compliant"),
					what + ": " + r.scgId + " pushed as -1");
		}
		Set<String> pushed = ComplianceDecisions.pushedIds(cr);
		ComplianceDecisions.CleanupPlan plan = ComplianceDecisions.cleanupPlan(
				kind, profile, pushed, all.values());
		Map<String, Double> real = new HashMap<>();
		for (String id : pushed) real.put(id, id.hashCode() % 2 == 0 ? 0.0 : 1.0);
		for (String id : ComplianceDecisions.staleControls(plan, real)) {
			throw new AssertionError(what + ": cleanup would retire " + id);
		}
	}

	private interface Call { Object run() throws Exception; }

	private static void expectFault(Call c, String fragment) {
		try {
			c.run();
			throw new AssertionError("expected ReadFault containing " + fragment);
		} catch (VimOptions.ReadFault e) {
			T.check(String.valueOf(e.getMessage()).contains(fragment),
					"fault message: " + e.getMessage());
		} catch (Exception e) {
			throw new AssertionError("wrong exception " + e);
		}
	}

	static Document xml(String s) throws Exception {
		DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
		f.setNamespaceAware(true);
		return f.newDocumentBuilder().parse(new ByteArrayInputStream(
				s.getBytes(StandardCharsets.UTF_8)));
	}
}
