package com.vcfcf.adapters.compliance;

/**
 * Executing test for {@link BenchmarkLoader#resolveBundledProfileName}
 * (build 56, review B1: unknown non-null profile names must FAIL LOUD,
 * never silently score against a different benchmark).
 *
 * <p>The repo has no test framework; this is a plain {@code main} that
 * throws {@link AssertionError} on any failed expectation and exits 0
 * on success. Run it via {@code ci/run_java_tests.sh} (compiles against
 * {@code src/} with the system javac; no external dependencies).
 */
public final class BenchmarkLoaderTest {

	public static void main(String[] args) {
		// Known bundled names resolve to themselves (6.7 / 7.0 added in
		// build 57).
		expectResolved("VMware_SCG_6.7", "VMware_SCG_6.7");
		expectResolved("VMware_SCG_7.0", "VMware_SCG_7.0");
		expectResolved("VMware_SCG_8.0", "VMware_SCG_8.0");
		expectResolved("VMware_SCG_9.0", "VMware_SCG_9.0");
		expectResolved("VMware_SCG_9.1", "VMware_SCG_9.1");

		// Absent name (null / blank) keeps the pre-v3 fallback (8.0), NOT
		// Auto: an existing instance with no stored value behaves exactly as
		// before the upgrade.
		expectResolved(null, "VMware_SCG_8.0");
		expectResolved("", "VMware_SCG_8.0");
		expectResolved("   ", "VMware_SCG_8.0");

		// Unknown NON-null names throw with an actionable message —
		// including the retired CIS profile (the review-B1 case: a
		// CIS-configured instance after an in-place upgrade must go to
		// a visible failed state, not silently score as SCG 8.0).
		expectThrows("CIS_vSphere_8", "not bundled in this version");
		expectThrows("CIS_vSphere_8", "CIS_vSphere_8");
		expectThrows("VMware_SCG_6.5", "not bundled in this version");
		expectThrows("VMware_SCG_10.0", "not bundled in this version");

		// Build 92: Custom is gone. The resolver treats it as unknown and
		// the message no longer offers it.
		expectThrows("Custom", "not bundled in this version");
		try {
			BenchmarkLoader.resolveBundledProfileName("Custom");
		} catch (RuntimeException e) {
			if (e.getMessage().contains("or Custom")) {
				throw new AssertionError("message still offers Custom: "
						+ e.getMessage());
			}
		}
		// Build 93: the Compliance Profile setting is removed. A stored
		// value is only reported: one INFO naming it (the adapter logs it
		// once per configure); Auto, blank and absent say nothing.
		for (String quiet : new String[] {null, "", "  ",
				"Auto (by version)", " auto (BY VERSION) "}) {
			if (ComplianceConfig.retiredProfileNotice(quiet) != null) {
				throw new AssertionError("no notice for '" + quiet + "'");
			}
		}
		String n90 = ComplianceConfig.retiredProfileNotice("VMware_SCG_9.0");
		if (n90 == null || !n90.contains("stored 'VMware_SCG_9.0'")
				|| !n90.contains("now runs Auto (by version)")
				|| !n90.contains("<Profile version=\"SCG 9.0\"/>")) {
			throw new AssertionError("fixed 9.0 notice: " + n90);
		}
		String nCustom = ComplianceConfig.retiredProfileNotice(" Custom ");
		if (nCustom == null || !nCustom.contains("stored 'Custom'")
				|| !nCustom.contains("SCG X.Y")) {
			throw new AssertionError("Custom notice: " + nCustom);
		}
		for (String stored : new String[] {"Custom", "custom", " Custom "}) {
			if (!ComplianceConfig.isCustomName(stored)) {
				throw new AssertionError("'" + stored + "' is Custom");
			}
		}
		if (ComplianceConfig.isCustomName("VMware_SCG_9.0")
				|| ComplianceConfig.isCustomName(null)) {
			throw new AssertionError("only Custom is Custom");
		}

		// Filename mapping covers every bundled profile.
		expectFilename("VMware_SCG_6.7", "scg_6.7.csv");
		expectFilename("VMware_SCG_7.0", "scg_7.0.csv");
		expectFilename("VMware_SCG_8.0", "scg_8.0.csv");
		expectFilename("VMware_SCG_9.0", "scg_9.0.csv");
		expectFilename("VMware_SCG_9.1", "scg_9.1.csv");

		System.out.println("BenchmarkLoaderTest: all assertions passed");
	}

	private static void expectResolved(String in, String want) {
		String got = BenchmarkLoader.resolveBundledProfileName(in);
		if (!want.equals(got)) {
			throw new AssertionError("resolveBundledProfileName(" + in
					+ ") = " + got + ", want " + want);
		}
	}

	private static void expectThrows(String in, String messageFragment) {
		try {
			String got = BenchmarkLoader.resolveBundledProfileName(in);
			throw new AssertionError("resolveBundledProfileName(" + in
					+ ") returned '" + got + "' instead of throwing");
		} catch (RuntimeException e) {
			String msg = String.valueOf(e.getMessage());
			if (!msg.contains(messageFragment)) {
				throw new AssertionError("resolveBundledProfileName(" + in
						+ ") threw, but message lacks '" + messageFragment
						+ "': " + msg);
			}
		}
	}

	private static void expectFilename(String resolved, String want) {
		String got = BenchmarkLoader.bundledFilename(resolved);
		if (!want.equals(got)) {
			throw new AssertionError("bundledFilename(" + resolved
					+ ") = " + got + ", want " + want);
		}
	}
}
