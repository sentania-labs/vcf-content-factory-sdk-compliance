package com.vcfcf.adapters.compliance;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * Build 58 (review W4): every per-object decision the collect loop makes,
 * as plain functions with no VCF Ops SDK dependency, so the tests drive the
 * same code the adapter runs.
 *
 * <ul>
 *   <li>{@link #decide}: which benchmark an object is scored against, or
 *       why it is not scored (no benchmark / version unreadable).</li>
 *   <li>{@link #resolveVmHostVersion}: a VM follows its host.</li>
 *   <li>The per-object stat payloads for every outcome.</li>
 *   <li>{@link #orphanControlIds}: which per-control keys to mark
 *       not-evaluated when an object's benchmark changes or is first
 *       seen.</li>
 *   <li>{@link #matchVCenter}: which VMWARE vCenter object this instance
 *       may push onto.</li>
 * </ul>
 */
public final class ComplianceDecisions {

	private ComplianceDecisions() {}

	static final String K = "VCF-CF Compliance|";

	// ----- benchmark decision --------------------------------------------

	public enum Outcome { SCORE, NO_BENCHMARK, VERSION_UNREADABLE }

	/** The benchmark decision for one object this cycle. */
	public static final class Decision {
		public final Outcome outcome;
		public final BenchmarkProfile profile;     // SCORE only
		public final String profileName;           // pushed as profile_name
		public final String bucket;                // rollup benchmark bucket
		public final boolean reusedPrevious;       // SCORE via last cycle's benchmark

		Decision(Outcome outcome, BenchmarkProfile profile, String profileName,
				String bucket, boolean reusedPrevious) {
			this.outcome = outcome;
			this.profile = profile;
			this.profileName = profileName;
			this.bucket = bucket;
			this.reusedPrevious = reusedPrevious;
		}
	}

	/**
	 * Decide the benchmark for an object.
	 *
	 * <p>Review B2: a version the adapter could not read is NOT "no
	 * benchmark". If the object had a benchmark last cycle (and that profile
	 * is loaded) it is scored against it again; otherwise the outcome is
	 * {@link Outcome#VERSION_UNREADABLE}, which the caller treats as an
	 * unreadable object (non-compliant, no alert cleanup, last-known host
	 * score). Only a READABLE version with no bundled SCG is
	 * {@link Outcome#NO_BENCHMARK}.
	 *
	 * @param previousProfileName benchmark applied to this object last
	 *        cycle, or null when unknown
	 * @param loadedByName profiles loaded this cycle, by name
	 */
	public static Decision decide(BenchmarkSelector selector,
			BenchmarkSelector.Kind kind, String governingVersion,
			String previousProfileName,
			Map<String, BenchmarkProfile> loadedByName) {
		BenchmarkSelector.Selection s = selector.select(kind, governingVersion);
		if (s.profile != null) {
			return new Decision(Outcome.SCORE, s.profile, s.profileName,
					s.bucket, false);
		}
		if (s.noBenchmark()) {
			return new Decision(Outcome.NO_BENCHMARK, null, s.profileName,
					s.bucket, false);
		}
		BenchmarkProfile prev = previousProfileName == null || loadedByName == null
				? null : loadedByName.get(previousProfileName);
		if (prev != null) {
			return new Decision(Outcome.SCORE, prev, prev.name,
					BenchmarkSelector.bucketOf(prev.name), true);
		}
		return new Decision(Outcome.VERSION_UNREADABLE, null, s.profileName,
				s.bucket, false);
	}

	/**
	 * The ESXi version governing a VM: its host's version from this cycle's
	 * host map; a host missing from the map is read once through
	 * {@code fallbackReader} and cached. Null (version unreadable) when the
	 * VM has no host or no read succeeds; never a default version.
	 */
	public static String resolveVmHostVersion(String hostMoid,
			Map<String, String> hostVersions,
			Function<String, String> fallbackReader) {
		if (hostMoid == null) return null;
		if (hostVersions.containsKey(hostMoid)) {
			return hostVersions.get(hostMoid);
		}
		String v = fallbackReader == null ? null : fallbackReader.apply(hostMoid);
		hostVersions.put(hostMoid, v);
		return v;
	}

	// ----- per-object payloads -------------------------------------------

	/**
	 * Stats for an evaluated object. Review W2: pass_count / fail_count
	 * are pushed as 0 when nothing was scored, so a previous cycle's
	 * counters never linger; score stays omitted (never a sentinel).
	 */
	public static Map<String, Double> complianceStats(
			ControlEvaluator.ComplianceResult cr) {
		Map<String, Double> stats = new LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			stats.put(K + ctrl.scgId + "|Compliant", ctrl.unreadable
					? ComplianceAdapterConstants.COMPLIANT_NOT_EVALUATED
					: (ctrl.compliant ? 1.0 : 0.0));
		}
		if (cr.totalCount > 0) {
			stats.put(K + "score", cr.score);
		}
		stats.put(K + "pass_count", (double) cr.passCount);
		stats.put(K + "fail_count", (double) cr.failCount);
		stats.put(K + "total_count", (double) cr.totalCount);
		stats.put(K + "unreadable_count", (double) cr.unreadableCount);
		stats.put(K + "non_compliant", ComplianceRollup.isNonCompliant(
				cr.failCount, cr.unreadableCount) ? 1.0 : 0.0);
		stats.put(K + "no_benchmark", 0.0);
		return stats;
	}

	/** Properties for an evaluated object. */
	public static Map<String, String> complianceProps(
			ControlEvaluator.ComplianceResult cr, String profileName) {
		Map<String, String> props = new LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			String base = K + ctrl.scgId;
			props.put(base + "|Actual", ctrl.actual);
			props.put(base + "|Expected", ctrl.expected);
			props.put(base + "|Description", ctrl.description);
		}
		props.put(K + "profile_name", profileName);
		return props;
	}

	/** A readable version with no SCG: flagged, counters zeroed (W2). */
	public static Map<String, Double> noBenchmarkStats() {
		Map<String, Double> stats = zeroCounters();
		stats.put(K + "no_benchmark", 1.0);
		stats.put(K + "non_compliant", 0.0);
		return stats;
	}

	/** A benchmark with nothing evaluable (e.g. non-vSAN cluster) (W2). */
	public static Map<String, Double> nothingEvaluatedStats() {
		Map<String, Double> stats = zeroCounters();
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "non_compliant", 0.0);
		return stats;
	}

	/**
	 * Governing version unreadable and no previous benchmark (B2):
	 * non-compliant, not no_benchmark. unreadable_count is left as is: the
	 * adapter does not know which benchmark's controls apply, so it cannot
	 * count them honestly.
	 */
	public static Map<String, Double> versionUnreadableStats() {
		Map<String, Double> stats = new LinkedHashMap<>();
		stats.put(K + "pass_count", 0.0);
		stats.put(K + "fail_count", 0.0);
		stats.put(K + "total_count", 0.0);
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "non_compliant", 1.0);
		return stats;
	}

	private static Map<String, Double> zeroCounters() {
		Map<String, Double> stats = new LinkedHashMap<>();
		stats.put(K + "pass_count", 0.0);
		stats.put(K + "fail_count", 0.0);
		stats.put(K + "total_count", 0.0);
		stats.put(K + "unreadable_count", 0.0);
		return stats;
	}

	/** profile_name-only properties. */
	public static Map<String, String> profileNameProps(String profileName) {
		Map<String, String> props = new LinkedHashMap<>();
		props.put(K + "profile_name", profileName);
		return props;
	}

	// ----- orphan-control cleanup (W1) -----------------------------------

	/**
	 * Control ids whose per-control keys must be marked not evaluated
	 * ({@code Compliant=-1}) for an object of {@code kind}.
	 *
	 * <p>Self-healing (review W1): when the object is seen for the first
	 * time since the tracker was last cleared (collector start, instance
	 * edit, periodic re-sweep) or its previous benchmark cannot be
	 * resolved, the candidate set is the UNION of every bundled profile's
	 * evaluated controls for the kind, because keys left by an unknown
	 * earlier benchmark may exist. Otherwise it is the previous profile's
	 * evaluated controls. Either way, controls the current profile evaluates
	 * are kept (they are pushed live).
	 *
	 * @param current the profile applied now, or null (no benchmark)
	 */
	public static Set<String> orphanControlIds(BenchmarkSelector.Kind kind,
			BenchmarkProfile previous, BenchmarkProfile current,
			Collection<BenchmarkProfile> allBundled, boolean firstSight) {
		Set<String> out = new TreeSet<>();
		if (firstSight || previous == null) {
			for (BenchmarkProfile p : allBundled) {
				addEvaluated(out, kind, p);
			}
		} else {
			addEvaluated(out, kind, previous);
		}
		if (current != null) {
			Set<String> keep = new TreeSet<>();
			addEvaluated(keep, kind, current);
			out.removeAll(keep);
		}
		return out;
	}

	private static void addEvaluated(Set<String> into,
			BenchmarkSelector.Kind kind, BenchmarkProfile p) {
		if (p == null) return;
		for (BenchmarkProfile.Control c : sliceFor(p, kind)) {
			if (BenchmarkSelector.evaluatedFor(kind, c)) {
				into.add(c.controlId);
			}
		}
	}

	public static Map<String, Double> orphanStats(Set<String> ids) {
		Map<String, Double> stats = new LinkedHashMap<>();
		for (String id : ids) {
			stats.put(K + id + "|Compliant",
					ComplianceAdapterConstants.COMPLIANT_NOT_EVALUATED);
		}
		return stats;
	}

	public static Map<String, String> orphanProps(Set<String> ids,
			String appliedName) {
		Map<String, String> props = new LinkedHashMap<>();
		for (String id : ids) {
			props.put(K + id + "|Actual", "(not in applied benchmark: "
					+ appliedName + ")");
		}
		return props;
	}

	public static java.util.List<BenchmarkProfile.Control> sliceFor(
			BenchmarkProfile p, BenchmarkSelector.Kind kind) {
		switch (kind) {
			case HOST: return p.hostControls();
			case VM: return p.vmControls();
			case VCENTER: return p.vCenterControls();
			case CLUSTER: return p.clusterControls();
			case VDS: return p.dvsControls();
			case PORTGROUP: return p.dvpgControls();
			default: return java.util.Collections.emptyList();
		}
	}

	// ----- vCenter stitch decision (B1) ----------------------------------

	/**
	 * The VMWARE vCenter object this instance may push onto (review B1).
	 *
	 * <ul>
	 *   <li>vCenter instance UUID known: the {@code VMEntityVCID} index
	 *       ONLY. Absent means VCF Ops does not monitor this vCenter (or its
	 *       key lacks the id): return null, never guess.</li>
	 *   <li>UUID unreadable: exact (case-insensitive) {@code VCURL} match
	 *       only. No prefix match, no display-name match, no "the only
	 *       vCenter" fallback: any of those can land this vCenter's rollup on
	 *       another vCenter's object.</li>
	 * </ul>
	 */
	public static <T> T matchVCenter(String vcInstanceUuid,
			Map<String, T> byUuid, Map<String, T> byUrl, String host) {
		if (vcInstanceUuid != null && !vcInstanceUuid.isEmpty()) {
			return byUuid.get(vcInstanceUuid);
		}
		if (host == null || host.isEmpty()) return null;
		T exact = byUrl.get(host);
		if (exact != null) return exact;
		for (Map.Entry<String, T> e : byUrl.entrySet()) {
			if (e.getKey().equalsIgnoreCase(host)) return e.getValue();
		}
		return null;
	}
}
