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
 *       why it is not scored normally (no benchmark / version
 *       unreadable).</li>
 *   <li>{@link #resolveVmHostVersion}: a VM follows its host.</li>
 *   <li>The per-object stat payloads for every outcome.</li>
 *   <li>{@link #candidateControlIds} / {@link #staleZeroControls}: which
 *       per-control keys to mark not evaluated (only live stale 0s outside
 *       the object's benchmark).</li>
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
	 * object where nothing was collected (score 0, non-compliant,
	 * collection_failed = 1, no alert cleanup; build 65). Only a READABLE
	 * version with no bundled SCG is
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
	 * The ESX version governing a VM: its host's version from this cycle's
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
	 * Stats for an evaluated object. Score (build 63, owner decision):
	 * unreadable controls count as failing
	 * ({@link ControlEvaluator#score}); pushed whenever at least one control
	 * was attempted, so an all-unreadable object reads 0. Only with nothing
	 * attempted is score omitted (never a stand-in). pass_count /
	 * fail_count / unreadable_count are always pushed and stay separate.
	 */
	public static Map<String, Double> complianceStats(
			ControlEvaluator.ComplianceResult cr) {
		Map<String, Double> stats = new LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			stats.put(K + ctrl.scgId + "|Compliant", ctrl.unreadable
					? ComplianceAdapterConstants.COMPLIANT_NOT_EVALUATED
					: (ctrl.compliant ? 1.0 : 0.0));
		}
		if (cr.attempted() > 0) {
			stats.put(K + "score", cr.score);
		}
		stats.put(K + "pass_count", (double) cr.passCount);
		stats.put(K + "fail_count", (double) cr.failCount);
		stats.put(K + "total_count", (double) cr.totalCount);
		stats.put(K + "unreadable_count", (double) cr.unreadableCount);
		stats.put(K + "non_compliant", ComplianceRollup.isNonCompliant(
				cr.failCount, cr.unreadableCount) ? 1.0 : 0.0);
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "collection_failed", collectionFailed(cr) ? 1.0 : 0.0);
		return stats;
	}

	/**
	 * Build 65 (review W1 on build 64): true when nothing could be read on
	 * the object at all: controls were attempted and every one was
	 * unreadable (e.g. a disconnected host). Pushed as
	 * {@code VCF-CF Compliance|collection_failed}; the version-unreadable
	 * payload sets it to 1 as well.
	 */
	public static boolean collectionFailed(ControlEvaluator.ComplianceResult cr) {
		return cr.totalCount == 0 && cr.unreadableCount > 0;
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
		stats.put(K + "collection_failed", 0.0);
		return stats;
	}

	/** A benchmark with nothing evaluable (e.g. non-vSAN cluster) (W2). */
	public static Map<String, Double> nothingEvaluatedStats() {
		Map<String, Double> stats = zeroCounters();
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "non_compliant", 0.0);
		stats.put(K + "collection_failed", 0.0);
		return stats;
	}

	/**
	 * Governing version unreadable and no previous benchmark (build 58 B2,
	 * build 65 W1): nothing could be collected, so by the build 63 rule
	 * (unreadable counts as failing) the object scores 0, is non-compliant,
	 * and {@code collection_failed} = 1 raises its "Compliance data not
	 * collected" alert. unreadable_count is NOT pushed: the adapter does not
	 * know which benchmark's controls apply, so it will not invent a count.
	 */
	public static Map<String, Double> versionUnreadableStats() {
		Map<String, Double> stats = new LinkedHashMap<>();
		stats.put(K + "score", 0.0);
		stats.put(K + "pass_count", 0.0);
		stats.put(K + "fail_count", 0.0);
		stats.put(K + "total_count", 0.0);
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "non_compliant", 1.0);
		stats.put(K + "collection_failed", 1.0);
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

	// ----- stale per-control cleanup (build 59) ---------------------------

	/**
	 * Control ids whose {@code Compliant} key could hold a stale value on an
	 * object of {@code kind}: every control any bundled profile evaluates for
	 * the kind, PLUS every control the manual-review overlay demoted for the
	 * kind (build 70: an earlier build may have scored and pushed it, e.g.
	 * the standard-switch controls wrongly read from distributed switches in
	 * builds 57 to 69), PLUS {@link #RETIRED_CONTROL_IDS} for the kind
	 * (build 72), minus the controls the object's current benchmark
	 * evaluates (those are pushed live every cycle). {@code current} null (no
	 * benchmark) means every such control is a candidate.
	 *
	 * <p>Candidates are only QUERIED, never pushed blindly: see
	 * {@link #staleZeroControls}.
	 */
	/**
	 * Control ids that earlier builds evaluated on a kind but that no
	 * bundled profile carries for that kind any more. They stay cleanup
	 * candidates so a lingering {@code Compliant = 0} is retired (-1).
	 *
	 * <p>Build 72: {@code vds.network-reset-port} (SCG 7.0 / 8.0 / 9.0)
	 * moved to the portgroup as {@code dvpg.network-reset-port}. Its read
	 * never resolved on a distributed switch, so builds 57 to 71 pushed -1
	 * (unreadable) there, not 0; listing it makes the retirement explicit
	 * rather than relying on that.
	 */
	static final Map<BenchmarkSelector.Kind, Set<String>> RETIRED_CONTROL_IDS;
	static {
		Map<BenchmarkSelector.Kind, Set<String>> m =
				new java.util.EnumMap<>(BenchmarkSelector.Kind.class);
		m.put(BenchmarkSelector.Kind.VDS, java.util.Collections.unmodifiableSet(
				new TreeSet<>(java.util.Arrays.asList("vds.network-reset-port"))));
		RETIRED_CONTROL_IDS = java.util.Collections.unmodifiableMap(m);
	}

	public static Set<String> candidateControlIds(BenchmarkSelector.Kind kind,
			BenchmarkProfile current, Collection<BenchmarkProfile> allBundled) {
		Set<String> out = new TreeSet<>();
		for (BenchmarkProfile p : allBundled) {
			addEvaluated(out, kind, p);
			for (BenchmarkProfile.Control c : sliceFor(p, kind)) {
				if (c.manualReview) out.add(c.controlId);
			}
		}
		out.addAll(RETIRED_CONTROL_IDS.getOrDefault(kind,
				java.util.Collections.emptySet()));
		if (current != null) {
			Set<String> keep = new TreeSet<>();
			addEvaluated(keep, kind, current);
			out.removeAll(keep);
		}
		return out;
	}

	/**
	 * Build 59 (review W1 on build 58): the controls to mark not evaluated
	 * ({@code Compliant=-1}) on one object. Only a candidate (outside the
	 * current benchmark) whose LATEST value in VCF Ops is 0 qualifies: that
	 * stale 0 is what keeps a per-control alert open. A key the object never
	 * had is absent from {@code latest} and is never created; a key already
	 * at -1 or 1 is left alone. {@code latest} null means the bulk read
	 * failed: nothing is cleaned for the object this cycle (no guess, no
	 * union fallback); the next cycle retries.
	 *
	 * @param latest control id -> latest Compliant value for this object, as
	 *        read from VCF Ops; null when the read failed
	 */
	public static Set<String> staleZeroControls(Set<String> candidates,
			Map<String, Double> latest) {
		Set<String> out = new TreeSet<>();
		if (latest == null || candidates == null) return out;
		for (Map.Entry<String, Double> e : latest.entrySet()) {
			Double v = e.getValue();
			if (v != null && v == 0.0 && candidates.contains(e.getKey())) {
				out.add(e.getKey());
			}
		}
		return out;
	}

	/**
	 * Build 76 (review of build 75, WARNING): the stale-control cleanup plan
	 * for ONE object, based on what was actually pushed this cycle.
	 *
	 * <ul>
	 *   <li>{@link #zeroOrOne}: controls the object's CURRENT benchmark
	 *       evaluates for its kind but that were NOT pushed this cycle (not
	 *       applicable, e.g. vSAN controls on a cluster where vSAN is not
	 *       enabled, or an advanced setting that was absent without an "or
	 *       Undefined" default). Any lingering 0 OR 1 is retired to -1: a 1
	 *       left from an earlier false pass is as wrong as a 0.</li>
	 *   <li>{@link #zeroOnly}: controls outside the current benchmark
	 *       ({@link #candidateControlIds}), not pushed this cycle. Only a
	 *       lingering 0 is retired (unchanged since build 59).</li>
	 * </ul>
	 * Controls pushed this cycle are never touched (their value is live).
	 * Values are read back first; a key the object never had is never
	 * created.
	 */
	public static final class CleanupPlan {
		public final Set<String> zeroOrOne;
		public final Set<String> zeroOnly;

		CleanupPlan(Set<String> zeroOrOne, Set<String> zeroOnly) {
			this.zeroOrOne = java.util.Collections.unmodifiableSet(zeroOrOne);
			this.zeroOnly = java.util.Collections.unmodifiableSet(zeroOnly);
		}

		/** Every control id whose latest value must be read back. */
		public Set<String> queryIds() {
			Set<String> all = new TreeSet<>(zeroOrOne);
			all.addAll(zeroOnly);
			return all;
		}

		public boolean isEmpty() {
			return zeroOrOne.isEmpty() && zeroOnly.isEmpty();
		}
	}

	/**
	 * @param current the benchmark applied to the object (null: none)
	 * @param pushed  control ids whose Compliant value was pushed for the
	 *                object this cycle (empty when nothing was pushed)
	 */
	public static CleanupPlan cleanupPlan(BenchmarkSelector.Kind kind,
			BenchmarkProfile current, Set<String> pushed,
			Collection<BenchmarkProfile> allBundled) {
		Set<String> live = pushed == null
				? java.util.Collections.<String>emptySet() : pushed;
		Set<String> zeroOrOne = new TreeSet<>();
		if (current != null) {
			addEvaluated(zeroOrOne, kind, current);
			zeroOrOne.removeAll(live);
		}
		Set<String> zeroOnly = candidateControlIds(kind, current, allBundled);
		zeroOnly.removeAll(live);
		zeroOnly.removeAll(zeroOrOne);
		return new CleanupPlan(zeroOrOne, zeroOnly);
	}

	/**
	 * Controls to set to -1 for one object under {@code plan}.
	 * {@code latest} null means the read-back failed: nothing is cleaned
	 * (never a guess; retried next cycle).
	 */
	public static Set<String> staleControls(CleanupPlan plan,
			Map<String, Double> latest) {
		Set<String> out = new TreeSet<>();
		if (latest == null || plan == null) return out;
		for (Map.Entry<String, Double> e : latest.entrySet()) {
			Double v = e.getValue();
			if (v == null) continue;
			String id = e.getKey();
			if (plan.zeroOrOne.contains(id) && (v == 0.0 || v == 1.0)) {
				out.add(id);
			} else if (plan.zeroOnly.contains(id) && v == 0.0) {
				out.add(id);
			}
		}
		return out;
	}

	/** Control ids whose Compliant value a result pushes. */
	public static Set<String> pushedIds(ControlEvaluator.ComplianceResult cr) {
		Set<String> out = new TreeSet<>();
		if (cr == null) return out;
		for (ControlEvaluator.ControlResult r : cr.controlResults) {
			out.add(r.scgId);
		}
		return out;
	}

	/** Full stat key for a control's Compliant metric. */
	public static String compliantKey(String controlId) {
		return K + controlId + "|Compliant";
	}

	/** Control id from a Compliant stat key; null for any other key. */
	public static String controlIdOfCompliantKey(String statKey) {
		if (statKey == null || !statKey.startsWith(K)
				|| !statKey.endsWith("|Compliant")) {
			return null;
		}
		String id = statKey.substring(K.length(),
				statKey.length() - "|Compliant".length());
		return id.isEmpty() || id.contains("|") ? null : id;
	}

	/**
	 * Default URL budget for one stats/latest GET: comfortably under the
	 * common 8 KB request-line / header limit of the Suite API front end.
	 */
	public static final int URL_BUDGET = 6000;

	/**
	 * Suite API paths for {@code GET /api/resources/stats/latest} covering
	 * every (resource, control) pair, sized by URL length (build 60, review
	 * N1 on build 59): the stat keys are split into chunks of at most half
	 * the budget, then each request is packed with as many resourceId
	 * parameters as fit in the rest. One candidate key (the typical VM case)
	 * packs about 120 objects per request; a host's worst case (86 keys)
	 * needs two key chunks. At least one id and one key per request, so a
	 * pathological single key longer than the budget still yields a request.
	 * Deterministic order.
	 */
	public static java.util.List<String> latestCompliantPaths(
			java.util.List<String> resourceIds, Set<String> controlIds,
			int urlBudget) {
		java.util.List<String> paths = new java.util.ArrayList<>();
		if (resourceIds.isEmpty() || controlIds.isEmpty()) return paths;
		String base = "/api/resources/stats/latest?";
		java.util.List<String> keyChunks = new java.util.ArrayList<>();
		StringBuilder chunk = new StringBuilder();
		int keyBudget = Math.max(1, urlBudget / 2);
		for (String cid : controlIds) {
			String part = "&statKey=" + enc(compliantKey(cid));
			if (chunk.length() > 0 && chunk.length() + part.length() > keyBudget) {
				keyChunks.add(chunk.toString());
				chunk.setLength(0);
			}
			chunk.append(part);
		}
		keyChunks.add(chunk.toString());
		for (String keys : keyChunks) {
			int i = 0;
			while (i < resourceIds.size()) {
				StringBuilder ids = new StringBuilder();
				while (i < resourceIds.size()) {
					String part = (ids.length() == 0 ? "" : "&") + "resourceId="
							+ enc(resourceIds.get(i));
					if (ids.length() > 0 && base.length() + ids.length()
							+ part.length() + keys.length() > urlBudget) {
						break;
					}
					ids.append(part);
					i++;
				}
				paths.add(base + ids + keys);
			}
		}
		return paths;
	}

	private static String enc(String s) {
		try {
			return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
		} catch (java.io.UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
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
