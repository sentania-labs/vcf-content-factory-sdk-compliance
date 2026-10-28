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
 *   <li>{@link #linkWorld}: whether and where this instance links its own
 *       vCenter object under ComplianceWorld (build 82; no cross-cycle
 *       cache since build 83).</li>
 *   <li>{@link #markNotCollected}: where a cycle that could not reach
 *       vCenter marks the rollup incomplete (build 93, review W1).</li>
 * </ul>
 */
public final class ComplianceDecisions {

	/**
	 * Build 95 (issue #25): the HTTP Basic Authorization header value for
	 * the vCenter REST and VAMI sessions, with the credential encoded as
	 * UTF-8 explicitly (as the SOAP login sends it). The platform default
	 * charset is not UTF-8 on every collector, and a non-ASCII password then
	 * failed Test Connection and the appliance reads while SOAP worked.
	 */
	public static String basicAuthorization(String username, String password) {
		return "Basic " + java.util.Base64.getEncoder().encodeToString(
				(username + ":" + password).getBytes(
						java.nio.charset.StandardCharsets.UTF_8));
	}


	private ComplianceDecisions() {}

	static final String K = "VCF-CF Compliance|";

	/**
	 * Build 95 (Scott 2026-10-14): 1 when some control of the object could
	 * not be read this cycle, else 0; pushed on every object every cycle.
	 * The "Compliance data not collected" alerts fire on it.
	 */
	public static final String HAS_UNREADABLE = K + "has_unreadable";
	/** Build 95: why, in plain words plus the logged detail (property). */
	public static final String UNREADABLE_REASON = K + "unreadable_reason";
	/** Build 95: the unreadable control ids, capped (property). */
	public static final String UNREADABLE_CONTROLS = K + "unreadable_controls";
	/**
	 * Build 95: the object's kind in words (property), pushed with every
	 * object payload, so the "Objects with unreadable controls" list (one
	 * view over six VMWARE kinds) can show what each row is.
	 */
	public static final String OBJECT_KIND = K + "object_kind";

	/** Build 95: the object_kind text for a kind. */
	public static String objectKindLabel(BenchmarkSelector.Kind kind) {
		if (kind == null) return "";
		switch (kind) {
			case HOST: return "ESX host";
			case VM: return "VM";
			case VCENTER: return "vCenter";
			case CLUSTER: return "Cluster";
			case VDS: return "Distributed switch";
			case PORTGROUP: return "Distributed portgroup";
			default: return kind.rollupName;
		}
	}

	/** Build 95: {@code props} with {@link #OBJECT_KIND} added (a copy). */
	public static Map<String, String> withObjectKind(Map<String, String> props,
			BenchmarkSelector.Kind kind) {
		Map<String, String> out = new LinkedHashMap<>(props);
		if (kind != null) out.put(OBJECT_KIND, objectKindLabel(kind));
		return out;
	}

	// ----- benchmark decision --------------------------------------------

	public enum Outcome { SCORE, NO_BENCHMARK, VERSION_UNREADABLE }

	/** The benchmark decision for one object this cycle. */
	public static final class Decision {
		public final Outcome outcome;
		public final BenchmarkProfile profile;     // SCORE only
		public final String profileName;           // pushed as profile_name
		public final String bucket;                // rollup benchmark bucket
		public final boolean reusedPrevious;       // SCORE via the last benchmark applied

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
	 * Build 95: true when nothing on the object could be read this cycle:
	 * controls were attempted and every one was unreadable (a host vCenter
	 * reports not responding, a whole read channel refused). Such an object
	 * pushes only its unreadable signals ({@link #complianceStats}).
	 */
	public static boolean nothingReadable(ControlEvaluator.ComplianceResult cr) {
		return cr.totalCount == 0 && cr.unreadableCount > 0;
	}

	/**
	 * Stats for an evaluated object. Score (build 95, decision point 7):
	 * passed over evaluated, over what was read; an unreadable control is
	 * in neither count ({@link ControlEvaluator#score}). Pushed whenever at
	 * least one control was read, never as a stand-in. non_compliant is a
	 * failing control that was read. pass_count / fail_count /
	 * unreadable_count are pushed and stay separate.
	 *
	 * <p>Build 95 (Scott 2026-10-14): {@link #HAS_UNREADABLE} is pushed every
	 * cycle (1 with any unreadable control). An object with nothing
	 * readable ({@link #nothingReadable}) pushes only its unreadable signals
	 * (has_unreadable, unreadable_count, collection_failed): no score, no
	 * pass / fail / total, no non_compliant, so its last read values stay as
	 * they were and the flag says they are not current.
	 */
	public static Map<String, Double> complianceStats(
			ControlEvaluator.ComplianceResult cr) {
		Map<String, Double> stats = new LinkedHashMap<>();
		if (nothingReadable(cr)) {
			stats.put(HAS_UNREADABLE, 1.0);
			stats.put(K + "unreadable_count", (double) cr.unreadableCount);
			stats.put(K + "collection_failed", 1.0);
			return stats;
		}
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			// Build 95 (Scott 2026-10-14, "if we have missing data we just
			// don't log it"): a control that could not be read this cycle
			// is not pushed at all, for every cause (a host vCenter reports
			// not responding included). Its last value, and any alert on
			// it, stay as they were; the object's has_unreadable flag says
			// the data is not current. Before build 95 it was pushed as -1.
			if (ctrl.unreadable) continue;
			stats.put(K + ctrl.scgId + "|Compliant",
					ctrl.compliant ? 1.0 : 0.0);
		}
		if (cr.totalCount > 0) {
			stats.put(K + "score", cr.score);
		}
		stats.put(K + "pass_count", (double) cr.passCount);
		stats.put(K + "fail_count", (double) cr.failCount);
		stats.put(K + "total_count", (double) cr.totalCount);
		stats.put(K + "unreadable_count", (double) cr.unreadableCount);
		stats.put(K + "non_compliant", ComplianceRollup.isNonCompliant(
				cr.failCount) ? 1.0 : 0.0);
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "collection_failed", collectionFailed(cr) ? 1.0 : 0.0);
		stats.put(HAS_UNREADABLE, cr.unreadableCount > 0 ? 1.0 : 0.0);
		return stats;
	}

	/** Build 95: the ids of the controls a result could not read. */
	public static Set<String> unreadableIds(ControlEvaluator.ComplianceResult cr) {
		Set<String> out = new TreeSet<>();
		if (cr == null) return out;
		for (ControlEvaluator.ControlResult r : cr.controlResults) {
			if (r.unreadable) out.add(r.scgId);
		}
		return out;
	}

	/**
	 * Build 95: the two unreadable properties of an object:
	 * {@link #UNREADABLE_REASON} and {@link #UNREADABLE_CONTROLS}. Both
	 * are pushed every cycle, "" when every control was read, so a reason
	 * from an earlier cycle never lingers.
	 */
	public static Map<String, String> unreadableProps(String reason,
			String controls) {
		Map<String, String> props = new LinkedHashMap<>();
		props.put(UNREADABLE_REASON, reason == null ? "" : reason);
		props.put(UNREADABLE_CONTROLS, controls == null ? "" : controls);
		return props;
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
		return complianceProps(cr, profileName,
				java.util.Collections.<String>emptySet());
	}

	/** Build 90: the suffix that marks an expected value from the overrides file. */
	public static final String SITE_OVERRIDE = " (site override)";

	/**
	 * Properties for an evaluated object. Build 90: for a control in
	 * {@code siteOverridden} (its expected value comes from the overrides
	 * file) Expected reads {@code "<v> (site override)"} and a read Actual
	 * reads {@code "<actual>, expected <v> (site override)"}, so the object
	 * and the published guide never silently disagree. Build 95: an
	 * unreadable control is left out entirely (its keys keep their last
	 * values).
	 */
	public static Map<String, String> complianceProps(
			ControlEvaluator.ComplianceResult cr, String profileName,
			Set<String> siteOverridden) {
		return complianceProps(cr, profileName, siteOverridden, null);
	}

	/**
	 * Build 95: as {@link #complianceProps(ControlEvaluator.ComplianceResult,
	 * String, Set)}, with the object's unreadable_reason ({@code reason};
	 * null: from the count alone, see {@link ObjectUnreadable#reasonText})
	 * and unreadable_controls. An object with nothing readable
	 * ({@link #nothingReadable}) pushes those two properties only.
	 */
	public static Map<String, String> complianceProps(
			ControlEvaluator.ComplianceResult cr, String profileName,
			Set<String> siteOverridden, String reason) {
		String why = cr.unreadableCount == 0 ? ""
				: (reason != null && !reason.isEmpty() ? reason
						: new ObjectUnreadable().reasonText(cr.unreadableCount));
		Map<String, String> unread = unreadableProps(why,
				ObjectUnreadable.controlsText(unreadableIds(cr)));
		if (nothingReadable(cr)) {
			return unread;
		}
		Map<String, String> props = new LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			// Build 95: an unreadable control's Actual, Expected and
			// Description are not pushed, so its last read Actual is not
			// overwritten with "(unreadable)" (see complianceStats).
			if (ctrl.unreadable) continue;
			String base = K + ctrl.scgId;
			boolean site = siteOverridden != null
					&& siteOverridden.contains(ctrl.scgId);
			String actual = ctrl.actual;
			String expected = ctrl.expected;
			if (site) {
				actual = actual + ", expected " + expected + SITE_OVERRIDE;
				expected = expected + SITE_OVERRIDE;
			}
			props.put(base + "|Actual", actual);
			props.put(base + "|Expected", expected);
			props.put(base + "|Description", ctrl.description);
		}
		props.put(K + "profile_name", profileName);
		props.putAll(unread);
		return props;
	}

	/** A readable version with no SCG: flagged, counters zeroed (W2). */
	public static Map<String, Double> noBenchmarkStats() {
		Map<String, Double> stats = zeroCounters();
		stats.put(K + "no_benchmark", 1.0);
		stats.put(K + "non_compliant", 0.0);
		stats.put(K + "collection_failed", 0.0);
		stats.put(HAS_UNREADABLE, 0.0);
		return stats;
	}

	/** A benchmark with nothing evaluable (e.g. non-vSAN cluster) (W2). */
	public static Map<String, Double> nothingEvaluatedStats() {
		Map<String, Double> stats = zeroCounters();
		stats.put(K + "no_benchmark", 0.0);
		stats.put(K + "non_compliant", 0.0);
		stats.put(K + "collection_failed", 0.0);
		stats.put(HAS_UNREADABLE, 0.0);
		return stats;
	}

	/**
	 * Governing version unreadable and no previous benchmark (build 58 B2,
	 * build 65 W1): nothing could be collected. Build 95 (Scott
	 * 2026-10-14): nothing readable pushes only the unreadable signals,
	 * has_unreadable = 1 and collection_failed = 1 (no score 0, no
	 * counters, no non_compliant; the last read values stay as they were).
	 * unreadable_count is NOT pushed: the adapter does not know which
	 * benchmark's controls apply, so it will not invent a count.
	 */
	public static Map<String, Double> versionUnreadableStats() {
		Map<String, Double> stats = new LinkedHashMap<>();
		stats.put(HAS_UNREADABLE, 1.0);
		stats.put(K + "collection_failed", 1.0);
		return stats;
	}

	/**
	 * Build 95: the properties of a version-unreadable object: its reason
	 * ("product version unreadable" and the label the selector gave, e.g.
	 * "benchmark unknown: ESX version unreadable") and, since the benchmark
	 * and so its controls are unknown, a plain statement in place of ids.
	 */
	public static Map<String, String> versionUnreadableProps(String label) {
		ObjectUnreadable u = new ObjectUnreadable();
		u.record("version-unreadable: " + label, 1);
		return unreadableProps(u.reasonText(1), VERSION_UNREADABLE_CONTROLS);
	}

	/** Build 95: unreadable_controls of a version-unreadable object. */
	public static final String VERSION_UNREADABLE_CONTROLS =
			"(not known: the benchmark depends on the version)";

	/**
	 * Build 96 (issue #16, peer review item 2): an object cut by the cycle
	 * budget two cycles in a row. Only the markers are pushed:
	 * has_unreadable = 1 (Not Read) and the reason; no score, no counters,
	 * no per-control value, so nothing from a partial read is shown (its
	 * last values stay). The walk then moves past it.
	 */
	public static Map<String, Double> cutTwiceStats() {
		Map<String, Double> stats = new LinkedHashMap<>();
		stats.put(HAS_UNREADABLE, 1.0);
		return stats;
	}

	/** Build 96: the reason text of an object cut twice. */
	public static final String CUT_TWICE_REASON = "cut by cycle budget twice";

	public static Map<String, String> cutTwiceProps() {
		return unreadableProps(CUT_TWICE_REASON + " (not read in full on two "
				+ "cycles in a row; the values shown are from its last full "
				+ "read)", "(not known: " + CUT_TWICE_REASON + ")");
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
	 * Build 90: the cleanup plan with the overrides file's skipped controls
	 * added. A skipped control is not evaluated, so like a control of the
	 * current benchmark that was not pushed, any lingering 0 OR 1 on it is
	 * set to -1 (a skipped control that was passing must not keep showing
	 * 1). Only a skipped control that some bundled profile evaluates for the
	 * kind (or the base plan already queries) is affected; a key the object
	 * never had is still never created.
	 */
	public static CleanupPlan cleanupPlan(BenchmarkSelector.Kind kind,
			BenchmarkProfile current, Set<String> pushed,
			Collection<BenchmarkProfile> allBundled, Set<String> skipped) {
		CleanupPlan base = cleanupPlan(kind, current, pushed, allBundled);
		if (skipped == null || skipped.isEmpty()) return base;
		Set<String> zeroOrOne = new TreeSet<>(base.zeroOrOne);
		Set<String> zeroOnly = new TreeSet<>(base.zeroOnly);
		for (String id : skipped) {
			if (pushed != null && pushed.contains(id)) continue;
			if (zeroOnly.remove(id)) zeroOrOne.add(id);
		}
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

	/**
	 * Build 96 (issue #42, DEF-025): the retired controls to push -1 again
	 * this cycle on one object: every control of {@code plan} (outside the
	 * object's benchmark, or in it but not applicable) whose latest value
	 * in VCF Ops is already -1. {@link #staleControls} sets a lingering 0
	 * (or 1) to -1 once; the per-control symptom needs its cancel cycles
	 * of fresh non-triggering samples before an open alert cancels, so a
	 * single -1 left the alert open (the shape of issue #41). The adapter
	 * pushes -1 again on later cycles while the control stays retired, up
	 * to {@link RetiredKeyRepeats#MAX_PUSHES} pushes per key in all
	 * (review W1; the alert needs 3 fresh samples). A key the object never had is absent from
	 * {@code latest} and is never created; {@code latest} null (the read
	 * failed) means nothing this cycle. Never a score change: a -1 key is
	 * outside every score and count.
	 */
	public static Set<String> heldNotEvaluatedControls(CleanupPlan plan,
			Map<String, Double> latest) {
		Set<String> out = new TreeSet<>();
		if (latest == null || plan == null) return out;
		for (Map.Entry<String, Double> e : latest.entrySet()) {
			Double v = e.getValue();
			if (v == null
					|| v != ComplianceAdapterConstants.COMPLIANT_NOT_EVALUATED) {
				continue;
			}
			String id = e.getKey();
			if (plan.zeroOrOne.contains(id) || plan.zeroOnly.contains(id)) {
				out.add(id);
			}
		}
		return out;
	}

	/**
	 * Build 88 (review W2): what to do after one /api/resources page.
	 * Build 96 (issue #52): {@link #EMPTY_UNCONFIRMED}, a valid but empty
	 * list for a kind whose last complete list had objects; held back like
	 * {@link #INCOMPLETE} for one cycle (see {@link #resourcePageOutcome(
	 * boolean, Long, int, int, int, int, boolean)}).
	 */
	public enum ResourcePage { COMPLETE, NEXT_PAGE, INCOMPLETE, EMPTY_UNCONFIRMED }

	/** Build 88 (review W2): page size requested from /api/resources. */
	public static final int RESOURCE_PAGE_SIZE = 10000;

	/** Build 88 (review W2): pages read at most per kind per cycle. */
	public static final int MAX_RESOURCE_PAGES = 20;

	/**
	 * Build 88 (review W2): whether a VCF Ops resource list read so far is
	 * the whole list. Since build 88 an object missing from the list is
	 * unmatched and leaves the totals, so a list that parsed but is short
	 * must hold the kind back (INCOMPLETE), never pass as complete.
	 *
	 * @param hasList      the page carried a {@code resourceList} array
	 * @param totalCount   {@code pageInfo.totalCount}, null when absent
	 * @param collected    rows read so far, this page included
	 * @param rowsThisPage rows on this page
	 * @param pageIndex    0-based index of the page just read
	 */
	public static ResourcePage resourcePageOutcome(boolean hasList,
			Long totalCount, int collected, int rowsThisPage, int pageIndex) {
		if (!hasList) {
			// No resourceList: complete only when the page says the list is
			// genuinely empty and nothing came before it.
			return totalCount != null && totalCount == 0 && collected == 0
					? ResourcePage.COMPLETE : ResourcePage.INCOMPLETE;
		}
		if (totalCount == null || collected >= totalCount) {
			// No pageInfo: one unpaged list, taken as returned.
			return ResourcePage.COMPLETE;
		}
		if (rowsThisPage == 0 || pageIndex + 1 >= MAX_RESOURCE_PAGES) {
			return ResourcePage.INCOMPLETE;   // short, and no way to finish
		}
		return ResourcePage.NEXT_PAGE;
	}

	/**
	 * Build 96 (issue #52): {@link #resourcePageOutcome(boolean, Long, int,
	 * int, int)} with the kind's history. A list that reads as complete with
	 * no rows (a 200 with an empty {@code resourceList} and a total of 0, or
	 * no list and a total of 0) is not taken as "no objects of this kind"
	 * when the kind's last complete list had objects: every object would
	 * then count as unmatched, the kind's numbers would drop to 0, and
	 * {@code Rollup|incomplete} would stay 0. It is
	 * {@link ResourcePage#EMPTY_UNCONFIRMED} instead, which the caller holds
	 * back like {@link ResourcePage#INCOMPLETE} (Rollup|incomplete = 1, the
	 * kind's keys keep their values). The next cycle's empty list is then
	 * accepted: a kind empty two cycles in a row is genuinely empty (its
	 * last objects were removed).
	 *
	 * @param previousCount rows in the kind's last complete list (0 when
	 *                      none was read since the instance was configured)
	 * @param emptyHeldBack the kind's previous read was an
	 *                      {@code EMPTY_UNCONFIRMED} empty list
	 */
	public static ResourcePage resourcePageOutcome(boolean hasList,
			Long totalCount, int collected, int rowsThisPage, int pageIndex,
			int previousCount, boolean emptyHeldBack) {
		ResourcePage r = resourcePageOutcome(hasList, totalCount, collected,
				rowsThisPage, pageIndex);
		if (r == ResourcePage.COMPLETE && collected == 0 && previousCount > 0
				&& !emptyHeldBack) {
			return ResourcePage.EMPTY_UNCONFIRMED;
		}
		return r;
	}

	/**
	 * Build 88: a vSphere Pod VM, by its configured guest id
	 * ({@code config.guestId}, read in the bulk VM enumeration). vSphere
	 * Pods run in a CRX (Container Runtime Executive) VM whose guest id
	 * starts with {@code crx}: {@code crxPod1Guest} (guest full name "VMware
	 * CRX Pod 1 (64-bit)", seen on devel Pods) and {@code crxSys1Guest} (named
	 * in the build 88 design). No vendor list of every CRX guest id was
	 * found, so any id starting with {@code crx}, in any case, is a Pod. A
	 * null or unread guest id is not a Pod (the VM is handled as a VM).
	 */
	public static boolean isPodGuestId(String guestId) {
		return guestId != null
				&& guestId.trim().toLowerCase(java.util.Locale.ROOT)
						.startsWith("crx");
	}

	/**
	 * Build 88: whether objects of one kind can be pushed to this cycle.
	 * False with no Suite API stitcher, or when the VCF Ops resource list
	 * for the kind could not be read; the caller then skips the kind and
	 * marks it incomplete (keys held back) rather than reporting every
	 * object as unmatched.
	 */
	public static boolean kindPushable(boolean stitcherPresent,
			boolean resourceListFailed) {
		return stitcherPresent && !resourceListFailed;
	}

	/** Build 95 review N5: an inventory listing that may fail. */
	public interface Lister<T> {
		java.util.List<T> list() throws Exception;
	}

	/**
	 * Build 95 (issue #18), made SDK-free by review N5: list one kind's
	 * inventory; when the listing fails, report it ({@code onFailure}),
	 * hold the kind back ({@link ComplianceRollup#markIncomplete}: its
	 * rollup keys, All and Benchmark keep their values and
	 * Rollup|incomplete = 1) and return null, so the caller skips the kind
	 * and the cycle goes on with the others. Never an empty list on a
	 * failure: an empty inventory would read as "nothing to score".
	 */
	public static <T> java.util.List<T> listOrHoldBack(Lister<T> lister,
			ComplianceRollup rollup, BenchmarkSelector.Kind kind,
			java.util.function.Consumer<Exception> onFailure) {
		try {
			return lister.list();
		} catch (Exception e) {
			onFailure.accept(e);
			rollup.markIncomplete(kind);
			return null;
		}
	}

	/**
	 * Build 95 review N4: the line a cycle logs when it ends, or null when
	 * nothing more is to be logged. An abandoned cycle (Stop Collecting)
	 * logs one WARN: where it stopped, what that leaves behind, and the
	 * cycle's timing summary (the per-phase time and call counts that
	 * sizing a cycle budget needs, issue #16), and no second "failed"
	 * line. A completed cycle logs its time at INFO; any other failure
	 * one WARN (the exception itself is logged by onCollect).
	 * {@code metricsSummary} may be null.
	 */
	public static String cycleEndLine(boolean completed, String abandonedAt,
			long ms, String metricsSummary) {
		if (abandonedAt != null) {
			return "ComplianceAdapter cycle abandoned after " + ms + " ms: "
					+ abandonedAt + ". Nothing more was read or pushed this "
					+ "cycle (the per-vCenter rollup included); the values "
					+ "already pushed stay, the rest keep their last values."
					+ (metricsSummary != null ? " " + metricsSummary : "");
		}
		if (completed) {
			return "ComplianceAdapter cycle took " + ms + " ms";
		}
		return "ComplianceAdapter cycle failed after " + ms + " ms (the "
				+ "exception is logged by onCollect)";
	}

	/**
	 * Build 87: the per-host score line is INFO when the host has any
	 * unreadable control (so a partly unreadable host is named at INFO),
	 * DEBUG when every control was read.
	 */
	public static boolean hostScoreLineAtInfo(int unreadableCount) {
		return unreadableCount > 0;
	}

	/**
	 * Control ids the stale-key cleanup must leave alone for one object:
	 * every control with a result this cycle. Build 95: that includes an
	 * unreadable control, which is not pushed but is held at its last
	 * value on purpose; the cleanup must not retire it to -1 either (a
	 * control of the current benchmark missing from this set would be).
	 */
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
	/**
	 * Build 96: samples per key in the stale-key read-back: enough to see
	 * every -1 the capped repeat pushes (one per cycle at most).
	 */
	public static final int LATEST_SAMPLES = RetiredKeyRepeats.MAX_PUSHES + 1;

	public static java.util.List<String> latestCompliantPaths(
			java.util.List<String> resourceIds, Set<String> controlIds,
			int urlBudget) {
		java.util.List<String> paths = new java.util.ArrayList<>();
		if (resourceIds.isEmpty() || controlIds.isEmpty()) return paths;
		// Build 96 (Codex P2 on PR #57): the last LATEST_SAMPLES samples
		// (with their timestamps), so the capped -1 repeats can be counted
		// only once they show as landed. The latest value is taken at the
		// newest timestamp, whatever order the samples come in.
		String base = "/api/resources/stats/latest?maxSamples="
				+ LATEST_SAMPLES + "&";
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
		return orphanProps(ids, appliedName,
				java.util.Collections.<String>emptySet(), null);
	}

	/**
	 * Build 90: as {@link #orphanProps(Set, String)}, but a control the
	 * overrides file skips reads {@code "(skipped by override file <name>)"}.
	 */
	public static Map<String, String> orphanProps(Set<String> ids,
			String appliedName, Set<String> skipped, String overridesFile) {
		Map<String, String> props = new LinkedHashMap<>();
		for (String id : ids) {
			boolean skip = skipped != null && skipped.contains(id);
			props.put(K + id + "|Actual", skip
					? "(skipped by override file " + overridesFile + ")"
					: "(not in applied benchmark: " + appliedName + ")");
		}
		return props;
	}

	// ----- Skip in force, pushed every cycle (build 92) --------------------

	/**
	 * Build 92 (adapter issue #41): what to push for one object's skipped
	 * controls this cycle. Build 90/91 sent a skipped control through the
	 * stale-key cleanup, which reads the latest value back and pushes -1
	 * only over a 0 or a 1: the first cycle pushed -1 once, every later
	 * cycle read -1 and pushed nothing, and a symptom on the key never saw
	 * its cancel cycles, so the open alert stayed active. A Skip in force is
	 * now pushed every cycle, -1 and the skip Actual text, with no read-back,
	 * exactly like a scored control.
	 *
	 * <p>The ids are the skipped controls the object's benchmark evaluates
	 * for its kind, taken from the benchmark BEFORE the overrides file was
	 * applied (the Skip removes the control from the adjusted one). A Skip
	 * of a control only another SCG version carries is not in force on this
	 * object and pushes nothing here.
	 */
	public static final class SkipPush {
		public final Set<String> ids;
		public final Map<String, Double> stats;
		public final Map<String, String> props;
		/**
		 * Build 96 (Codex P2 on PR #57): the timestamp the object's push
		 * must carry when retired-key repeats ride it (null: the caller's
		 * own), so the read-back can match the landed samples exactly.
		 */
		public final Long pushTimestamp;

		SkipPush(Set<String> ids, String overridesFile) {
			this.ids = java.util.Collections.unmodifiableSet(ids);
			this.stats = java.util.Collections.unmodifiableMap(
					orphanStats(ids));
			this.props = java.util.Collections.unmodifiableMap(
					orphanProps(ids, null, ids, overridesFile));
			this.pushTimestamp = null;
		}

		private SkipPush(Set<String> ids, Map<String, Double> stats,
				Map<String, String> props, Long pushTimestamp) {
			this.ids = java.util.Collections.unmodifiableSet(ids);
			this.stats = java.util.Collections.unmodifiableMap(stats);
			this.props = java.util.Collections.unmodifiableMap(props);
			this.pushTimestamp = pushTimestamp;
		}

		/**
		 * Build 96 (issue #42, peer review item 4): this Skip payload plus
		 * -1 and the "(not in applied benchmark: ...)" Actual for the
		 * retired keys whose repeat rides the object's push this cycle
		 * ({@code retired}; none of them is live or skipped). {@code skip}
		 * may be null.
		 */
		public static SkipPush withRetired(SkipPush skip, Set<String> retired,
				String appliedName, long pushTimestamp) {
			if (retired == null || retired.isEmpty()) return skip;
			Set<String> ids = new TreeSet<>(retired);
			Map<String, Double> stats = new LinkedHashMap<>(orphanStats(retired));
			Map<String, String> props = new LinkedHashMap<>(
					orphanProps(retired, appliedName));
			if (skip != null) {
				ids.addAll(skip.ids);
				stats.putAll(skip.stats);
				props.putAll(skip.props);
			}
			return new SkipPush(ids, stats, props, pushTimestamp);
		}

		public boolean isEmpty() {
			return ids.isEmpty();
		}
	}

	/**
	 * @param kind          the object's kind
	 * @param unadjusted    the object's benchmark before the overrides file
	 *                      (null: no benchmark, nothing to push)
	 * @param skipped       the resolved Skip ids for this cycle
	 * @param overridesFile the instance's Overrides file name, for the text
	 */
	public static SkipPush skipPush(BenchmarkSelector.Kind kind,
			BenchmarkProfile unadjusted, Set<String> skipped,
			String overridesFile) {
		Set<String> ids = new TreeSet<>();
		if (unadjusted != null && skipped != null && !skipped.isEmpty()) {
			addEvaluated(ids, kind, unadjusted);
			ids.retainAll(skipped);
		}
		return new SkipPush(ids, overridesFile);
	}

	/**
	 * Build 92 review W3: where one object's per-cycle push goes. The
	 * adapter's {@link ComplianceStitcher} in production; a counting sink in
	 * the tests, which cannot load the SDK.
	 */
	public interface PushSink {
		void pushProperties(String resourceId, Map<String, String> properties,
				long timestamp);
		void pushStats(String resourceId, Map<String, Double> stats,
				long timestamp);
	}

	/**
	 * Build 92 review W3: send one object's per-cycle payload with its
	 * skipped controls in force ({@link #skipPush}) merged in, as ONE
	 * properties call and ONE stats call. Before this the Skip went out in a
	 * second pair of Suite API calls per object per cycle (one VM Skip on a
	 * 5,000-VM vCenter: about 10,000 extra POSTs every cycle). A skipped
	 * control is not in the adjusted benchmark, so its keys never collide
	 * with a scored control's.
	 *
	 * @param skip null or empty: the payload is sent unchanged
	 */
	public static void pushObject(PushSink sink, String resourceId,
			Map<String, String> props, Map<String, Double> stats,
			SkipPush skip, long timestamp) {
		Map<String, String> p = props;
		Map<String, Double> s = stats;
		if (skip != null && !skip.isEmpty()) {
			p = new LinkedHashMap<>(props);
			p.putAll(skip.props);
			s = new LinkedHashMap<>(stats);
			s.putAll(skip.stats);
		}
		long ts = skip != null && skip.pushTimestamp != null
				? skip.pushTimestamp : timestamp;
		sink.pushProperties(resourceId, p, ts);
		sink.pushStats(resourceId, s, ts);
	}

	// ----- overrides file status (build 90) --------------------------------

	/** Build 90: the overrides keys, under {@code Summary|}. */
	public static final String OVR_FILE = "Summary|overrides_file";
	public static final String OVR_STATUS = "Summary|overrides_status";
	public static final String OVR_SKIPPED = "Summary|overrides_skipped";
	public static final String OVR_OVERRIDDEN = "Summary|overrides_overridden";
	public static final String OVR_NOT_LOADED = "Summary|overrides_not_loaded";

	/**
	 * Build 90: the overrides status properties. {@code prefix} is "" on
	 * the pack's Compliance World and {@code "VCF-CF Compliance|"} on the
	 * vCenter object. Pushed every cycle, "none" and 0 included, so a
	 * removed file never leaves an old status behind.
	 */
	public static Map<String, String> overridesProps(String prefix,
			String fileName, String statusText) {
		Map<String, String> props = new LinkedHashMap<>();
		props.put(prefix + OVR_FILE, fileName == null ? "" : fileName);
		props.put(prefix + OVR_STATUS, statusText);
		return props;
	}

	/** Build 90: the overrides counts and the not-loaded flag. */
	public static Map<String, Double> overridesStats(String prefix,
			int skipped, int overridden, boolean notLoaded) {
		Map<String, Double> stats = new LinkedHashMap<>();
		stats.put(prefix + OVR_SKIPPED, (double) skipped);
		stats.put(prefix + OVR_OVERRIDDEN, (double) overridden);
		stats.put(prefix + OVR_NOT_LOADED, notLoaded ? 1.0 : 0.0);
		return stats;
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

	// ----- ComplianceWorld to vCenter relationship (build 82) -------------

	/** Outcome of one cycle's ComplianceWorld to vCenter link attempt. */
	public enum LinkOutcome {
		/**
		 * addChild returned true: the Suite API accepted the request. The
		 * add is asynchronous, so this is "requested and accepted", not
		 * "linked"; only a children readback proves the edge.
		 */
		ACCEPTED,
		/** This instance's own vCenter object was not resolved: skipped. */
		NO_VCENTER,
		/** The ComplianceWorld id lookup found no single match: skipped. */
		NO_WORLD,
		/** addChild returned false: retried next cycle with a fresh lookup. */
		ADD_FAILED
	}

	/** The link outcome plus the world id this cycle used. */
	public static final class WorldLink {
		public final LinkOutcome outcome;
		/** World id that was used, or null when none was resolved. */
		public final String worldId;

		WorldLink(LinkOutcome outcome, String worldId) {
			this.outcome = outcome;
			this.worldId = worldId;
		}
	}

	/**
	 * Decide this cycle's ComplianceWorld (parent) to VMwareAdapter Instance
	 * (child) link. Only this instance's own vCenter object is ever passed
	 * in; nothing else is linked.
	 *
	 * <p>Build 83 (review of build 82, W2): nothing is cached between
	 * cycles. The add is asynchronous, so a POST to a deleted world's id
	 * can be accepted and then dropped, and a cache cleared only on a
	 * failed add would keep the stale id forever. The world is looked up
	 * every cycle instead (one local GET).
	 *
	 * <ul>
	 *   <li>No vCenter object: skip, no lookup.</li>
	 *   <li>{@code findWorld} null (zero or ambiguous matches, normal on
	 *       the first cycle): skip.</li>
	 *   <li>Otherwise {@code addChild(world, vCenter)}: ACCEPTED or
	 *       ADD_FAILED.</li>
	 * </ul>
	 *
	 * @param vcResourceId this instance's own VMwareAdapter Instance id
	 * @param findWorld the singleton lookup (null on no single match)
	 * @param addChild the additive relationship call (parent, child)
	 */
	public static WorldLink linkWorld(String vcResourceId,
			java.util.function.Supplier<String> findWorld,
			java.util.function.BiPredicate<String, String> addChild) {
		if (vcResourceId == null || vcResourceId.trim().isEmpty()) {
			return new WorldLink(LinkOutcome.NO_VCENTER, null);
		}
		String worldId = findWorld.get();
		if (worldId == null || worldId.trim().isEmpty()) {
			return new WorldLink(LinkOutcome.NO_WORLD, null);
		}
		if (addChild.test(worldId, vcResourceId)) {
			return new WorldLink(LinkOutcome.ACCEPTED, worldId);
		}
		return new WorldLink(LinkOutcome.ADD_FAILED, worldId);
	}

	// ----- Cycle that could not reach vCenter (build 93, review W1) -------

	/**
	 * The one stat a cycle that failed before any read pushes on the
	 * vCenter object: {@code Rollup|incomplete} = 1. It raises "Compliance
	 * data not collected (vCenter)" (symptom
	 * {@code vcfcf_compliance_collection_vcenter_rollup_incomplete}), so the
	 * last scores are not shown as current with no signal. Nothing else is
	 * pushed: a count the adapter could not take is not a 0. The next
	 * complete cycle pushes 0 with the full rollup.
	 */
	public static Map<String, Double> notCollectedStats() {
		Map<String, Double> m = new LinkedHashMap<>();
		m.put(ComplianceRollup.INCOMPLETE_KEY, 1.0);
		return m;
	}

	/**
	 * Push {@link #notCollectedStats} onto this instance's own vCenter
	 * object without vCenter: the id resolved by the last cycle that
	 * reached vCenter since the instance was configured, else
	 * {@code resolveByHost} (the VMWARE vCenter object whose VCURL is the
	 * entered host exactly, the only match possible with no vCenter UUID;
	 * see {@link #matchVCenter}). Never another vCenter's object.
	 *
	 * @return the resource id pushed to, or null when none was resolved
	 *         (nothing pushed)
	 */
	public static String markNotCollected(String lastResolvedId,
			java.util.function.Supplier<String> resolveByHost,
			java.util.function.BiConsumer<String, Map<String, Double>> push) {
		return markNotCollected(lastResolvedId, id -> null, resolveByHost,
				push);
	}

	/**
	 * Build 104 review N3: as above, but the cached id is first checked
	 * against the current VMwareAdapter Instance list ({@code listed}: TRUE,
	 * FALSE, or null when the list could not be read). An id the list no
	 * longer has is not used (a batch push to it would be dropped without
	 * an error); the entered host is resolved instead. Unknown keeps the
	 * cached id, as before.
	 */
	public static String markNotCollected(String lastResolvedId,
			java.util.function.Function<String, Boolean> listed,
			java.util.function.Supplier<String> resolveByHost,
			java.util.function.BiConsumer<String, Map<String, Double>> push) {
		String id = lastResolvedId;
		if (id != null && !id.trim().isEmpty()
				&& Boolean.FALSE.equals(listed.apply(id))) {
			id = null;
		}
		if (id == null || id.trim().isEmpty()) {
			id = resolveByHost.get();
		}
		if (id == null || id.trim().isEmpty()) {
			return null;
		}
		push.accept(id, notCollectedStats());
		return id;
	}
}
