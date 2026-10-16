package com.vcfcf.adapters.compliance;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The benchmark applied to each object last cycle, keyed
 * {@code <Kind>|<moid>} (build 59, review N3 on build 58).
 *
 * <p>Its only job is review B2's fallback: an object whose governing version
 * cannot be read this cycle is scored against the benchmark it had last
 * cycle (see {@link ComplianceDecisions#decide}). It holds no cleanup state
 * (per-control cleanup reads live values from VCF Ops every cycle, see
 * {@link ComplianceDecisions#staleZeroControls}), so nothing periodic wipes
 * it. It lives in one configuration's {@link Configured} holder, so it
 * starts empty after a collector restart (in-memory) or an instance edit
 * (a new holder, since an edit can change the vCenter or the benchmark
 * mode; build 95 review W12), and is trimmed to objects still in
 * inventory. Only kinds whose inventory was listed are trimmed: a kind held
 * back this cycle (its listing, or its VCF Ops resource list, failed) keeps
 * its entries, so its objects can still fall back next cycle (build 95,
 * external review P2).
 *
 * <p>No SDK dependencies.
 */
public final class LastBenchmarkMemory {

	private final ConcurrentHashMap<String, String> applied =
			new ConcurrentHashMap<>();

	public static String key(BenchmarkSelector.Kind kind, String moid) {
		return kind.name() + "|" + moid;
	}

	/**
	 * The benchmark last applied to the object, or null. Build 96 (review
	 * N17): not necessarily last cycle's; a held-back kind or a version
	 * that stays unreadable keeps it for several cycles.
	 */
	public String previous(String key) {
		return key == null ? null : applied.get(key);
	}

	/** Remember this cycle's benchmark; returns the previous one. */
	public String record(String key, String profileName) {
		if (key == null || profileName == null) return null;
		return applied.put(key, profileName);
	}

	/**
	 * Forget objects no longer in inventory (bounds memory). An entry is
	 * kept when its key is in {@code seenKeys}, or when its kind is in
	 * {@code heldBackKinds}: a held-back kind was not (fully) listed this
	 * cycle, so an absent key there says nothing about the object.
	 */
	public void retain(Set<String> seenKeys,
			Set<BenchmarkSelector.Kind> heldBackKinds) {
		applied.keySet().removeIf(k -> !seenKeys.contains(k)
				&& !heldBack(k, heldBackKinds));
	}

	private static boolean heldBack(String key,
			Set<BenchmarkSelector.Kind> heldBackKinds) {
		if (heldBackKinds == null) return false;
		for (BenchmarkSelector.Kind kind : heldBackKinds) {
			if (key.startsWith(kind.name() + "|")) return true;
		}
		return false;
	}

	/** Empty the memory (the tests; the adapter uses a new holder). */
	public void clear() {
		applied.clear();
	}

	public int size() {
		return applied.size();
	}
}
