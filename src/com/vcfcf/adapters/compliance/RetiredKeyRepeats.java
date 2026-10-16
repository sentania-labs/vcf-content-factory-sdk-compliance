package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 96 (issue #42, review W1): how many times the stale-key cleanup
 * has pushed -1 to each retired key, so the repeat stops after
 * {@link #MAX_PUSHES} pushes per key (the retirement itself counts as one).
 * The per-control alert cancels after 3 fresh non-failing samples, so 4 is
 * enough; an unbounded repeat would cost two Suite API calls per object
 * per cycle for good. In memory, one per instance configuration: after a
 * restart a held key gets at most {@link #MAX_PUSHES} more, which is
 * harmless. Keyed by the object's {@link LastBenchmarkMemory#key} (kind and
 * MOID). An object's entries are dropped for keys that are no longer
 * retired, so a later retirement counts from the start, and (review N1-r2)
 * objects that leave inventory are dropped by {@link #retain}, with the
 * same seen set as the benchmark memory. SDK-free.
 */
final class RetiredKeyRepeats {

	/** -1 pushes per retired key, the retirement included. */
	static final int MAX_PUSHES = 4;

	private final Map<String, Map<String, Integer>> byObject = new HashMap<>();

	/**
	 * The keys to push -1 on this cycle for one object: every key retired
	 * now ({@code stale}, counted as its first push), plus each key already
	 * at -1 ({@code held}) that has had fewer than {@link #MAX_PUSHES}.
	 * Records the pushes.
	 */
	synchronized Set<String> toPush(String objectKey, Set<String> stale,
			Set<String> held) {
		Map<String, Integer> prev = byObject.get(objectKey);
		Map<String, Integer> next = new HashMap<>();
		Set<String> out = new TreeSet<>();
		for (String id : stale) {
			next.put(id, 1);
			out.add(id);
		}
		for (String id : held) {
			if (next.containsKey(id)) continue;
			int n = prev == null ? 0 : prev.getOrDefault(id, 0);
			if (n < MAX_PUSHES) {
				out.add(id);
				n++;
			}
			next.put(id, n);
		}
		if (next.isEmpty()) {
			byObject.remove(objectKey);
		} else {
			byObject.put(objectKey, next);
		}
		return out;
	}

	/**
	 * Review N1-r2: forget the objects not seen this cycle, except those of
	 * a kind held back (not listed in full), exactly as
	 * {@link LastBenchmarkMemory#retain} does.
	 */
	synchronized void retain(Set<String> seenKeys,
			Set<BenchmarkSelector.Kind> heldBackKinds) {
		byObject.keySet().removeIf(k -> !seenKeys.contains(k)
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

	synchronized int size() {
		return byObject.size();
	}
}
