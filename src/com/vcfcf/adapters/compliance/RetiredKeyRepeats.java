package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 96 (issue #42, review W1, peer review items 4 and 6): the -1
 * pushes to each retired control key, capped at {@link #MAX_PUSHES} per key
 * (the retirement itself counts as one). The per-control alert cancels
 * after 3 fresh non-failing samples, so 4 is enough; an unbounded repeat
 * would cost two Suite API calls per object per cycle for good.
 *
 * <p>Where the pushes go: the retirement (a lingering 0 or 1 set to -1)
 * comes from the stale-key cleanup's read-back ({@link #toPush}). The
 * repeats ride the object's own per-cycle push, the way a Skip in force
 * does ({@link #fold}), so they cost no extra call and are made whenever
 * the object is visited, inside the cycle budget, even on a cycle whose
 * cleanup is cut. The cleanup pushes a repeat itself only for a key the
 * object's push did not carry this cycle.
 *
 * <p>In memory, one per instance configuration: after a restart a held key
 * gets at most {@link #MAX_PUSHES} more, which is harmless. Keyed by the
 * object's {@link LastBenchmarkMemory#key} (kind and MOID). Counts are
 * dropped for keys a read-back shows are no longer retired, and for
 * objects that leave inventory ({@link #retain}, the benchmark memory's
 * seen set); a read-back that returned nothing for the object changes
 * nothing (item 6). SDK-free.
 */
final class RetiredKeyRepeats {

	/** -1 pushes per retired key, the retirement included. */
	static final int MAX_PUSHES = 4;

	private final Map<String, Map<String, Integer>> byObject = new HashMap<>();
	private final Map<String, Set<String>> foldedThisCycle = new HashMap<>();

	/** Start of a cycle: nothing folded yet. */
	synchronized void beginCycle() {
		foldedThisCycle.clear();
	}

	/**
	 * The retired keys to carry -1 for in the object's own push this cycle:
	 * known retired, fewer than {@link #MAX_PUSHES} pushes so far, and not
	 * in {@code live} (pushed with a value, or skipped, this cycle). Records
	 * the pushes.
	 */
	synchronized Set<String> fold(String objectKey, Set<String> live) {
		Set<String> out = new TreeSet<>();
		Map<String, Integer> counts = byObject.get(objectKey);
		if (counts == null) return out;
		for (Map.Entry<String, Integer> e : counts.entrySet()) {
			if (live != null && live.contains(e.getKey())) continue;
			if (e.getValue() < MAX_PUSHES) {
				out.add(e.getKey());
				e.setValue(e.getValue() + 1);
			}
		}
		if (!out.isEmpty()) {
			foldedThisCycle.computeIfAbsent(objectKey, k -> new HashSet<>())
					.addAll(out);
		}
		return out;
	}

	/**
	 * After the cleanup's read-back for one object: the keys to push -1 on
	 * now. Every key retired now ({@code stale}, counted as its first
	 * push), plus each key already at -1 ({@code held}) with fewer than
	 * {@link #MAX_PUSHES} pushes that the object's own push did not carry
	 * this cycle. Records the pushes. A key read back as neither is no
	 * longer retired and its count is dropped. {@code readBackEmpty}: the
	 * read returned no value for the object, so nothing is changed.
	 */
	synchronized Set<String> toPush(String objectKey, Set<String> stale,
			Set<String> held, boolean readBackEmpty) {
		Set<String> out = new TreeSet<>();
		if (readBackEmpty) return out;
		Map<String, Integer> prev = byObject.get(objectKey);
		Set<String> folded = foldedThisCycle.getOrDefault(objectKey,
				java.util.Collections.<String>emptySet());
		Map<String, Integer> next = new HashMap<>();
		for (String id : stale) {
			next.put(id, 1);
			out.add(id);
		}
		for (String id : held) {
			if (next.containsKey(id)) continue;
			int n = prev == null ? 0 : prev.getOrDefault(id, 0);
			if (!folded.contains(id) && n < MAX_PUSHES) {
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
