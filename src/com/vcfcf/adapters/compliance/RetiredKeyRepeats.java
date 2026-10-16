package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 96 (issue #42, review W1, peer review items 4 and 6, Codex P2 on
 * PR #57): the -1 samples that reached each retired control key, capped at
 * {@link #MAX_PUSHES} per key (the retirement itself counts as one). The
 * per-control alert cancels after 3 fresh non-failing samples, so 4 is
 * enough; an unbounded repeat would cost two Suite API calls per object
 * per cycle for good.
 *
 * <p>Where the pushes go: the retirement (a lingering 0 or 1 set to -1)
 * comes from the stale-key cleanup's read-back ({@link #toPush}). The
 * repeats ride the object's own per-cycle push, the way a Skip in force
 * does ({@link #fold}), so they cost no extra call and are made whenever
 * the object is visited, inside the cycle budget. The cleanup pushes a
 * repeat itself only for a key the object's push did not carry this
 * cycle.
 *
 * <p>Only a sample that landed counts. The Suite API pushes log and
 * swallow their failures, so a push is recorded as pending (its
 * timestamp, which the push carries) and counted when a later read-back
 * returns a sample with that timestamp (the read-back asks for the last
 * {@link ComplianceDecisions#LATEST_SAMPLES} samples). A pending push that a read-back in a
 * later cycle still does not show is taken as failed and dropped, so a
 * transient push failure costs no attempt. Until a read-back confirms
 * them, pending pushes count toward the cap (so a push not yet ingested
 * is not repeated beyond it).
 *
 * <p>In memory, one per instance configuration: after a restart a held key
 * gets at most {@link #MAX_PUSHES} more, which is harmless. Keyed by the
 * object's {@link LastBenchmarkMemory#key} (kind and MOID). Entries are
 * dropped for keys a read-back shows are no longer retired, and for
 * objects that leave inventory ({@link #retain}, the benchmark memory's
 * seen set); a read-back that returned nothing for the object changes
 * nothing. SDK-free.
 */
final class RetiredKeyRepeats {

	/** -1 samples per retired key, the retirement included. */
	static final int MAX_PUSHES = 4;

	private static final class Pending {
		final long ts;
		final long cycle;

		Pending(long ts, long cycle) {
			this.ts = ts;
			this.cycle = cycle;
		}
	}

	private static final class Entry {
		int confirmed;
		final List<Pending> pending = new ArrayList<>();

		int used() {
			return confirmed + pending.size();
		}
	}

	private final Map<String, Map<String, Entry>> byObject = new HashMap<>();
	private final Map<String, Set<String>> foldedThisCycle = new HashMap<>();
	private long cycle;

	/** Start of a cycle: nothing folded yet. */
	synchronized void beginCycle() {
		foldedThisCycle.clear();
		cycle++;
	}

	/**
	 * The retired keys to carry -1 for in the object's own push this cycle
	 * (at {@code ts}): known retired, fewer than {@link #MAX_PUSHES} samples
	 * landed or pending, and not in {@code live} (pushed with a value, or
	 * skipped, this cycle). Records them as pending.
	 */
	synchronized Set<String> fold(String objectKey, Set<String> live,
			long ts) {
		Set<String> out = new TreeSet<>();
		Map<String, Entry> entries = byObject.get(objectKey);
		if (entries == null) return out;
		for (Map.Entry<String, Entry> e : entries.entrySet()) {
			if (live != null && live.contains(e.getKey())) continue;
			if (e.getValue().used() < MAX_PUSHES) {
				out.add(e.getKey());
				e.getValue().pending.add(new Pending(ts, cycle));
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
	 * now (at {@code ts}). First, pending pushes are settled against the
	 * read-back's sample times ({@code sampleTimes}, key to the times of
	 * the samples returned): one among them landed and counts; one from an
	 * earlier cycle that is not is dropped (failed). Then:
	 * every key retired now ({@code stale}) is pushed, as a fresh first
	 * sample; each key already at -1 ({@code held}) is pushed if it has
	 * fewer than {@link #MAX_PUSHES} samples landed or pending and the
	 * object's own push did not carry it this cycle. A key read back as
	 * neither is no longer retired and is forgotten. {@code readBackEmpty}:
	 * the read returned no value for the object, so nothing is changed.
	 */
	synchronized Set<String> toPush(String objectKey, Set<String> stale,
			Set<String> held, boolean readBackEmpty,
			Map<String, Set<Long>> sampleTimes, long ts) {
		Set<String> out = new TreeSet<>();
		if (readBackEmpty) return out;
		Map<String, Entry> prev = byObject.get(objectKey);
		Set<String> folded = foldedThisCycle.getOrDefault(objectKey,
				java.util.Collections.<String>emptySet());
		Map<String, Entry> next = new HashMap<>();
		for (String id : stale) {
			Entry e = new Entry();
			e.pending.add(new Pending(ts, cycle));
			next.put(id, e);
			out.add(id);
		}
		for (String id : held) {
			if (next.containsKey(id)) continue;
			Entry e = prev == null ? null : prev.get(id);
			if (e == null) e = new Entry();
			settle(e, sampleTimes == null ? null : sampleTimes.get(id));
			if (!folded.contains(id) && e.used() < MAX_PUSHES) {
				e.pending.add(new Pending(ts, cycle));
				out.add(id);
			}
			next.put(id, e);
		}
		if (next.isEmpty()) {
			byObject.remove(objectKey);
		} else {
			byObject.put(objectKey, next);
		}
		return out;
	}

	/**
	 * Settle pending pushes against the sample times the read-back
	 * returned (the last {@link ComplianceDecisions#LATEST_SAMPLES}): a
	 * pending push with a sample at its exact time (the
	 * object's push carries the time recorded at the fold) landed and
	 * counts. One not
	 * among them is dropped as failed if it is from an earlier cycle, and
	 * kept if it is from this cycle (not ingested yet).
	 */
	private void settle(Entry e, Set<Long> samples) {
		Iterator<Pending> it = e.pending.iterator();
		while (it.hasNext()) {
			Pending p = it.next();
			if (landed(p.ts, samples)) {
				e.confirmed++;
				it.remove();
			} else if (p.cycle < cycle) {
				it.remove();   // pushed in an earlier cycle, never landed
			}
		}
	}

	private static boolean landed(long ts, Set<Long> samples) {
		return samples != null && samples.contains(ts);
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

	/** Test view: samples confirmed landed for one key. */
	synchronized int confirmed(String objectKey, String id) {
		Map<String, Entry> m = byObject.get(objectKey);
		Entry e = m == null ? null : m.get(id);
		return e == null ? 0 : e.confirmed;
	}
}
