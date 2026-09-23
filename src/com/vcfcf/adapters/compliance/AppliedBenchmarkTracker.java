package com.vcfcf.adapters.compliance;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Build 58 (review W1): benchmark applied to each object, keyed
 * {@code <Kind>|<moid>}, used to decide orphan-control cleanup.
 *
 * <p>Self-healing rather than history-dependent: an object absent from the
 * tracker is a "first sight" and is cleaned against the union of every
 * bundled profile (see {@link ComplianceDecisions#orphanControlIds}). The
 * tracker is emptied on collector start (it is in-memory), on an instance
 * edit ({@link #clear()} from configure), and every
 * {@link #RESWEEP_CYCLES} cycles, so a push that failed silently (the
 * framework swallows push errors) is retried within a bounded time.
 *
 * <p>No SDK dependencies.
 */
public final class AppliedBenchmarkTracker {

	/** 24 cycles = one day at the default 60-minute interval. */
	public static final int RESWEEP_CYCLES = 24;

	private final ConcurrentHashMap<String, String> applied =
			new ConcurrentHashMap<>();
	private int cyclesSinceSweep;

	public static String key(BenchmarkSelector.Kind kind, String moid) {
		return kind.name() + "|" + moid;
	}

	/** Benchmark applied last time this object was recorded, or null. */
	public String previous(String key) {
		return key == null ? null : applied.get(key);
	}

	/** True when the object has not been recorded since the last clear. */
	public boolean firstSight(String key) {
		return key != null && !applied.containsKey(key);
	}

	/** True when this object's keys need cleanup this cycle. */
	public boolean needsCleanup(String key, String nowApplied) {
		String prev = previous(key);
		return prev == null || !prev.equals(nowApplied);
	}

	public void record(String key, String profileName) {
		if (key != null && profileName != null) applied.put(key, profileName);
	}

	/** Drop objects no longer in inventory. */
	public void retain(Set<String> seenKeys) {
		applied.keySet().retainAll(seenKeys);
	}

	public void clear() {
		applied.clear();
		cyclesSinceSweep = 0;
	}

	/**
	 * Call once at the start of every cycle. Returns true (and clears) on
	 * every {@link #RESWEEP_CYCLES}-th cycle.
	 */
	public synchronized boolean startCycle() {
		cyclesSinceSweep++;
		if (cyclesSinceSweep >= RESWEEP_CYCLES) {
			applied.clear();
			cyclesSinceSweep = 0;
			return true;
		}
		return false;
	}

	public int size() {
		return applied.size();
	}
}
