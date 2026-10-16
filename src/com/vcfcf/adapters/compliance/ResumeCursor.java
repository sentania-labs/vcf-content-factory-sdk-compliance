package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Build 96 (issue #16, review B1 and B1-r2): where a cycle that ended
 * early on its budget or breaker stopped, so the next cycle carries on
 * from there instead of starting again at the top. Without it every cycle
 * would stop at the same point and what lies past it would never be read
 * again.
 *
 * <p>One resume point across kinds: the kinds run in the fixed
 * {@link #ROUND}, and a cycle starts at the kind the last early-ended cycle
 * stopped in ({@link #round}) and wraps round to the others. Within that
 * kind it reads only the objects after the last one finished
 * ({@link #order}); reaching the end of the list finishes the kind for
 * this pass and clears its cursor, and the walk goes on to the next kind
 * (VMs after hosts). So a full pass over every object spreads over
 * consecutive cycles, and every object is read within a bounded number of
 * cycles, whatever the per-kind sizes. Kept in the configured holder (one
 * per instance configuration, in memory). The order changes nothing in a
 * score: every object is scored on its own. A kind's rollup is pushed
 * only over all of its objects: when a resumed walk finishes the kind, the
 * share read by the earlier cycles of the pass ({@link Carry}) is added;
 * when it ends early again, the kind stays held back and the share grows.
 * Each kind is walked in MOID order (peer review item 7). SDK-free.
 */
final class ResumeCursor {

	private final Map<BenchmarkSelector.Kind, String> after =
			new EnumMap<>(BenchmarkSelector.Kind.class);

	/**
	 * The objects to read this cycle: those after the cursor's object, to
	 * the end of the list (the ones before it were read earlier in this
	 * pass), or the whole list when there is no cursor or its object is
	 * gone. {@link #resumed} says which.
	 */
	synchronized <T> List<T> order(BenchmarkSelector.Kind kind,
			List<T> objects, Function<T, String> id) {
		if (objects == null) return null;
		List<T> sorted = sorted(objects, id);
		String c = after.get(kind);
		if (c == null) return sorted;
		for (int i = 0; i < sorted.size(); i++) {
			if (c.equals(id.apply(sorted.get(i)))) {
				return new ArrayList<>(sorted.subList(i + 1, sorted.size()));
			}
		}
		return sorted;
	}

	/**
	 * Peer review item 7: the walk order is by MOID (nulls last), so the
	 * cursor means the same position whatever order vCenter lists in.
	 */
	static <T> List<T> sorted(List<T> objects, Function<T, String> id) {
		List<T> out = new ArrayList<>(objects);
		out.sort(java.util.Comparator.comparing(id,
				java.util.Comparator.nullsLast(
						java.util.Comparator.<String>naturalOrder())));
		return out;
	}

	/**
	 * Whether {@link #order} returns only part of {@code objects} (a tail
	 * after the cursor), so this cycle cannot read the whole kind.
	 */
	synchronized <T> boolean resumed(BenchmarkSelector.Kind kind,
			List<T> objects, Function<T, String> id) {
		String c = after.get(kind);
		if (c == null || objects == null) return false;
		for (T o : objects) {
			if (c.equals(id.apply(o))) return true;
		}
		return false;
	}

	/**
	 * The cycle ended early in {@code kind} with {@code lastDone} the last
	 * object it finished. Null (nothing finished in this kind this cycle)
	 * leaves the cursor where it was.
	 */
	synchronized void stoppedAfter(BenchmarkSelector.Kind kind,
			String lastDone) {
		if (lastDone != null) after.put(kind, lastDone);
	}

	/** Every object of {@code kind} was read this cycle: start at the top. */
	synchronized void completed(BenchmarkSelector.Kind kind) {
		after.remove(kind);
	}

	synchronized String cursor(BenchmarkSelector.Kind kind) {
		return after.get(kind);
	}

	// ----- Build 96 review B1-r2: one resume point across kinds -----------

	/**
	 * The fixed round of kinds. A cycle starts at the kind the last
	 * early-ended cycle stopped in, carries on through the kinds after it,
	 * and wraps round to the ones before it, so no kind waits behind
	 * another one for good (VMs after a host walk that overruns, say).
	 */
	static final List<BenchmarkSelector.Kind> ROUND =
			java.util.Collections.unmodifiableList(java.util.Arrays.asList(
					BenchmarkSelector.Kind.VCENTER, BenchmarkSelector.Kind.VDS,
					BenchmarkSelector.Kind.PORTGROUP,
					BenchmarkSelector.Kind.CLUSTER, BenchmarkSelector.Kind.HOST,
					BenchmarkSelector.Kind.VM));

	private BenchmarkSelector.Kind startKind;
	private String dropped;

	/** This cycle's kinds, in order, starting at {@link #startKind}. */
	synchronized List<BenchmarkSelector.Kind> round() {
		int at = startKind == null ? 0 : ROUND.indexOf(startKind);
		if (at < 0) at = 0;
		List<BenchmarkSelector.Kind> out = new ArrayList<>(ROUND.size());
		out.addAll(ROUND.subList(at, ROUND.size()));
		out.addAll(ROUND.subList(0, at));
		return out;
	}

	/**
	 * Where the next cycle starts: the kind this cycle ended early in, or
	 * null (the top of the round) after a cycle that read everything.
	 */
	synchronized void startAt(BenchmarkSelector.Kind kind) {
		startKind = kind;
	}

	synchronized BenchmarkSelector.Kind startKind() {
		return startKind;
	}

	/**
	 * The object ({@code KIND|moid}) the last cycle dropped because the
	 * limit was reached while it was read, or null. A second drop in a row
	 * of the same object pushes it flagged instead and steps past it.
	 */
	synchronized String dropped() {
		return dropped;
	}

	synchronized void dropped(String objectKey) {
		dropped = objectKey;
	}

	synchronized void clearDropped() {
		dropped = null;
	}

	// ----- Build 96 (peer review item 3): the pass carried across cycles --

	/**
	 * What the cycles of the current pass that ended early in a kind read
	 * of it: its rollup share and the objects seen. When a later cycle
	 * reads the rest of the kind, both are added, so the kind's rollup
	 * covers every object (read across those cycles) and is pushed, and
	 * the benchmark memory is trimmed against every object seen.
	 */
	static final class Carry {
		final ComplianceRollup.Part part;
		final java.util.Set<String> seen;

		Carry(ComplianceRollup.Part part, java.util.Set<String> seen) {
			this.part = part;
			this.seen = java.util.Collections.unmodifiableSet(
					new java.util.HashSet<>(seen));
		}
	}

	private final Map<BenchmarkSelector.Kind, Carry> carry =
			new EnumMap<>(BenchmarkSelector.Kind.class);

	synchronized Carry carry(BenchmarkSelector.Kind kind) {
		return carry.get(kind);
	}

	synchronized void carry(BenchmarkSelector.Kind kind, Carry c) {
		if (c == null) {
			carry.remove(kind);
		} else {
			carry.put(kind, c);
		}
	}
}
