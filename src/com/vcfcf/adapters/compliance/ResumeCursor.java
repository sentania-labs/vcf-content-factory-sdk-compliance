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
 * score: every object is scored on its own, and a kind's rollup is pushed
 * only from a cycle that read all of it (a resumed tail holds it back).
 * SDK-free.
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
		String c = after.get(kind);
		if (c == null || objects == null) return objects;
		for (int i = 0; i < objects.size(); i++) {
			if (c.equals(id.apply(objects.get(i)))) {
				return new ArrayList<>(objects.subList(i + 1, objects.size()));
			}
		}
		return objects;
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
}
