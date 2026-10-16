package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Build 96 (issue #16, review B1): where a cycle that ended early on its
 * budget or breaker stopped, per kind, so the next cycle starts after the
 * last object it finished instead of at the top. Without it every cycle
 * would stop at the same object and the objects past it would never be
 * read again. The next cycle reads the kind in rotated order (after the
 * cursor to the end, then from the top round to the cursor); a cycle that
 * reaches every object of the kind clears the cursor. So consecutive
 * early-ended cycles together cover the whole kind. Kept in the
 * configured holder (one per instance configuration, in memory). An
 * object order changes nothing in a score: every object is scored on its
 * own, and a kind's rollup is pushed only for a cycle that read all of it.
 * SDK-free.
 */
final class ResumeCursor {

	private final Map<BenchmarkSelector.Kind, String> after =
			new EnumMap<>(BenchmarkSelector.Kind.class);

	/**
	 * {@code objects} in this cycle's order: after the cursor's object to
	 * the end, then from the top round to it. The listing order when there
	 * is no cursor or its object is gone.
	 */
	synchronized <T> List<T> order(BenchmarkSelector.Kind kind,
			List<T> objects, Function<T, String> id) {
		String c = after.get(kind);
		if (c == null || objects == null) return objects;
		int at = -1;
		for (int i = 0; i < objects.size(); i++) {
			if (c.equals(id.apply(objects.get(i)))) {
				at = i;
				break;
			}
		}
		if (at < 0) return objects;
		List<T> out = new ArrayList<>(objects.size());
		out.addAll(objects.subList(at + 1, objects.size()));
		out.addAll(objects.subList(0, at + 1));
		return out;
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
}
