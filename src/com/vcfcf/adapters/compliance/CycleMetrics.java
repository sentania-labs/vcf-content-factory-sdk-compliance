package com.vcfcf.adapters.compliance;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Build 95 (issue #17, bulk-collection design build A): per-phase wall time
 * and call counts for one collection cycle, appended to the cycle summary
 * log line. Measurement only: nothing here changes what is read, scored or
 * pushed.
 *
 * <p>Time is EXCLUSIVE per phase. Phases nest (a push inside the host loop,
 * an esxcli call inside a host read, an inventory listing inside a kind's
 * collector); entering an inner phase pauses the outer one, so every
 * millisecond is counted once and the phases add up to the timed part of
 * the cycle. Calls are attributed to the phase that is current when they
 * are made: a SOAP call made while a host is read counts under hosts, an
 * esxcli SOAP call under esxcli, a Suite API push under pushes.
 *
 * <p>One instance per cycle, used by the cycle's own thread; the methods
 * are synchronized only so a stray call from another thread cannot corrupt
 * the stack. No SDK dependencies.
 */
public final class CycleMetrics {

	/** The phases the summary reports, in log order. */
	public enum Phase {
		INVENTORY("inventory"),
		HOSTS("host reads"),
		VMS("VM reads"),
		NETWORK("network reads"),
		VCENTER("vCenter reads"),
		ESXCLI("esxcli"),
		PUSHES("pushes"),
		SHADOW("bulk shadow"),
		OTHER("other");

		public final String label;

		Phase(String label) {
			this.label = label;
		}
	}

	private static final class Tally {
		long nanos;
		long soap;
		long suite;
	}

	private final LongSupplier clock;
	private final Map<Phase, Tally> tallies = new EnumMap<>(Phase.class);
	private final Deque<Phase> stack = new ArrayDeque<>();
	private long sinceNs;

	public CycleMetrics() {
		this(System::nanoTime);
	}

	/** Test seam: a controllable monotonic clock in nanoseconds. */
	CycleMetrics(LongSupplier clock) {
		this.clock = clock;
		for (Phase p : Phase.values()) {
			tallies.put(p, new Tally());
		}
		stack.push(Phase.OTHER);
		sinceNs = clock.getAsLong();
	}

	/** Enter {@code phase}; pair with {@link #exit} in a finally. */
	public synchronized void enter(Phase phase) {
		charge();
		stack.push(phase);
	}

	/**
	 * Leave the current phase (it must be {@code phase}; a mismatch is
	 * ignored rather than thrown, measurement must never fail a cycle).
	 */
	public synchronized void exit(Phase phase) {
		if (stack.size() <= 1 || stack.peek() != phase) {
			return;
		}
		charge();
		stack.pop();
	}

	/** The phase calls are currently attributed to. */
	public synchronized Phase current() {
		return stack.peek();
	}

	/** One vim25 SOAP call (vCenter /sdk, esxcli included). */
	public synchronized void soapCall() {
		tallies.get(stack.peek()).soap++;
	}

	/** One Suite API call (GET or POST). */
	public synchronized void suiteCall() {
		tallies.get(stack.peek()).suite++;
	}

	/** Exclusive milliseconds spent in {@code phase} so far. */
	public synchronized long millis(Phase phase) {
		charge();
		return tallies.get(phase).nanos / 1_000_000L;
	}

	public synchronized long soapCalls(Phase phase) {
		return tallies.get(phase).soap;
	}

	public synchronized long suiteCalls(Phase phase) {
		return tallies.get(phase).suite;
	}

	public synchronized long soapCalls() {
		long n = 0;
		for (Tally t : tallies.values()) n += t.soap;
		return n;
	}

	public synchronized long suiteCalls() {
		long n = 0;
		for (Tally t : tallies.values()) n += t.suite;
		return n;
	}

	/**
	 * The text appended to the cycle summary line, e.g.
	 * {@code "timing: inventory 120 ms (6 SOAP, 7 Suite API), host reads
	 * 900 ms (84 SOAP), ...; SOAP calls 310 (esxcli 48), Suite API calls
	 * 352"}. Every phase is listed, 0 included, so lines compare cycle to
	 * cycle.
	 */
	public synchronized String summary() {
		charge();
		StringBuilder b = new StringBuilder("timing: ");
		boolean first = true;
		for (Phase p : Phase.values()) {
			Tally t = tallies.get(p);
			if (!first) b.append(", ");
			first = false;
			b.append(p.label).append(' ').append(t.nanos / 1_000_000L)
					.append(" ms (").append(t.soap).append(" SOAP, ")
					.append(t.suite).append(" Suite API)");
		}
		b.append("; SOAP calls ").append(soapCalls())
				.append(" (esxcli ").append(tallies.get(Phase.ESXCLI).soap)
				.append("), Suite API calls ").append(suiteCalls());
		return b.toString();
	}

	private void charge() {
		long now = clock.getAsLong();
		tallies.get(stack.peek()).nanos += now - sinceNs;
		sinceNs = now;
	}

	/** {@link #enter} / {@link #exit} as a try-with-resources scope. */
	public Scope scope(Phase phase) {
		enter(phase);
		return new Scope(this, phase);
	}

	/** Closes its phase; a null metrics makes every call a no-op. */
	public static final class Scope implements AutoCloseable {
		private final CycleMetrics m;
		private final Phase p;

		private Scope(CycleMetrics m, Phase p) {
			this.m = m;
			this.p = p;
		}

		@Override
		public void close() {
			if (m != null) m.exit(p);
		}
	}

	/** A scope on {@code m}, or a no-op scope when {@code m} is null. */
	public static Scope scope(CycleMetrics m, Phase phase) {
		return m == null ? new Scope(null, phase) : m.scope(phase);
	}
}
