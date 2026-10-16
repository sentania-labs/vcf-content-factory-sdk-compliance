package com.vcfcf.adapters.compliance;

import java.util.function.LongSupplier;

/**
 * Build 96 (issue #16, DEF-026): the per-cycle limits. A cycle ends early,
 * cleanly, when either is reached:
 *
 * <ul>
 *   <li><b>Time budget:</b> {@link #FRACTION} of the instance's collection
 *       interval (the platform's {@code getMonitoringIntervalInSec}, else
 *       the collected resource's interval, else
 *       {@link #DEFAULT_INTERVAL_SEC}; clamped to {@link #MIN_INTERVAL_SEC}
 *       to {@link #MAX_INTERVAL_SEC}). The budget is checked before each
 *       call and does not cancel a call in flight, so the worst case is
 *       the budget plus one call (30 s connect plus 120 s read): 390 s on
 *       a 5 minute interval, which is the interval plus 90 s.</li>
 *   <li><b>Consecutive-timeout breaker:</b> {@link #BREAKER_TIMEOUTS} vCenter
 *       calls in a row that timed out (connect or read), with no answer in
 *       between: the vCenter is not answering, and every further call would
 *       wait out its own timeout.</li>
 * </ul>
 *
 * Once reached, the limit stays reached for the rest of the cycle (a new
 * budget is made each cycle). The vCenter clients refuse new calls
 * ({@link Exhausted}, so what was being read is UNREADABLE, never a value)
 * and the adapter holds back the kind it was collecting and every kind not
 * yet started ({@code Rollup|incomplete} = 1, their keys keep their values),
 * then pushes the rollup as usual. SDK-free; the clock is injectable.
 */
public final class CycleBudget {

	/** Share of the collection interval a cycle may take. */
	public static final double FRACTION = 0.8;

	/** VCF Operations' default collection interval (5 minutes). */
	public static final int DEFAULT_INTERVAL_SEC = 300;

	/** A reported interval outside this range is clamped into it. */
	public static final int MIN_INTERVAL_SEC = 60;
	public static final int MAX_INTERVAL_SEC = 24 * 60 * 60;

	/** vCenter calls in a row that timed out before the cycle ends. */
	public static final int BREAKER_TIMEOUTS = 5;

	/** A call refused because the cycle's limit was reached. */
	public static final class Exhausted extends java.io.IOException {
		private static final long serialVersionUID = 1L;

		public Exhausted(String why) {
			super("cycle ended early: " + why + "; call not made");
		}
	}

	/** The interval the budget is taken from, and where it came from. */
	public static final class Interval {
		public final int seconds;
		public final String source;

		Interval(int seconds, String source) {
			this.seconds = seconds;
			this.source = source;
		}
	}

	/**
	 * The collection interval: the platform's value, else the collected
	 * resource's, else {@link #DEFAULT_INTERVAL_SEC}. A value of 0 or less
	 * counts as not reported. A reported value outside
	 * {@link #MIN_INTERVAL_SEC} to {@link #MAX_INTERVAL_SEC} is clamped
	 * into that range (review N3), and the source says so.
	 */
	public static Interval interval(Integer platformSec, Integer resourceSec) {
		if (reported(platformSec)) {
			return clamped(platformSec, "the collection interval from the "
					+ "platform");
		}
		if (reported(resourceSec)) {
			return clamped(resourceSec, "the collection interval of the "
					+ "Compliance World resource");
		}
		return new Interval(DEFAULT_INTERVAL_SEC, "the default collection "
				+ "interval (none was reported)");
	}

	private static boolean reported(Integer s) {
		return s != null && s > 0;
	}

	private static Interval clamped(int s, String source) {
		if (s < MIN_INTERVAL_SEC) {
			return new Interval(MIN_INTERVAL_SEC, source + ", " + s
					+ " s raised to the " + MIN_INTERVAL_SEC + " s minimum");
		}
		if (s > MAX_INTERVAL_SEC) {
			return new Interval(MAX_INTERVAL_SEC, source + ", " + s
					+ " s lowered to the " + MAX_INTERVAL_SEC + " s maximum");
		}
		return new Interval(s, source);
	}

	/** The cycle budget for an interval, in milliseconds. */
	public static long budgetMs(int intervalSec) {
		return Math.round(intervalSec * 1000L * FRACTION);
	}

	private final long budgetMs;
	private final int breakerLimit;
	private final LongSupplier nanoClock;
	private final long startNs;
	private int consecutiveTimeouts;
	private int timeouts;
	private int refusals;
	private String endedBecause;

	public CycleBudget(long budgetMs, int breakerLimit, LongSupplier nanoClock) {
		this.budgetMs = budgetMs;
		this.breakerLimit = breakerLimit;
		this.nanoClock = nanoClock;
		this.startNs = nanoClock.getAsLong();
	}

	public long budgetMs() {
		return budgetMs;
	}

	public long elapsedMs() {
		return (nanoClock.getAsLong() - startNs) / 1_000_000L;
	}

	/** A vCenter call timed out (connect or read). */
	public synchronized void timedOut() {
		consecutiveTimeouts++;
		timeouts++;
	}

	/** A vCenter call got an answer (any HTTP status): the run is broken. */
	public synchronized void answered() {
		consecutiveTimeouts = 0;
	}

	public synchronized int timeouts() {
		return timeouts;
	}

	/**
	 * Why the cycle must end, or null while it may go on. The first reason
	 * found is kept: once reached, a limit stays reached.
	 */
	public synchronized String exhausted() {
		if (endedBecause != null) return endedBecause;
		if (consecutiveTimeouts >= breakerLimit) {
			endedBecause = consecutiveTimeouts + " vCenter calls in a row timed "
					+ "out (breaker " + breakerLimit + ")";
		} else {
			long ms = elapsedMs();
			if (ms >= budgetMs) {
				endedBecause = "the cycle time budget of " + (budgetMs / 1000)
						+ " s was used up (" + (ms / 1000) + " s elapsed)";
			}
		}
		return endedBecause;
	}

	/**
	 * Throws {@link Exhausted} when the cycle must end, and counts the
	 * refusal ({@link #refusals}). Every client calls this before a call.
	 */
	public void check() throws Exhausted {
		String why = exhausted();
		if (why != null) {
			synchronized (this) {
				refusals++;
			}
			throw new Exhausted(why);
		}
	}

	/**
	 * Build 96 (review N2-r2): calls refused so far this cycle. The adapter
	 * compares it before and after an object: an object is cut only when a
	 * call was actually refused while it was read, not when the deadline
	 * merely passed after its last read.
	 */
	public synchronized int refusals() {
		return refusals;
	}
}
