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
 *       {@link #DEFAULT_INTERVAL_SEC}), so a slow vCenter cannot hold the
 *       collector thread past the next scheduled cycle.</li>
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

	/**
	 * An interval outside this range is not believed (an unexpected unit,
	 * or an unset value), and the default is used instead.
	 */
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
	 * The collection interval: the platform's value when it is believable,
	 * else the collected resource's, else {@link #DEFAULT_INTERVAL_SEC}.
	 */
	public static Interval interval(Integer platformSec, Integer resourceSec) {
		if (sane(platformSec)) {
			return new Interval(platformSec, "the collection interval from "
					+ "the platform");
		}
		if (sane(resourceSec)) {
			return new Interval(resourceSec, "the collection interval of the "
					+ "Compliance World resource");
		}
		return new Interval(DEFAULT_INTERVAL_SEC, "the default collection "
				+ "interval (the platform did not report one"
				+ (platformSec != null ? ": it reported " + platformSec + " s"
						: "") + ")");
	}

	private static boolean sane(Integer s) {
		return s != null && s >= MIN_INTERVAL_SEC && s <= MAX_INTERVAL_SEC;
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

	/** Throws {@link Exhausted} when the cycle must end. */
	public void check() throws Exhausted {
		String why = exhausted();
		if (why != null) throw new Exhausted(why);
	}
}
