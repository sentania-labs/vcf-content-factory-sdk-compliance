package com.vcfcf.adapters.compliance;

import java.util.function.BooleanSupplier;

/**
 * Build 95 (issue #16, first slice): cooperative stop between objects.
 *
 * <p>The framework checks its stop flag only between resources, and this
 * adapter collects everything under one resource (ComplianceWorld), so a
 * Stop Collecting used to wait for the whole vCenter walk. Every
 * per-object loop now calls {@link #check} before each object; once a stop
 * is requested the next check throws {@link InterruptedException}, the
 * cycle is abandoned within one object, and nothing more is read or
 * pushed. No time budget yet (that needs its own decision).
 *
 * <p>No SDK dependencies: the adapter supplies the flag.
 */
public final class StopCheck {

	private final BooleanSupplier stopRequested;
	private volatile String stoppedAt;

	public StopCheck(BooleanSupplier stopRequested) {
		this.stopRequested = stopRequested;
	}

	/**
	 * Throw when a stop was requested; {@code where} names the loop and
	 * object, for the abandoned-cycle log line.
	 */
	public void check(String where) throws InterruptedException {
		if (stopRequested.getAsBoolean()) {
			stoppedAt = where;
			throw new InterruptedException("Stop Collecting requested; cycle "
					+ "abandoned before " + where);
		}
	}

	/** Where the last check stopped the cycle, or null. */
	public String stoppedAt() {
		return stoppedAt;
	}
}
