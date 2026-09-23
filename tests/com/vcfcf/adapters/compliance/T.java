package com.vcfcf.adapters.compliance;

/** Minimal assertion helpers for the plain-main tests (no framework). */
final class T {

	private T() {}

	static void check(boolean cond, String what) {
		if (!cond) throw new AssertionError(what);
	}

	static void eq(Object want, Object got, String what) {
		if (want == null ? got != null : !want.equals(got)) {
			throw new AssertionError(what + ": want <" + want + "> got <"
					+ got + ">");
		}
	}

	static void near(double want, Double got, String what) {
		if (got == null || Math.abs(want - got) > 1e-9) {
			throw new AssertionError(what + ": want <" + want + "> got <"
					+ got + ">");
		}
	}
}
