package com.vcfcf.adapters.compliance;

/** Shared SDK-free constants (so tests need no VCF Ops SDK). */
public final class ComplianceAdapterConstants {

	private ComplianceAdapterConstants() {}

	/**
	 * Per-control {@code Compliant} value domain: 1 compliant, 0
	 * non-compliant, -1 not evaluated (unreadable this cycle, or no longer
	 * in the applied benchmark). The per-control compliance alerts fire on
	 * {@code Compliant == 0} only (owner-approved).
	 */
	public static final double COMPLIANT_NOT_EVALUATED = -1.0;
}
