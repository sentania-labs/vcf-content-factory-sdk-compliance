package com.vcfcf.adapters.compliance;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One configuration of an adapter instance (build 95, review W12): the
 * account, every client built from it, and the state a cycle hands to the
 * next cycle (the benchmark applied to each object, the vCenter object last
 * resolved, the one-shot zero of the retired Custom rollup bucket).
 *
 * <p>{@code configureAdapter} builds a new one, with fresh state, and
 * publishes it with one volatile write; each cycle copies that one
 * reference at its start and reads and writes only through the copy. A
 * cycle still running across an instance edit therefore keeps the old
 * account and clients to its end and refills only the old holder's state,
 * which nothing reads again. The next cycle starts on the new holder, so
 * it cannot inherit the old vCenter's benchmarks or resource id, and no
 * cycle can copy the new account with the old clients.
 *
 * <p>Generic over the two Suite API types ({@code S} the Suite API client,
 * {@code T} the stitcher) only so this class needs no VCF Ops SDK and the
 * plain-main tests can exercise it. Either may be null (no ambient Suite
 * API credentials on this collector).
 */
final class Configured<S, T> {

	final ComplianceConfig account;
	final VSphereClient vsphere;
	final BenchmarkLoader loader;
	final S suite;
	final T stitcher;
	/** Benchmark applied to each object by this configuration's cycles. */
	final LastBenchmarkMemory memory = new LastBenchmarkMemory();
	// Build 96 (issue #16, review B1): where an early-ended cycle stopped,
	// per kind, so the next one resumes after it.
	final ResumeCursor resume = new ResumeCursor();
	// Build 96 (issue #42, review W1): the capped -1 repeats per retired key.
	final RetiredKeyRepeats retiredRepeats = new RetiredKeyRepeats();
	// Build 96 (peer review item 4): stale-key cleanup entries a cycle that
	// ended early could not run, for the start of the next cycle (the
	// adapter's own PendingCleanup type, held as Object here).
	final java.util.List<Object> deferredCleanup =
			java.util.Collections.synchronizedList(new java.util.ArrayList<>());
	private final AtomicReference<String> vcResourceId =
			new AtomicReference<>();
	private final AtomicBoolean zeroCustomBucket;

	Configured(ComplianceConfig account, VSphereClient vsphere,
			BenchmarkLoader loader, S suite, T stitcher,
			boolean zeroCustomBucket) {
		this.account = account;
		this.vsphere = vsphere;
		this.loader = loader;
		this.suite = suite;
		this.stitcher = stitcher;
		this.zeroCustomBucket = new AtomicBoolean(zeroCustomBucket);
	}

	/**
	 * This instance's vCenter object as resolved by the last cycle of this
	 * configuration that reached vCenter; null before any did.
	 */
	String lastVcResourceId() {
		return vcResourceId.get();
	}

	void rememberVcResourceId(String id) {
		vcResourceId.set(id);
	}

	/** True until the retired Custom bucket has been zeroed once. */
	boolean zeroCustomBucketPending() {
		return zeroCustomBucket.get();
	}

	void customBucketZeroed() {
		zeroCustomBucket.set(false);
	}
}
