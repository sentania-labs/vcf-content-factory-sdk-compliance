// TEST-ONLY STUB (compliance build 104, issue #17). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.vcfcf.adapter.stitch;

/** Test stub of the buildkit 1.0.24 batch push result. */
public final class SuiteApiBatchResult {
	private final int sent;
	private final int batchesOk;
	private final int batchesFailed;
	private final int fellBack;
	private final int skipped;
	private final int dropped;
	private final boolean stopped;

	SuiteApiBatchResult(int sent, int batchesOk, int batchesFailed,
			int fellBack, int skipped, int dropped, boolean stopped) {
		this.sent = sent;
		this.batchesOk = batchesOk;
		this.batchesFailed = batchesFailed;
		this.fellBack = fellBack;
		this.skipped = skipped;
		this.dropped = dropped;
		this.stopped = stopped;
	}

	public int getSent() { return sent; }
	public int getBatchesOk() { return batchesOk; }
	public int getBatchesFailed() { return batchesFailed; }
	public int getFellBack() { return fellBack; }
	public int getSkipped() { return skipped; }
	public int getDropped() { return dropped; }
	public boolean isStopped() { return stopped; }

	public boolean isClean() {
		return batchesFailed == 0 && skipped == 0 && dropped == 0 && !stopped;
	}
}
