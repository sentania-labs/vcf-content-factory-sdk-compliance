// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.vcfcf.adapter.stitch;

import com.integrien.alive.common.adapter3.Logger;
import com.vcfcf.adapter.VcfCfAdapter;

/**
 * Test stub: create() fails unless a test installs {@link #testFactory}
 * (the ambient Suite API credential is absent off the appliance, as on a
 * collector without it).
 */
public final class SuiteApiStitcher {
	public interface Backend {
		String get(String path) throws java.io.IOException,
				InterruptedException;
		default void pushProperties(String id,
				java.util.Map<String, String> p, long ts) {}
		default void pushStats(String id, java.util.Map<String, Double> s,
				long ts) {}
		default boolean addChild(String parent, String child) { return true; }
		default String findSingletonResourceId(String ak, String rk) {
			return null;
		}
		default void discard() {}
	}

	/** Test hook: the backend create() returns; null makes it throw. */
	public static volatile Backend testFactory;

	private final Backend b;

	private SuiteApiStitcher(Backend b) {
		this.b = b;
	}

	public static SuiteApiStitcher create(VcfCfAdapter<?> adapter,
			Logger logger) {
		Backend f = testFactory;
		if (f == null) {
			throw new IllegalStateException("no ambient Suite API credential "
					+ "(test stub)");
		}
		return new SuiteApiStitcher(f);
	}

	public String get(String path) throws java.io.IOException,
			InterruptedException {
		return b.get(path);
	}

	public void pushProperties(String id, java.util.Map<String, String> p,
			long ts) {
		b.pushProperties(id, p, ts);
	}

	public void pushStats(String id, java.util.Map<String, Double> s,
			long ts) {
		b.pushStats(id, s, ts);
	}

	public boolean addChild(String parent, String child) {
		return b.addChild(parent, child);
	}

	public String findSingletonResourceId(String ak, String rk) {
		return b.findSingletonResourceId(ak, rk);
	}

	public void discard() {
		b.discard();
	}
}
