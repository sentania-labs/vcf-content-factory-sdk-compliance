// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.integrien.alive.common.adapter3;

public abstract class AdapterBase {
	/** Test hook: the conf directory getAdapterDescribeFile resolves in. */
	public static volatile String testConfDir = ".";
	/** Test hook: what getMonitoringIntervalInSec returns. */
	public volatile Integer testMonitoringIntervalSec;

	public static java.nio.file.Path getAdapterDescribeFile(String kind,
			String name) {
		return java.nio.file.Paths.get(testConfDir, name);
	}

	public Integer getMonitoringIntervalInSec() {
		return testMonitoringIntervalSec;
	}

	public javax.net.ssl.TrustManager getAdapterTrustManager() {
		return null;
	}

	public javax.net.ssl.KeyManager[] getKeyManagers() {
		return null;
	}

	public boolean isDynamicMetricsAllowed() {
		return false;
	}
}
