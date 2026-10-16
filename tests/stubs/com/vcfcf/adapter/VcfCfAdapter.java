// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.vcfcf.adapter;

import com.integrien.alive.common.adapter3.AdapterBase;
import com.integrien.alive.common.adapter3.Logger;
import com.integrien.alive.common.adapter3.ResourceStatus;
import com.integrien.alive.common.adapter3.config.ResourceConfig;
import com.vcfcf.adapter.spi.ResourceSink;
import com.vcfcf.adapter.spi.VcfCfCollector;
import com.vcfcf.adapter.spi.VcfCfTester;

public abstract class VcfCfAdapter<C> extends AdapterBase {
	/** Test hook: every logInfo / logWarn / logError line, with its level. */
	public final java.util.List<String> testLog =
			java.util.Collections.synchronizedList(new java.util.ArrayList<>());
	/** Test hook: what isAbortRequested returns. */
	public volatile boolean testAbort;

	protected VcfCfAdapter(String adapterKindKey) {
	}

	protected VcfCfAdapter(String adapterKindKey, String adapterDir,
			Integer adapterInstanceId) {
	}

	protected abstract void configureAdapter(ResourceStatus status,
			ResourceConfig rc);

	protected abstract VcfCfTester<C> getTester();

	protected abstract VcfCfCollector<C> getCollector();

	protected boolean discoverOnCollect() {
		return false;
	}

	protected void enumerateResources(ResourceSink sink)
			throws InterruptedException, Exception {
	}

	protected java.util.List<String> certificateCheckUrls(ResourceConfig rc) {
		return java.util.Collections.emptyList();
	}

	public void onDiscard() {
	}

	protected String getCredentialField(ResourceConfig rc, String key) {
		return rc == null ? null : rc.testFields.get(key);
	}

	protected String getIdentifier(ResourceConfig rc, String key) {
		return rc == null ? null : rc.testFields.get(key);
	}

	protected boolean isAbortRequested() {
		return testAbort;
	}

	protected Logger componentLogger(Class<?> component) {
		return new Logger(component.getSimpleName());
	}

	protected void logInfo(String message) {
		testLog.add("INFO " + message);
	}

	protected void logWarn(String message) {
		testLog.add("WARN " + message);
	}

	protected void logWarn(String message, Throwable t) {
		testLog.add("WARN " + message);
	}

	protected void logError(String message, Throwable t) {
		testLog.add("ERROR " + message);
	}
}
