// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.integrien.alive.common.adapter3.config;

import com.integrien.alive.common.adapter3.ResourceKey;

public class ResourceConfig {
	public final ResourceKey key;
	/** Test hook: identifier and credential fields by key. */
	public final java.util.Map<String, String> testFields =
			new java.util.HashMap<>();
	/** Test hook: what getIntervalInSec returns. */
	public volatile Integer testIntervalSec;

	public ResourceConfig(ResourceKey key) {
		this.key = key;
	}

	public Integer getIntervalInSec() {
		return testIntervalSec;
	}
}
