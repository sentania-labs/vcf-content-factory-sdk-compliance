// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.integrien.alive.common.adapter3;

import com.integrien.alive.common.adapter3.config.ResourceIdentifierConfig;

public class ResourceKey {
	public final String name;
	public final String resourceKind;
	public final String adapterKind;
	public final java.util.List<ResourceIdentifierConfig> identifiers =
			new java.util.ArrayList<>();

	public ResourceKey(String name, String resourceKind, String adapterKind) {
		this.name = name;
		this.resourceKind = resourceKind;
		this.adapterKind = adapterKind;
	}

	public boolean addIdentifier(ResourceIdentifierConfig id) {
		return identifiers.add(id);
	}
}
