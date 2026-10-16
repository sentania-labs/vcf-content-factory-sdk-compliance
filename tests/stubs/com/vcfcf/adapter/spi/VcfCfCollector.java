// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.vcfcf.adapter.spi;

import com.integrien.alive.common.adapter3.AdapterBase;
import com.integrien.alive.common.adapter3.MetricData;
import com.integrien.alive.common.adapter3.config.ResourceConfig;
import com.integrien.alive.common.util.CommonConstants.ResourceStatusEnum;
import com.vcfcf.adapter.http.ManagedHttpClient;

public interface VcfCfCollector<C> {
	void collect(C config, ManagedHttpClient httpClient, ResourceConfig rc,
			java.util.List<MetricData> out, AdapterBase adapter)
			throws InterruptedException, Exception;

	default ResourceStatusEnum mapCollectException(Exception e) {
		return ResourceStatusEnum.RESOURCE_STATUS_ERROR;
	}
}
