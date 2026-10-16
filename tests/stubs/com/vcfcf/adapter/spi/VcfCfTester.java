// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.vcfcf.adapter.spi;

import com.integrien.alive.common.adapter3.TestParam;
import com.vcfcf.adapter.http.ManagedHttpClient;

public interface VcfCfTester<C> {
	void test(C config, ManagedHttpClient httpClient, TestParam param)
			throws Exception;
}
