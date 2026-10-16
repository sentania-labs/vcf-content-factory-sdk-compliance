// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.integrien.alive.common.adapter3;

public class MetricData {
	public final MetricKey key;
	public final long timestamp;
	public final Double value;
	public final String text;

	public MetricData(MetricKey key, long timestamp, double value) {
		this.key = key;
		this.timestamp = timestamp;
		this.value = value;
		this.text = null;
	}

	public MetricData(MetricKey key, long timestamp, String text) {
		this.key = key;
		this.timestamp = timestamp;
		this.value = null;
		this.text = text;
	}
}
