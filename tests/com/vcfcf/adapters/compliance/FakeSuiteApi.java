package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Build 96 (issue #27): a fake of the three Suite API calls the stitcher
 * makes ({@link ComplianceStitcher.SuiteApi}). GET answers come from
 * {@link #bodies} (first key contained in the path wins) or {@link #answer};
 * pushes are recorded.
 */
final class FakeSuiteApi implements ComplianceStitcher.SuiteApi {

	/** A GET answer: a body, or a thrown exception. */
	interface Answer {
		String get(String path) throws java.io.IOException,
				InterruptedException;
	}

	static final class Push {
		final String resourceId;
		final Map<String, String> props;
		final Map<String, Double> stats;

		Push(String resourceId, Map<String, String> props,
				Map<String, Double> stats) {
			this.resourceId = resourceId;
			this.props = props;
			this.stats = stats;
		}
	}

	static final String EMPTY =
			"{\"pageInfo\":{\"totalCount\":0},\"resourceList\":[]}";

	final Map<String, String> bodies = new LinkedHashMap<>();
	volatile Answer answer;
	final List<String> gets = Collections.synchronizedList(new ArrayList<>());
	final List<Push> pushes = Collections.synchronizedList(new ArrayList<>());

	@Override
	public String get(String path) throws java.io.IOException,
			InterruptedException {
		gets.add(path);
		Answer a = answer;
		if (a != null) {
			String r = a.get(path);
			if (r != null) return r;
		}
		for (Map.Entry<String, String> e : bodies.entrySet()) {
			if (path.contains(e.getKey())) return e.getValue();
		}
		return EMPTY;
	}

	@Override
	public void pushProperties(String id, Map<String, String> p, long ts) {
		pushes.add(new Push(id, new LinkedHashMap<>(p), null));
	}

	@Override
	public void pushStats(String id, Map<String, Double> s, long ts) {
		pushes.add(new Push(id, null, new LinkedHashMap<>(s)));
	}

	/** Every stat pushed to {@code id}, merged in push order. */
	Map<String, Double> statsFor(String id) {
		Map<String, Double> out = new LinkedHashMap<>();
		synchronized (pushes) {
			for (Push p : pushes) {
				if (p.stats != null && p.resourceId.equals(id)) {
					out.putAll(p.stats);
				}
			}
		}
		return out;
	}

	/** One VMWARE resource row of /api/resources (vim25-backed kind). */
	static String row(String id, String name, String moid, String vcUuid) {
		return "{\"identifier\":\"" + id + "\",\"resourceKey\":{\"name\":\""
				+ name + "\",\"resourceIdentifiers\":["
				+ "{\"identifierType\":{\"name\":\"VMEntityName\"},\"value\":\""
				+ name + "\"},"
				+ "{\"identifierType\":{\"name\":\"VMEntityObjectID\"},"
				+ "\"value\":\"" + moid + "\"},"
				+ "{\"identifierType\":{\"name\":\"VMEntityVCID\"},\"value\":\""
				+ vcUuid + "\"}]}}";
	}

	/** One page of /api/resources. */
	static String page(long totalCount, String... rows) {
		return "{\"pageInfo\":{\"totalCount\":" + totalCount + "},"
				+ "\"resourceList\":[" + String.join(",", rows) + "]}";
	}
}
