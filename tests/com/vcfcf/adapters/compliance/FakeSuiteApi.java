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
	/**
	 * Build 96 (Codex P2 on PR #57): what VCF Ops holds, resource id ->
	 * stat key -> {value, timestamp}: every successful pushStats lands
	 * here, and /api/resources/stats/latest answers from it (with the
	 * timestamps), unless {@link #answer} answers first.
	 */
	final Map<String, Map<String, List<double[]>>> store = new LinkedHashMap<>();
	/** While true, pushes are recorded as attempts but do not land. */
	volatile boolean failPushes;

	void seed(String rid, String key, double value, long ts) {
		synchronized (store) {
			store.computeIfAbsent(rid, k -> new LinkedHashMap<>())
					.computeIfAbsent(key, k -> new ArrayList<>())
					.add(new double[] {value, ts});
		}
	}

	Double stored(String rid, String key) {
		synchronized (store) {
			Map<String, List<double[]>> m = store.get(rid);
			List<double[]> v = m == null ? null : m.get(key);
			return v == null || v.isEmpty() ? null : v.get(v.size() - 1)[0];
		}
	}

	private String latestFromStore(String path) {
		List<String> rids = new ArrayList<>();
		List<String> keys = new ArrayList<>();
		int max = 1;
		for (String part : path.substring(path.indexOf('?') + 1).split("&")) {
			int eq = part.indexOf('=');
			if (eq < 0) continue;
			String v;
			try {
				v = java.net.URLDecoder.decode(part.substring(eq + 1), "UTF-8");
			} catch (java.io.UnsupportedEncodingException e) {
				throw new IllegalStateException(e);
			}
			if (part.startsWith("resourceId=")) rids.add(v);
			if (part.startsWith("statKey=")) keys.add(v);
			if (part.startsWith("maxSamples=")) max = Integer.parseInt(v);
		}
		StringBuilder b = new StringBuilder("{\"values\":[");
		boolean firstRid = true;
		synchronized (store) {
			for (String rid : rids) {
				Map<String, List<double[]>> m = store.get(rid);
				if (m == null) continue;
				StringBuilder stats = new StringBuilder();
				for (String k : keys) {
					List<double[]> all = m.get(k);
					if (all == null || all.isEmpty()) continue;
					List<double[]> v = all.subList(Math.max(0,
							all.size() - max), all.size());
					StringBuilder t = new StringBuilder();
					StringBuilder d = new StringBuilder();
					for (double[] x : v) {
						if (t.length() > 0) {
							t.append(',');
							d.append(',');
						}
						t.append((long) x[1]);
						d.append(x[0]);
					}
					if (stats.length() > 0) stats.append(',');
					stats.append("{\"timestamps\":[").append(t)
							.append("],\"statKey\":{\"key\":\"").append(k)
							.append("\"},\"data\":[").append(d).append("]}");
				}
				if (!firstRid) b.append(',');
				firstRid = false;
				b.append("{\"resourceId\":\"").append(rid)
						.append("\",\"stat-list\":{\"stat\":[").append(stats)
						.append("]}}");
			}
		}
		return b.append("]}").toString();
	}
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
		if (path.startsWith("/api/resources/stats/latest")) {
			return latestFromStore(path);
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
		if (failPushes) return;   // logged and swallowed, as the framework does
		for (Map.Entry<String, Double> e : s.entrySet()) {
			seed(id, e.getKey(), e.getValue(), ts);
		}
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
