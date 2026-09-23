package com.vcfcf.adapters.compliance;

import java.util.Map;
import java.util.TreeMap;

/**
 * Build 74: why controls were unreadable this cycle. SDK-free.
 *
 * <p>Each unreadable control instance is recorded with a reason category
 * (the part of the reason before the first {@code ":"}, e.g.
 * {@code soap-fault}, {@code missing-element}, {@code esxcli-command-failed},
 * {@code esxcli-field-missing}, {@code vami-http-403},
 * {@code vami-session}, {@code host-not-connected}). The adapter logs each
 * record at DEBUG and, once per cycle at INFO, the count by category
 * ({@link #summary()}), so a broken read path is diagnosable from the log
 * instead of only from an aggregate unreadable count.
 */
public final class UnreadableReasons {

	private final Map<String, Integer> byCategory = new TreeMap<>();
	private int total;

	/** Category of a reason string: text before the first ':'. */
	public static String category(String reason) {
		if (reason == null || reason.trim().isEmpty()) return "unknown";
		String r = reason.trim();
		int c = r.indexOf(':');
		return (c > 0 ? r.substring(0, c) : r).trim();
	}

	/** Record {@code count} unreadable control instances for a reason. */
	public void record(String reason, int count) {
		if (count <= 0) return;
		byCategory.merge(category(reason), count, Integer::sum);
		total += count;
	}

	public int total() {
		return total;
	}

	/** e.g. {@code "esxcli-field-missing=9, soap-fault=3"}; "" when none. */
	public String summary() {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, Integer> e : byCategory.entrySet()) {
			if (sb.length() > 0) sb.append(", ");
			sb.append(e.getKey()).append('=').append(e.getValue());
		}
		return sb.toString();
	}

	public Map<String, Integer> byCategory() {
		return java.util.Collections.unmodifiableMap(byCategory);
	}
}
