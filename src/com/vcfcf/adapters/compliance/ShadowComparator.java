package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Build 95 (bulk-collection design build B, shadow mode): compares what the
 * existing per-object read path produced for each control with what the
 * bulk read path produces for the same object, for one kind in one cycle.
 * Scores, pushes and alerts come only from the per-object path; this class
 * only counts and reports.
 *
 * <p>Use: {@link #record} every per-object control result while the kind is
 * scored (only the controls the bulk path can also read: advanced settings
 * and vim properties, never esxcli or VAMI), then, page by page,
 * {@link #compare} the bulk result for each object, then {@link #finish}.
 * An object the per-object path did not score (unmatched, no benchmark,
 * wholly unreadable) has no record and is not compared. A recorded control
 * the bulk side did not produce is a disagreement ({@code (not produced)}),
 * never silently skipped.
 *
 * <p>Values compared are the per-control outcome text:
 * {@code "(unreadable)"} for an unreadable control, else the Actual value
 * followed by {@code " pass"} or {@code " fail"}, so a different value
 * with the same verdict still shows. No SDK dependencies.
 *
 * <p>Build 103 (issue #17 build 2): the bulk read is primary, so the
 * adapter records the bulk result and compares the per-object one
 * ({@link #perObjectCheck}); the labels in the lines and the summary say
 * which side is which.
 */
public final class ShadowComparator {

	/** Disagreement lines logged per kind per cycle, at most. */
	public static final int DISAGREEMENT_LOG_CAP = 25;

	/** Placeholder for a recorded control the bulk side did not produce. */
	public static final String NOT_PRODUCED = "(not produced)";

	private final String kind;
	private final int cap;
	// Build 103: the recorded side, the compared side, and where scores
	// come from, for the lines and the summary.
	private final String recordedLabel;
	private final String comparedLabel;
	private final String scoresFrom;
	// Review W5: false when shadow mode is off; nothing is recorded, so
	// nothing is held in memory and the bulk read is not made.
	private final boolean enabled;
	// moid -> (control id -> outcome), and moid -> object name.
	private final Map<String, Map<String, String>> recorded = new HashMap<>();
	private final Map<String, String> names = new HashMap<>();
	private final List<String> lines = new ArrayList<>();
	private long objectsCompared;
	private long controlsCompared;
	private long disagreements;
	private long bulkObjectsWithoutRecord;
	private String failure;

	public ShadowComparator(String kind) {
		this(kind, DISAGREEMENT_LOG_CAP, true);
	}

	/**
	 * Review W5: {@code enabled} false (shadow mode off) makes
	 * {@link #record} a no-op, so {@link #hasRecords} stays false and the
	 * caller skips the bulk read.
	 */
	public ShadowComparator(String kind, boolean enabled) {
		this(kind, DISAGREEMENT_LOG_CAP, enabled);
	}

	ShadowComparator(String kind, int cap) {
		this(kind, cap, true);
	}

	ShadowComparator(String kind, int cap, boolean enabled) {
		this(kind, cap, enabled, "per-object", "bulk",
				"scores still come from the per-object path");
	}

	private ShadowComparator(String kind, int cap, boolean enabled,
			String recordedLabel, String comparedLabel, String scoresFrom) {
		this.kind = kind;
		this.cap = cap;
		this.enabled = enabled;
		this.recordedLabel = recordedLabel;
		this.comparedLabel = comparedLabel;
		this.scoresFrom = scoresFrom;
	}

	/**
	 * Build 103: the comparator of a cycle scored from the bulk read: the
	 * bulk result is recorded, the per-object re-read compared.
	 */
	public static ShadowComparator perObjectCheck(String kind,
			boolean enabled) {
		return new ShadowComparator(kind, DISAGREEMENT_LOG_CAP, enabled,
				"bulk", "per-object", "scores come from the bulk read");
	}

	public boolean isEnabled() {
		return enabled;
	}

	/** The comparable outcome text of one control result. */
	public static String outcome(ControlEvaluator.ControlResult r) {
		if (r.unreadable) return "(unreadable)";
		return String.valueOf(r.actual) + (r.compliant ? " pass" : " fail");
	}

	/**
	 * Record the per-object results for {@code moid}, keeping only the
	 * controls in {@code comparable} (control ids the bulk path reads).
	 */
	public void record(String moid, String name,
			List<ControlEvaluator.ControlResult> results,
			java.util.Set<String> comparable) {
		if (!enabled || moid == null || results == null) return;
		Map<String, String> m = new LinkedHashMap<>();
		for (ControlEvaluator.ControlResult r : results) {
			if (comparable.contains(r.scgId)) {
				m.put(r.scgId, outcome(r));
			}
		}
		if (m.isEmpty()) return;
		recorded.put(moid, m);
		names.put(moid, name);
	}

	public boolean hasRecords() {
		return !recorded.isEmpty();
	}

	/** Whether {@code moid} has a per-object record to compare against. */
	public boolean isRecorded(String moid) {
		return moid != null && recorded.containsKey(moid);
	}

	/**
	 * Compare the bulk results for one object. The record is consumed, so
	 * an object appearing twice in the bulk pages is compared once, and
	 * {@link #finish} can report the objects the bulk pages never returned.
	 */
	public void compare(String moid,
			List<ControlEvaluator.ControlResult> bulkResults) {
		Map<String, String> want = moid == null ? null : recorded.remove(moid);
		if (want == null) {
			bulkObjectsWithoutRecord++;
			return;
		}
		Map<String, String> got = new HashMap<>();
		if (bulkResults != null) {
			for (ControlEvaluator.ControlResult r : bulkResults) {
				got.put(r.scgId, outcome(r));
			}
		}
		objectsCompared++;
		for (Map.Entry<String, String> e : want.entrySet()) {
			controlsCompared++;
			String bulk = got.getOrDefault(e.getKey(), NOT_PRODUCED);
			if (!bulk.equals(e.getValue())) {
				disagreements++;
				if (lines.size() < cap) {
					lines.add(kind + " " + names.get(moid) + " (" + moid
							+ ") " + e.getKey() + ": " + recordedLabel + " '"
							+ e.getValue() + "', " + comparedLabel + " '"
							+ bulk + "'");
				}
			}
		}
		names.remove(moid);
	}

	/** The bulk read for the kind failed; the summary says why. */
	public void fail(String reason) {
		if (failure == null) failure = reason;
	}

	public String summaryKind() { return kind; }
	public long objectsCompared() { return objectsCompared; }
	public long controlsCompared() { return controlsCompared; }
	public long disagreements() { return disagreements; }
	public long bulkObjectsWithoutRecord() { return bulkObjectsWithoutRecord; }
	public int recordedNotReturned() { return recorded.size(); }
	public String failure() { return failure; }

	/** The capped disagreement lines, then a "(+N more)" line if capped. */
	public List<String> disagreementLines() {
		List<String> out = new ArrayList<>(lines);
		if (disagreements > lines.size()) {
			out.add(kind + ": (+" + (disagreements - lines.size())
					+ " more disagreement(s) not listed)");
		}
		return out;
	}

	/**
	 * The summary with the response sizes (review W5): total bytes over
	 * the pages and the largest page, so devel can size the page size and
	 * the response cap.
	 */
	public String summary(int pages, long bulkMillis, long bytes,
			long maxPageBytes) {
		String s = summary(pages, bulkMillis);
		int at = s.lastIndexOf(" ms (");
		return s.substring(0, at) + " ms, " + bytes + " bytes, largest page "
				+ maxPageBytes + " bytes" + s.substring(at + 3);
	}

	/** The one INFO line per kind per cycle. */
	public String summary(int pages, long bulkMillis) {
		StringBuilder b = new StringBuilder();
		b.append("Bulk shadow ").append(kind).append(": ");
		if (failure != null) {
			b.append(comparedLabel).append(" read FAILED (").append(failure)
					.append("), ");
		}
		b.append(controlsCompared).append(" control(s) compared on ")
				.append(objectsCompared).append(" object(s), ")
				.append(disagreements).append(" disagreement(s); ")
				.append(recorded.size()).append(" scored object(s) not "
						+ "returned by the " + comparedLabel + " read, ")
				.append(bulkObjectsWithoutRecord).append(" " + comparedLabel
						+ " object(s) not scored " + ("bulk".equals(
								recordedLabel) ? "from the bulk read"
								: "per object") + "; ");
		if (pages >= 0) b.append(pages).append(" page(s), ");
		b.append(bulkMillis).append(" ms (").append(scoresFrom).append(")");
		return b.toString();
	}
}
