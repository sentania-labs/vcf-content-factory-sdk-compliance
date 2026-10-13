package com.vcfcf.adapters.compliance;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Build 90: reads the instance's overrides file from the VCF Ops central
 * configuration-file store (UI: Administration, Configuration Files,
 * Management Packs Configuration), once per cycle, and keeps the last good
 * parse. Ported from the vcommunity adapter's SolutionConfigStore.
 *
 * <p>Wire: {@code GET /api/configurations/files?path=SolutionConfig/<name>.xml}
 * through the instance's Suite API channel, raw body. The store answers a
 * file it does not have with HTTP 400 (apiErrorCode 1501), not 404 (the
 * factory's knowledge/context/investigations/vcommunity-solutionconfig-400-2026-06-16.md).
 *
 * <ul>
 *   <li><b>No name set:</b> no fetch, no overrides, status none.</li>
 *   <li><b>Absent</b> (HTTP 400 or 404): no overrides, and the last good
 *       parse is dropped. An instance that names a file the store does not
 *       have runs on the guide alone, never on a stale guess.</li>
 *   <li><b>Fetch failed</b> (any other error, or no Suite API channel): the
 *       last good parse is kept. The alert flag is raised when there is no
 *       copy in force, or after {@value #FETCH_FAILURE_ALERT_CYCLES}
 *       straight failures even with one (review of build 90, W2): a
 *       persistent 401, 403 or 5xx is not transient.</li>
 *   <li><b>Parse failed:</b> the last good parse is kept.</li>
 *   <li><b>A new name</b> starts from nothing: another file's last good
 *       parse is never applied.</li>
 * </ul>
 *
 * <p>No VCF Ops SDK dependency: the Suite API GET is passed in as a
 * {@link Fetcher}, so the tests drive the same code the adapter runs.
 */
public final class OverridesStore {

	/** The Suite API GET: path relative to the Suite API base, raw body. */
	public interface Fetcher {
		String get(String path) throws Exception;
	}

	public enum Status { NONE, OK, ABSENT, PARSE_FAILED, FETCH_FAILED }

	/**
	 * Straight fetch failures, with a copy in force, after which the alert
	 * flag is raised anyway. With no copy in force it is raised on the
	 * first failure.
	 */
	public static final int FETCH_FAILURE_ALERT_CYCLES = 3;

	/** This cycle's outcome. */
	public static final class Snapshot {
		/** The file name as configured (normalised), "" when none. */
		public final String fileName;
		public final Status status;
		/** The parse in force this cycle; null when no overrides apply. */
		public final ComplianceOverrides.Parsed parsed;
		/** When the parse in force was read; null when none. */
		public final Instant lastGood;
		/** Why it was not read this cycle (absent, parse or fetch error). */
		public final String detail;
		/**
		 * FETCH_FAILED only: the short reason for the status text, for
		 * example {@code HTTP 503}, {@code refused (HTTP 403)} or {@code no
		 * Suite API channel}. Null otherwise.
		 */
		public final String fetchReason;
		/** FETCH_FAILED only: straight fetch failures, this one included. */
		public final int fetchFailures;

		Snapshot(String fileName, Status status,
				ComplianceOverrides.Parsed parsed, Instant lastGood,
				String detail) {
			this(fileName, status, parsed, lastGood, detail, null, 0);
		}

		Snapshot(String fileName, Status status,
				ComplianceOverrides.Parsed parsed, Instant lastGood,
				String detail, String fetchReason, int fetchFailures) {
			this.fileName = fileName;
			this.status = status;
			this.parsed = parsed;
			this.lastGood = lastGood;
			this.detail = detail;
			this.fetchReason = fetchReason;
			this.fetchFailures = fetchFailures;
		}

		/**
		 * 1 (raises "Compliance overrides file not loaded") when the named
		 * file could not be loaded this cycle because the store does not
		 * have it or it does not parse, or when the fetch failed and no copy
		 * is in force, or when the fetch has failed
		 * {@value OverridesStore#FETCH_FAILURE_ALERT_CYCLES} cycles in a row
		 * even with a copy in force; 0 otherwise.
		 */
		public boolean notLoaded() {
			if (status == Status.ABSENT || status == Status.PARSE_FAILED) {
				return true;
			}
			return status == Status.FETCH_FAILED && (parsed == null
					|| fetchFailures >= FETCH_FAILURE_ALERT_CYCLES);
		}

		/**
		 * The {@code Summary|overrides_status} text: {@code none},
		 * {@code OK}, {@code N rejected}, {@code absent},
		 * {@code parse failed, last good from <local time>} (or {@code
		 * parse failed, no previous copy}), {@code fetch failed: <reason>,
		 * last good from <local time>} ({@code fetch failed N cycles:
		 * <reason>, last good from <local time>} once N reaches
		 * {@link OverridesStore#FETCH_FAILURE_ALERT_CYCLES}), or {@code fetch failed: <reason>, no copy in force}. The
		 * reason is {@code HTTP <status>}, {@code refused (HTTP 401|403)},
		 * {@code no Suite API channel}, or {@code no answer (<error>)}.
		 *
		 * @param rejected rejected entries this cycle (OK only)
		 * @param zone     the collector's time zone
		 */
		public String statusText(int rejected, ZoneId zone) {
			switch (status) {
				case NONE:
					return "none";
				case OK:
					return rejected > 0 ? rejected + " rejected" : "OK";
				case ABSENT:
					return "absent";
				case PARSE_FAILED:
					return lastGood != null
							? "parse failed, last good from "
									+ formatTime(lastGood, zone)
							: "parse failed, no previous copy";
				default:
					String reason = fetchReason != null ? fetchReason
							: "no answer";
					if (parsed == null) {
						return "fetch failed: " + reason + ", no copy in force";
					}
					return "fetch failed"
							+ (fetchFailures >= FETCH_FAILURE_ALERT_CYCLES
									? " " + fetchFailures + " cycles" : "")
							+ ": " + reason + ", last good from "
							+ formatTime(lastGood, zone);
			}
		}
	}

	private static final DateTimeFormatter TIME = DateTimeFormatter
			.ofPattern("yyyy-MM-dd HH:mm z", Locale.ROOT);

	static String formatTime(Instant t, ZoneId zone) {
		return TIME.format(t.atZone(zone == null ? ZoneId.systemDefault()
				: zone));
	}

	/** The store's "no such file" answer, as the Suite API client reports it. */
	private static final Pattern ABSENT_STATUS =
			Pattern.compile("\\bHTTP 40[04]\\b");

	/** Any HTTP status in a Suite API client error message. */
	private static final Pattern HTTP_STATUS =
			Pattern.compile("\\bHTTP (\\d{3})\\b");

	/**
	 * The short status-text reason for a failed fetch. VCF Operations
	 * answered a 401 or 403 (the channel's identity was refused, for example
	 * one without the configuration-file read privilege), so that is
	 * "refused", not "did not answer". Another HTTP status is named as is;
	 * an error without one (timeout, connection) is "no answer".
	 */
	static String fetchReason(Exception e) {
		String msg = e == null ? "" : String.valueOf(e.getMessage());
		java.util.regex.Matcher m = HTTP_STATUS.matcher(msg);
		if (m.find()) {
			String code = m.group(1);
			if ("401".equals(code) || "403".equals(code)) {
				return "refused (HTTP " + code + ")";
			}
			return "HTTP " + code;
		}
		return "no answer (" + (e == null ? "unknown error"
				: e.getClass().getSimpleName()) + ")";
	}

	private String lastName = "";
	private ComplianceOverrides.Parsed lastGood;
	private Instant lastGoodAt;
	/** Straight FETCH_FAILED cycles for the current name. */
	private int fetchFailures;

	/**
	 * The configured name without path noise: trimmed, and a trailing
	 * {@code .xml} removed (the setting is the name without extension, but
	 * a typed extension is forgiven). Null input is "".
	 */
	public static String normaliseName(String raw) {
		if (raw == null) return "";
		String n = raw.trim();
		if (n.toLowerCase(Locale.ROOT).endsWith(".xml")) {
			n = n.substring(0, n.length() - 4).trim();
		}
		return n;
	}

	/** The store path for a file name. */
	static String path(String fileName) {
		return "/api/configurations/files?path=SolutionConfig/"
				+ enc(fileName) + ".xml";
	}

	/**
	 * Fetch and parse the file for this cycle.
	 *
	 * @param rawName the instance setting as stored
	 * @param fetcher the Suite API GET; null when no channel is available
	 * @param now     this cycle's time (recorded as the last good time)
	 */
	public synchronized Snapshot refresh(String rawName, Fetcher fetcher,
			Instant now) {
		String name = normaliseName(rawName);
		if (!name.equals(lastName)) {
			lastName = name;
			lastGood = null;
			lastGoodAt = null;
			fetchFailures = 0;
		}
		if (name.isEmpty()) {
			fetchFailures = 0;
			return new Snapshot("", Status.NONE, null, null, null);
		}
		if (name.contains("/") || name.contains("\\")) {
			lastGood = null;
			lastGoodAt = null;
			fetchFailures = 0;
			return new Snapshot(name, Status.ABSENT, null, null,
					"the name must not contain a path (enter only the name "
							+ "of your copy)");
		}
		if (fetcher == null) {
			return fetchFailed(name, "no Suite API channel on this collector",
					"no Suite API channel");
		}
		String body;
		try {
			body = fetcher.get(path(name));
		} catch (Exception e) {
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			String msg = String.valueOf(e.getMessage());
			if (ABSENT_STATUS.matcher(msg).find()) {
				lastGood = null;
				lastGoodAt = null;
				fetchFailures = 0;
				return new Snapshot(name, Status.ABSENT, null, null,
						"the configuration-file store has no file named '"
								+ name + "' (" + msg + ")");
			}
			return fetchFailed(name, e.getClass().getSimpleName() + ": " + msg,
					fetchReason(e));
		}
		fetchFailures = 0;
		ComplianceOverrides.Parsed parsed;
		try {
			parsed = ComplianceOverrides.parse(body);
		} catch (ComplianceOverrides.ParseException e) {
			return keep(name, Status.PARSE_FAILED, e.getMessage());
		}
		lastGood = parsed;
		lastGoodAt = now;
		return new Snapshot(name, Status.OK, parsed, now, null);
	}

	private Snapshot keep(String name, Status status, String detail) {
		return new Snapshot(name, status, lastGood, lastGoodAt, detail);
	}

	private Snapshot fetchFailed(String name, String detail, String reason) {
		fetchFailures++;
		return new Snapshot(name, Status.FETCH_FAILED, lastGood, lastGoodAt,
				detail, reason, fetchFailures);
	}

	private static String enc(String s) {
		try {
			return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
		} catch (java.io.UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}
}
