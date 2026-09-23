package com.vcfcf.adapters.compliance;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads a normalized benchmark profile from the canonical CSV schema.
 *
 * <p>The loader is strictly header-aware. The previous loader used
 * positional indexing ({@code fields[6]} / {@code [9]} / {@code [11]})
 * tuned for VMware SCG 8.0's column order. SCG 9.0 reordered the
 * source CSV: every rule read garbage values, producing zero matching
 * controls per host and a sentinel score of 100. Re-introducing
 * positional indexing here would re-introduce that failure mode, so
 * this loader only accepts the canonical schema (see
 * CANONICAL_SCHEMA.md). Source benchmarks must be
 * normalized first by the Python scripts under {@code scripts/}.
 *
 * <p>If any required column is missing the loader throws — the
 * adapter wraps that into a {@code CollectionException} so the
 * adapter status goes Down with an actionable message instead of
 * silently producing a wrong score.
 */
public final class BenchmarkLoader {

	/** Required header columns in the canonical CSV. */
	static final List<String> REQUIRED_COLUMNS = Arrays.asList(
			"control_id",
			"priority",
			"resource_kind",
			"adapter_kind",
			"parameter",
			"parameter_kind",
			"value_type",
			"expected_value",
			"title",
			"description",
			"source_ref",
			"remediation_text"
	);

	/**
	 * Canonical column 13 — {@code read_recipe}. Optional by contract
	 * (see CANONICAL_SCHEMA.md): a CSV without it still loads, and every
	 * vim_property control then reads as non-evaluable / informational.
	 * Kept out of {@link #REQUIRED_COLUMNS} so older bundled or custom
	 * CSVs do not hard-fail the loader. When the header IS present, the
	 * loader populates it by name like every other column.
	 */
	static final String READ_RECIPE_COLUMN = "read_recipe";

	/**
	 * Every bundled profile name, oldest SCG first. v3 (build 57) loads
	 * all of them once for "Auto (by version)" mode and selects one per
	 * object; the fixed choices force one of them for every object.
	 */
	public static final List<String> BUNDLED_PROFILES = Arrays.asList(
			"VMware_SCG_6.7",
			"VMware_SCG_7.0",
			"VMware_SCG_8.0",
			"VMware_SCG_9.0",
			"VMware_SCG_9.1"
	);

	/**
	 * v3 manual-review overlay, relative to the pak's {@code profiles/}
	 * directory. Columns {@code profile,control_id,reason}. Each row demotes
	 * one control of one BUNDLED profile to non-evaluable (see
	 * {@link BenchmarkProfile.Control#asManualReview()}). Custom profiles
	 * are never overlaid: their author owns their expected values.
	 */
	static final String MANUAL_REVIEW_FILE = "manual_review.csv";

	private volatile BenchmarkProfile cachedProfile;
	private volatile String cachedProfileKey;

	private volatile Map<String, BenchmarkProfile> cachedAll;
	private volatile String cachedAllKey;

	// Overlay rows applied by the most recent load (diagnostics only).
	private volatile int lastManualReviewApplied;

	/**
	 * Load every bundled profile (Auto mode). Cached per confDir; the
	 * returned map is keyed by profile name in {@link #BUNDLED_PROFILES}
	 * order. Any profile that fails to load throws: Auto mode never runs on
	 * a partial benchmark set, because an object whose SCG failed to load
	 * would otherwise fall into "no benchmark" and hide the broken install.
	 */
	public Map<String, BenchmarkProfile> loadAll(String confDir) {
		String key = String.valueOf(confDir);
		Map<String, BenchmarkProfile> all = cachedAll;
		if (all != null && key.equals(cachedAllKey)) {
			return all;
		}
		Map<String, java.util.Set<String>> overlay = loadManualReview(confDir);
		Map<String, BenchmarkProfile> out = new java.util.LinkedHashMap<>();
		int applied = 0;
		for (String name : BUNDLED_PROFILES) {
			BenchmarkProfile p = loadBundled(name, confDir, overlay);
			applied += countManualReview(p);
			out.put(name, p);
		}
		all = java.util.Collections.unmodifiableMap(out);
		cachedAll = all;
		cachedAllKey = key;
		lastManualReviewApplied = applied;
		return all;
	}

	/** Overlay rows applied by the most recent load call. */
	public int lastManualReviewApplied() {
		return lastManualReviewApplied;
	}

	public BenchmarkProfile load(String profileName, String customPath,
			String confDir) {
		String key = profileName + "|" + customPath + "|" + confDir;
		if (cachedProfile != null && key.equals(cachedProfileKey)) {
			return cachedProfile;
		}

		BenchmarkProfile profile;
		if ("Custom".equalsIgnoreCase(profileName) && customPath != null
				&& !customPath.isEmpty()) {
			List<String> lines = readFile(Paths.get(customPath));
			profile = new BenchmarkProfile("Custom",
					parseCanonical(lines, customPath));
			lastManualReviewApplied = 0;
		} else {
			String resolvedName = resolveBundledProfileName(profileName);
			profile = loadBundled(resolvedName, confDir,
					loadManualReview(confDir));
			lastManualReviewApplied = countManualReview(profile);
		}
		cachedProfile = profile;
		cachedProfileKey = key;
		return profile;
	}

	/** Load one bundled profile by resolved name and apply the overlay. */
	private BenchmarkProfile loadBundled(String resolvedName, String confDir,
			Map<String, java.util.Set<String>> overlay) {
		String filename = bundledFilename(resolvedName);
		List<String> lines;
		String sourceForErrors;
		Path readFrom = locateBundled(filename, confDir);
		if (readFrom != null) {
			lines = readFile(readFrom);
			sourceForErrors = readFrom.toString();
		} else {
			// Fall back to classpath only as a last resort; in
			// production the file is always present under confDir.
			InputStream is = getClass().getResourceAsStream(
					"/profiles/canonical/" + filename);
			if (is == null) {
				throw new RuntimeException(
						"Canonical profile not found: " + filename
						+ " (looked under confDir=" + confDir
						+ " and classpath /profiles/canonical/)");
			}
			lines = readStream(is);
			sourceForErrors = "classpath:/profiles/canonical/" + filename;
		}
		List<BenchmarkProfile.Control> controls =
				parseCanonical(lines, sourceForErrors);
		return new BenchmarkProfile(resolvedName,
				applyManualReview(resolvedName, controls, overlay));
	}

	/**
	 * Demote every control named for {@code profileName} in the overlay to
	 * manual review. Rows naming a control the profile does not carry are
	 * ignored here (the unit test pins that every shipped row matches).
	 */
	static List<BenchmarkProfile.Control> applyManualReview(
			String profileName, List<BenchmarkProfile.Control> controls,
			Map<String, java.util.Set<String>> overlay) {
		java.util.Set<String> ids = overlay == null ? null
				: overlay.get(profileName);
		if (ids == null || ids.isEmpty()) return controls;
		List<BenchmarkProfile.Control> out = new ArrayList<>(controls.size());
		for (BenchmarkProfile.Control c : controls) {
			out.add(ids.contains(c.controlId) ? c.asManualReview() : c);
		}
		return out;
	}

	/** Diagnostic only: controls the overlay demoted in this profile. */
	private static int countManualReview(BenchmarkProfile p) {
		return p == null ? 0 : p.manualReviewCount;
	}

	/**
	 * Read {@code <confDir>/profiles/manual_review.csv} (classpath fallback
	 * {@code /profiles/manual_review.csv}).
	 *
	 * <p>Build 70: a missing overlay now FAILS the load (the adapter goes
	 * Down with this message). The overlay no longer only demotes prose
	 * expected values (whose failure mode was a false fail); it also demotes
	 * the host-side standard-switch controls that would otherwise be read
	 * from the distributed switch, and scoring those is a false PASS. A
	 * broken install must be visible, never silently less safe.
	 */
	static Map<String, java.util.Set<String>> loadManualReview(String confDir) {
		List<String> lines = null;
		if (confDir != null && !confDir.isEmpty()) {
			Path p = Paths.get(confDir, "profiles", MANUAL_REVIEW_FILE);
			if (Files.exists(p)) {
				lines = readFileStatic(p);
			}
		}
		if (lines == null) {
			InputStream is = BenchmarkLoader.class.getResourceAsStream(
					"/profiles/" + MANUAL_REVIEW_FILE);
			if (is != null) lines = readStreamStatic(is);
		}
		if (lines == null) {
			throw new RuntimeException("profiles/" + MANUAL_REVIEW_FILE
					+ " not found (looked under confDir=" + confDir
					+ " and the classpath). It is required for the bundled "
					+ "profiles: without it, standard-switch controls would "
					+ "be scored from the distributed switch (false pass). "
					+ "Reinstall the pak.");
		}
		return parseManualReview(lines);
	}

	static Map<String, java.util.Set<String>> parseManualReview(
			List<String> lines) {
		Map<String, java.util.Set<String>> out = new HashMap<>();
		if (lines == null) return out;
		List<String> records = stitchRecords(lines);
		if (records.isEmpty()) return out;
		String[] header = parseCsvLine(records.get(0));
		int idxProfile = -1;
		int idxControl = -1;
		for (int i = 0; i < header.length; i++) {
			String h = header[i].trim();
			if ("profile".equals(h)) idxProfile = i;
			if ("control_id".equals(h)) idxControl = i;
		}
		if (idxProfile < 0 || idxControl < 0) {
			throw new RuntimeException(MANUAL_REVIEW_FILE
					+ " is missing the profile / control_id header");
		}
		for (int i = 1; i < records.size(); i++) {
			String rec = records.get(i);
			if (rec.trim().isEmpty() || rec.trim().startsWith("#")) continue;
			String[] f = parseCsvLine(rec);
			String profile = field(f, idxProfile);
			String control = field(f, idxControl);
			if (profile.isEmpty() || control.isEmpty()) continue;
			out.computeIfAbsent(profile, k -> new java.util.HashSet<>())
					.add(control);
		}
		return out;
	}

	/**
	 * Resolves the configured profile name to a bundled profile.
	 *
	 * <p>An absent name ({@code null} / blank) keeps the describe.xml
	 * default. Any unknown NON-null name — including the retired
	 * {@code CIS_vSphere_8} — throws (build 56, review B1): the
	 * exception propagates out of the collect cycle so the adapter
	 * instance goes to a visible failed state with an actionable
	 * message, instead of silently scoring against a benchmark the
	 * operator did not configure. A silent fallback would put a
	 * confident compliance score on dashboards that answers a
	 * different question than the instance's own configuration says —
	 * for a compliance product the wrong-score mode is strictly worse
	 * than a one-click-recoverable Down. {@code Custom} reaches here
	 * only when {@code custom_profile_path} is unset (the caller
	 * handles the valid Custom+path case first) and gets its own
	 * actionable message.
	 */
	static String resolveBundledProfileName(String profileName) {
		if (profileName == null || profileName.trim().isEmpty()) {
			return "VMware_SCG_8.0";
		}
		switch (profileName) {
			case "VMware_SCG_9.1":
			case "VMware_SCG_9.0":
			case "VMware_SCG_8.0":
			case "VMware_SCG_7.0":
			case "VMware_SCG_6.7":
				return profileName;
			default:
				if ("Custom".equalsIgnoreCase(profileName)) {
					throw new RuntimeException(
							"benchmark_profile 'Custom' requires "
							+ "custom_profile_path to point at a "
							+ "canonical-schema profile CSV on the "
							+ "collector");
				}
				throw new RuntimeException(
						"configured benchmark_profile '" + profileName
						+ "' is not bundled in this version; choose "
						+ "Auto (by version), VMware_SCG_6.7 / 7.0 / 8.0 / "
						+ "9.0 / 9.1, or Custom");
		}
	}

	/**
	 * Maps the resolved profile name to its canonical-CSV filename
	 * under {@code profiles/canonical/}. Source CSVs (vendor formats)
	 * live in {@code profiles/} but the loader never reads them — the
	 * Python normalizers under {@code scripts/} are the only producer
	 * of canonical files.
	 */
	static String bundledFilename(String resolvedName) {
		switch (resolvedName) {
			case "VMware_SCG_6.7":
				return "scg_6.7.csv";
			case "VMware_SCG_7.0":
				return "scg_7.0.csv";
			case "VMware_SCG_9.1":
				return "scg_9.1.csv";
			case "VMware_SCG_9.0":
				return "scg_9.0.csv";
			case "VMware_SCG_8.0":
			default:
				return "scg_8.0.csv";
		}
	}

	private Path locateBundled(String filename, String confDir) {
		if (confDir == null || confDir.isEmpty()) return null;
		Path canonical = Paths.get(confDir, "profiles", "canonical", filename);
		if (Files.exists(canonical)) return canonical;
		return null;
	}

	public void invalidate() {
		cachedProfile = null;
		cachedProfileKey = null;
		cachedAll = null;
		cachedAllKey = null;
	}

	private static List<String> readStreamStatic(InputStream is) {
		return new BenchmarkLoader().readStream(is);
	}

	private static List<String> readFileStatic(Path path) {
		return new BenchmarkLoader().readFile(path);
	}

	private List<String> readStream(InputStream is) {
		List<String> lines = new ArrayList<>();
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(is, StandardCharsets.UTF_8))) {
			String line;
			while ((line = reader.readLine()) != null) {
				lines.add(line);
			}
		} catch (IOException e) {
			throw new RuntimeException("Failed to read bundled profile", e);
		}
		return lines;
	}

	private List<String> readFile(Path path) {
		List<String> lines = new ArrayList<>();
		try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
			String line;
			while ((line = reader.readLine()) != null) {
				lines.add(line);
			}
		} catch (IOException e) {
			throw new RuntimeException("Failed to read profile: " + path, e);
		}
		return lines;
	}

	/**
	 * Parses the canonical CSV. Throws if the header is missing
	 * required columns — the caller wraps this into a
	 * {@code CollectionException} so the adapter goes Down with a
	 * descriptive message rather than silently scoring nothing.
	 */
	static List<BenchmarkProfile.Control> parseCanonical(List<String> lines,
			String sourceForErrors) {
		// Find the first non-blank line for the header.
		// CSV records can span multiple physical lines when fields
		// contain quoted newlines (SCG sources do this routinely),
		// so we stitch logical records as we go.
		List<String> records = stitchRecords(lines);
		if (records.isEmpty()) {
			throw new RuntimeException(
					"Canonical profile is empty: " + sourceForErrors);
		}

		String headerLine = records.get(0);
		String[] headerFields = parseCsvLine(headerLine);
		Map<String, Integer> headerMap = new HashMap<>();
		for (int i = 0; i < headerFields.length; i++) {
			headerMap.put(headerFields[i].trim(), i);
		}

		List<String> missing = new ArrayList<>();
		for (String required : REQUIRED_COLUMNS) {
			if (!headerMap.containsKey(required)) {
				missing.add(required);
			}
		}
		if (!missing.isEmpty()) {
			throw new RuntimeException(
					"Canonical profile " + sourceForErrors
					+ " is missing required column(s): " + missing
					+ ". Re-run scripts/normalize_*.py to regenerate.");
		}

		int idxControlId = headerMap.get("control_id");
		int idxPriority = headerMap.get("priority");
		int idxResourceKind = headerMap.get("resource_kind");
		int idxAdapterKind = headerMap.get("adapter_kind");
		int idxParameter = headerMap.get("parameter");
		int idxParameterKind = headerMap.get("parameter_kind");
		int idxValueType = headerMap.get("value_type");
		int idxExpectedValue = headerMap.get("expected_value");
		int idxTitle = headerMap.get("title");
		int idxDescription = headerMap.get("description");
		int idxSourceRef = headerMap.get("source_ref");
		int idxRemediationText = headerMap.get("remediation_text");
		// Optional column: -1 when absent, in which case field() returns
		// "" and every vim_property control loads as non-evaluable.
		Integer idxReadRecipeBox = headerMap.get(READ_RECIPE_COLUMN);
		int idxReadRecipe = idxReadRecipeBox != null ? idxReadRecipeBox : -1;

		List<BenchmarkProfile.Control> controls = new ArrayList<>();
		for (int i = 1; i < records.size(); i++) {
			String record = records.get(i);
			if (record.trim().isEmpty()) continue;
			String[] fields = parseCsvLine(record);

			String controlId = field(fields, idxControlId);
			if (controlId.isEmpty()) continue;

			controls.add(new BenchmarkProfile.Control(
					controlId,
					field(fields, idxPriority),
					field(fields, idxResourceKind),
					field(fields, idxAdapterKind),
					field(fields, idxParameter),
					field(fields, idxParameterKind),
					field(fields, idxValueType),
					field(fields, idxExpectedValue),
					field(fields, idxTitle),
					field(fields, idxDescription),
					field(fields, idxSourceRef),
					field(fields, idxRemediationText),
					field(fields, idxReadRecipe)
			));
		}
		return controls;
	}

	private static String field(String[] fields, int idx) {
		if (idx < 0 || idx >= fields.length) return "";
		String v = fields[idx];
		return v == null ? "" : v.trim();
	}

	/**
	 * Stitch physical lines into logical CSV records. A record may
	 * span multiple lines when a field contains a quoted newline.
	 * Tracks an even/odd count of unescaped double-quotes across
	 * accumulated lines and emits a record whenever the count is
	 * even (i.e. quotes are balanced).
	 */
	static List<String> stitchRecords(List<String> lines) {
		List<String> records = new ArrayList<>();
		StringBuilder current = new StringBuilder();
		int unbalancedQuotes = 0;

		for (String line : lines) {
			if (current.length() > 0) current.append('\n');
			current.append(line);
			unbalancedQuotes += countQuotes(line);
			if (unbalancedQuotes % 2 == 0) {
				records.add(current.toString());
				current.setLength(0);
				unbalancedQuotes = 0;
			}
		}
		// Flush any trailing content even if quotes are unbalanced —
		// better to return a malformed last record than to silently
		// swallow data.
		if (current.length() > 0) {
			records.add(current.toString());
		}
		return records;
	}

	private static int countQuotes(String s) {
		int n = 0;
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) == '"') n++;
		}
		return n;
	}

	/**
	 * Minimal RFC-4180-ish field splitter. Handles double-quoted
	 * fields and doubled-quote escapes. Does not require the input to
	 * be a single line — callers stitch multi-line records with
	 * {@link #stitchRecords} first.
	 */
	static String[] parseCsvLine(String line) {
		List<String> fields = new ArrayList<>();
		StringBuilder current = new StringBuilder();
		boolean inQuotes = false;

		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if (c == '"') {
				if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
					current.append('"');
					i++;
				} else {
					inQuotes = !inQuotes;
				}
			} else if (c == ',' && !inQuotes) {
				fields.add(current.toString());
				current.setLength(0);
			} else {
				current.append(c);
			}
		}
		fields.add(current.toString());
		return fields.toArray(new String[0]);
	}
}
