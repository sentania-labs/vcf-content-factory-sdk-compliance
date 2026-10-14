package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * Build 95 (Scott 2026-10-14, "How are we publishing a reason?"): why the
 * controls of ONE object could not be read this cycle, published on the
 * object as {@code VCF-CF Compliance|unreadable_reason}, with the affected
 * control ids as {@code VCF-CF Compliance|unreadable_controls}. SDK-free.
 *
 * <p>The adapter records every unreadable reason it already logs (the same
 * strings {@link UnreadableReasons} counts per cycle) while it reads one
 * object, then {@link #reasonText} turns them into one line: per cause, the
 * cause in plain words ({@link #plainWords}), the logged detail of its
 * first occurrence, and how many controls it covers when more than one
 * cause applies. Causes are listed most controls first.
 */
public final class ObjectUnreadable {

	/** unreadable_reason is cut to this many characters, at most. */
	public static final int REASON_CAP = 1000;

	/** Control ids named in unreadable_controls, at most. */
	public static final int CONTROLS_CAP = 20;

	/** One cause: the plain words, the first detail, the control count. */
	private static final class Cause {
		final String plain;
		final String detail;
		int count;

		Cause(String plain, String detail) {
			this.plain = plain;
			this.detail = detail;
		}
	}

	// plain words -> cause, in first-seen order (ties keep that order).
	private final Map<String, Cause> causes = new LinkedHashMap<>();

	/** Record {@code count} unreadable controls for one logged reason. */
	public void record(String reason, int count) {
		if (count <= 0) return;
		String plain = plainWords(reason);
		Cause c = causes.get(plain);
		if (c == null) {
			c = new Cause(plain, reason == null ? "" : reason.trim());
			causes.put(plain, c);
		}
		c.count += count;
	}

	public boolean isEmpty() {
		return causes.isEmpty();
	}

	/**
	 * The unreadable_reason text, e.g. {@code "host not responding
	 * (host-not-connected: connectionState=notResponding)"} or, with two
	 * causes, {@code "permission refused (soap-fault: NoPermission ...), 3
	 * controls; esxcli unavailable (esxcli-unavailable: no esxcli
	 * session), 1 control"}. "" when nothing was recorded and
	 * {@code unreadableCount} is 0; {@code "unknown cause (no reason
	 * recorded)"} when controls were unreadable but no reason was recorded
	 * (never an empty reason beside has_unreadable = 1). At most
	 * {@link #REASON_CAP} characters, ending {@code "(+N more causes)"} when
	 * causes were left out.
	 */
	public String reasonText(int unreadableCount) {
		if (causes.isEmpty()) {
			return unreadableCount > 0 ? "unknown cause (no reason recorded)"
					: "";
		}
		List<Cause> list = new ArrayList<>(causes.values());
		list.sort((a, b) -> Integer.compare(b.count, a.count));
		boolean several = list.size() > 1;
		// Room kept for the "(+N more causes)" suffix while more follow.
		final int reserve = 24;
		StringBuilder sb = new StringBuilder();
		int used = 0;
		for (Cause c : list) {
			String part = c.plain
					+ (c.detail.isEmpty() ? "" : " (" + c.detail + ")")
					+ (several ? ", " + c.count + (c.count == 1 ? " control"
							: " controls") : "");
			String sep = sb.length() == 0 ? "" : "; ";
			boolean last = used == list.size() - 1;
			int limit = last ? REASON_CAP : REASON_CAP - reserve;
			if (sb.length() + sep.length() + part.length() <= limit) {
				sb.append(sep).append(part);
				used++;
				continue;
			}
			if (sb.length() == 0) {
				// One cause longer than the cap: cut its detail.
				sb.append(part, 0, Math.max(0, limit - 3)).append("...");
				used++;
			}
			break;
		}
		int left = list.size() - used;
		if (left > 0) {
			sb.append(" (+").append(left).append(left == 1 ? " more cause)"
					: " more causes)");
		}
		return sb.toString();
	}

	/**
	 * The unreadable_controls text: the ids sorted, comma separated, at
	 * most {@link #CONTROLS_CAP} named, then {@code "(+N more)"}. "" for
	 * none.
	 */
	public static String controlsText(Collection<String> ids) {
		if (ids == null || ids.isEmpty()) return "";
		TreeSet<String> sorted = new TreeSet<>(ids);
		StringBuilder sb = new StringBuilder();
		int n = 0;
		for (String id : sorted) {
			if (n == CONTROLS_CAP) break;
			if (sb.length() > 0) sb.append(", ");
			sb.append(id);
			n++;
		}
		if (sorted.size() > n) {
			sb.append(" (+").append(sorted.size() - n).append(" more)");
		}
		return sb.toString();
	}

	/**
	 * The cause of one logged unreadable reason, in plain words. The
	 * reason codes are the categories the adapter logs (text before the
	 * first ':', see {@link UnreadableReasons#category}); the detail after
	 * it decides a few (a SOAP fault naming NoPermission is "permission
	 * refused", a host's connection state, a VAMI HTTP status). An unknown
	 * code is given as "could not be read" with the code, never dropped.
	 */
	public static String plainWords(String reason) {
		String cat = UnreadableReasons.category(reason);
		String all = reason == null ? "" : reason.toLowerCase(Locale.ROOT);
		switch (cat) {
			case "host-not-connected":
				return all.contains("notresponding") ? "host not responding"
						: "host disconnected";
			case "advanced-settings-unreadable":
				return all.contains("flapped")
						? "host disconnected during the read"
						: "host advanced settings unreadable";
			case "extraconfig-unreadable":
				return "VM advanced settings unreadable";
			case "vcenter-settings-unreadable":
				return "vCenter advanced settings unreadable";
			case "esxcli-host-unreachable":
				return "host unreachable for esxcli";
			case "esxcli-unavailable":
				return "esxcli unavailable";
			case "esxcli-command-failed":
				return "esxcli command failed";
			case "esxcli-field-missing":
				return "esxcli field missing";
			case "esxcli-not-bulk":
				return "not readable in a bulk read";
			case "soap-fault":
				return all.contains("nopermission") ? "permission refused"
						: "vCenter returned a fault";
			case "response-too-large":
				return "vCenter response over the size cap";
			case "missing-element":
				return "setting not returned by vCenter";
			case "prefix-cap":
				return "property path not reachable";
			case "value-absent":
				return "value not present";
			case "empty-value":
			case "unparsable-value":
				return "value not readable";
			case "vami-session":
				return "appliance session refused";
			case "vami-parse":
				return "appliance answer not readable";
			case "vami-exception":
				return "appliance not reached";
			case "vami-field-missing":
				return "appliance field missing";
			case "vami-failed":
				return "appliance read failed";
			case "recipe-malformed":
			case "recipe-unknown-style":
				return "read recipe invalid";
			case "vsan-probe-failed":
				return "vSAN probe failed";
			case "version-unreadable":
				return "product version unreadable";
			case "exception":
				return all.contains("nopermission") ? "permission refused"
						: "read failed";
			case "unknown":
				return "unknown cause";
			default:
				if (cat.startsWith("vami-http-")) {
					String code = cat.substring("vami-http-".length());
					return "401".equals(code) || "403".equals(code)
							? "appliance permission refused"
							: "appliance returned HTTP " + code;
				}
				return "could not be read (" + cat + ")";
		}
	}
}
