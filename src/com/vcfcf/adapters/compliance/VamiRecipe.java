package com.vcfcf.adapters.compliance;

import java.util.List;

/**
 * Build 74: the {@code vami:} recipe grammar and the JSON-to-value mapping
 * rules, SDK-free so they are unit-tested ({@link VamiApiClient} does the
 * HTTP and JSON parsing and calls these).
 *
 * <p>Grammar: {@code vami:<appliance-path>:<field>}. The appliance path is
 * everything up to the LAST colon (it may contain {@code /}). The field is:
 * <ul>
 *   <li>{@code (value)}: the response body itself is the value (a bare
 *       scalar, e.g. {@code GET /api/appliance/access/ssh} returns
 *       {@code true}). A boolean stays Boolean.</li>
 *   <li>{@code (list)}: the response body itself is a list; its elements
 *       are comma-joined.</li>
 *   <li>otherwise a field name (dotted for nesting) in a JSON object body.
 *       Build 76: a field may carry an absent default,
 *       {@code <field>?absent=<value>}: when a SUCCESSFUL 200 JSON-object
 *       body does not contain the field, the value is {@code <value>}
 *       instead of UNREADABLE. Only for fields whose absence the vendor
 *       spec defines (e.g. {@code local-accounts/{username}}
 *       {@code max_days_between_password_change}: "If unset, password never
 *       expires", mapped to -1). An HTTP failure, a failed session, or a
 *       body that is not a JSON object stays UNREADABLE.</li>
 * </ul>
 *
 * <p>Outcome rules (the cardinal rule: a failed read is never a pass):
 * <ul>
 *   <li>any HTTP / session / transport failure, or an absent field: the
 *       read failed (UNREADABLE upstream);</li>
 *   <li>a 200 with an EMPTY list: a definitive answer ("nothing
 *       configured"), returned as the empty string, which scores FAIL
 *       under {@code (non-empty)} (build 74; it used to be UNREADABLE);</li>
 *   <li>{@code true} / {@code false} text: Boolean; anything else: String.</li>
 * </ul>
 */
public final class VamiRecipe {

	public static final String SELF_VALUE = "(value)";
	public static final String SELF_LIST = "(list)";
	public static final String ABSENT_OPTION = "?absent=";

	public final String appliancePath;
	public final String field;
	/** Value for an absent field in a successful object body, or null. */
	public final String absentDefault;

	private VamiRecipe(String appliancePath, String field,
			String absentDefault) {
		this.appliancePath = appliancePath;
		this.field = field;
		this.absentDefault = absentDefault;
	}

	/** Parse a {@code vami:} recipe; null when malformed. */
	public static VamiRecipe parse(String recipe) {
		if (recipe == null) return null;
		String r = recipe.trim();
		if (!r.startsWith("vami:")) return null;
		String rest = r.substring("vami:".length());
		int lastColon = rest.lastIndexOf(':');
		if (lastColon <= 0 || lastColon >= rest.length() - 1) return null;
		String path = rest.substring(0, lastColon).trim();
		String field = rest.substring(lastColon + 1).trim();
		String absent = null;
		int opt = field.indexOf(ABSENT_OPTION);
		if (opt >= 0) {
			absent = field.substring(opt + ABSENT_OPTION.length()).trim();
			field = field.substring(0, opt).trim();
			if (absent.isEmpty()) return null;
			if (SELF_VALUE.equals(field) || SELF_LIST.equals(field)) {
				return null;   // absent default only applies to named fields
			}
		}
		if (path.isEmpty() || field.isEmpty()) return null;
		return new VamiRecipe(path, field, absent);
	}

	/**
	 * The value for a field that is ABSENT from a response body: the
	 * recipe's absent default when the body was a successfully parsed JSON
	 * object and a default is declared, else null (UNREADABLE).
	 */
	public Object absentValue(boolean bodyIsObject) {
		if (!bodyIsObject || absentDefault == null) return null;
		return scalarValue(absentDefault);
	}

	/**
	 * A JSON list as a value: elements (already rendered to text by the
	 * caller) comma-joined; an empty list is the empty string (FAIL under
	 * {@code (non-empty)}, not UNREADABLE).
	 */
	public static String listValue(List<String> items) {
		if (items == null || items.isEmpty()) return "";
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < items.size(); i++) {
			if (i > 0) sb.append(',');
			String s = items.get(i);
			sb.append(s != null ? s : "");
		}
		return sb.toString();
	}

	/**
	 * A JSON scalar's text as a value: Boolean for true/false, else the
	 * text; null text means the read produced nothing (UNREADABLE).
	 */
	public static Object scalarValue(String text) {
		if (text == null) return null;
		if ("true".equalsIgnoreCase(text)) return Boolean.TRUE;
		if ("false".equalsIgnoreCase(text)) return Boolean.FALSE;
		return text;
	}
}
