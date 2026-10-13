package com.vcfcf.adapters.compliance;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Build 90: the instance's overrides file (the factory's
 * knowledge/designs/sdk-adapters/compliance-overrides-file.md). One XML file
 * in the VCF Ops central configuration-file store, named by the instance's
 * {@code overrides_file} setting, with three entry types:
 *
 * <pre>
 * &lt;ComplianceOverrides&gt;
 *   &lt;Skip control="esx.account-lockout-max-attempts"/&gt;
 *   &lt;Override control="esx.account-lockout-max-attempts" expected="5"/&gt;
 *   &lt;Profile version="SCG 9.0"/&gt;
 *   &lt;Profile kind="VirtualMachine" version="SCG 8.0"/&gt;
 * &lt;/ComplianceOverrides&gt;
 * </pre>
 *
 * <ul>
 *   <li>{@code Skip}: the control is not evaluated and not pushed; its key
 *       goes through the stale-key cleanup (0 or 1 set to -1, actual
 *       "(skipped by override file &lt;name&gt;)").</li>
 *   <li>{@code Override}: the control's expected value in every loaded
 *       profile, checked against the control's value_type and comparison
 *       mode ({@link #checkValue}). A value that fails the check in any
 *       profile is rejected for every profile: the SCG value stays, never a
 *       pass.</li>
 *   <li>{@code Profile}: pins the SCG version for the instance, or with
 *       {@code kind} for one object kind, in place of Auto (by version) or
 *       the fixed choice. A per-kind pin wins over the instance pin.</li>
 * </ul>
 *
 * <p>Unknown elements, attributes, versions, kinds and control ids are
 * rejected entries (reported, not fatal). A file that is not well-formed
 * XML, or whose root is not {@code ComplianceOverrides}, fails to parse
 * ({@link #parse} throws); the store keeps the previous parse.
 *
 * <p>No VCF Ops SDK dependency: unit-testable with a plain JDK.
 */
public final class ComplianceOverrides {

	private ComplianceOverrides() {}

	public static final String ROOT = "ComplianceOverrides";

	/** The entry types. */
	public enum Type { SKIP, OVERRIDE, PROFILE }

	/** One accepted entry of the file, in file order. */
	public static final class Entry {
		public final Type type;
		public final String control;       // SKIP, OVERRIDE
		public final String expected;      // OVERRIDE
		public final String profileName;   // PROFILE: resolved bundled name
		public final BenchmarkSelector.Kind kind;   // PROFILE: null = instance
		public final String text;          // the entry as written, for logs

		Entry(Type type, String control, String expected, String profileName,
				BenchmarkSelector.Kind kind, String text) {
			this.type = type;
			this.control = control;
			this.expected = expected;
			this.profileName = profileName;
			this.kind = kind;
			this.text = text;
		}
	}

	/** The result of a successful parse. */
	public static final class Parsed {
		public final List<Entry> entries;
		/** Entries rejected while parsing, one message each. */
		public final List<String> rejected;

		Parsed(List<Entry> entries, List<String> rejected) {
			this.entries = Collections.unmodifiableList(entries);
			this.rejected = Collections.unmodifiableList(rejected);
		}

		public boolean isEmpty() {
			return entries.isEmpty() && rejected.isEmpty();
		}
	}

	/** Thrown when the file cannot be parsed at all. */
	public static final class ParseException extends Exception {
		private static final long serialVersionUID = 1L;

		ParseException(String message) {
			super(message);
		}
	}

	// ----- parse -----------------------------------------------------------

	private static final Pattern VERSION = Pattern.compile(
			"(?i)^(?:vmware[ _]?)?(?:scg[ _]?)?(\\d+\\.\\d+)$");

	/**
	 * Parse the file body. External entities and DOCTYPE declarations are
	 * refused. Throws {@link ParseException} when the body is not
	 * well-formed XML or the root is not {@value #ROOT}.
	 */
	public static Parsed parse(String xml) throws ParseException {
		if (xml == null || xml.trim().isEmpty()) {
			throw new ParseException("the file is empty");
		}
		Document doc;
		try {
			DocumentBuilder db = secureFactory().newDocumentBuilder();
			db.setErrorHandler(SILENT);
			doc = db.parse(new ByteArrayInputStream(
					xml.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception e) {
			throw new ParseException("not well-formed XML: "
					+ e.getMessage());
		}
		Element root = doc.getDocumentElement();
		if (root == null || !ROOT.equals(root.getTagName())) {
			throw new ParseException("the root element must be <" + ROOT
					+ ">, found <" + (root == null ? "" : root.getTagName())
					+ ">");
		}
		List<Entry> entries = new ArrayList<>();
		List<String> rejected = new ArrayList<>();
		Set<String> skipped = new LinkedHashSet<>();
		Set<String> overridden = new LinkedHashSet<>();
		boolean instancePin = false;
		Set<BenchmarkSelector.Kind> kindPins =
				java.util.EnumSet.noneOf(BenchmarkSelector.Kind.class);

		NodeList nodes = root.getChildNodes();
		for (int i = 0; i < nodes.getLength(); i++) {
			Node n = nodes.item(i);
			if (n.getNodeType() != Node.ELEMENT_NODE) continue;
			Element el = (Element) n;
			String text = describe(el);
			String tag = el.getTagName();
			Type type;
			Set<String> allowed;
			if ("Skip".equals(tag)) {
				type = Type.SKIP;
				allowed = set("control");
			} else if ("Override".equals(tag)) {
				type = Type.OVERRIDE;
				allowed = set("control", "expected");
			} else if ("Profile".equals(tag)) {
				type = Type.PROFILE;
				allowed = set("version", "kind");
			} else {
				rejected.add(text + ": unknown entry type (use Skip, Override "
						+ "or Profile)");
				continue;
			}
			String badAttr = unknownAttribute(el, allowed);
			if (badAttr != null) {
				rejected.add(text + ": unknown attribute '" + badAttr + "'");
				continue;
			}
			if (type == Type.PROFILE) {
				String version = attr(el, "version");
				if (version == null) {
					rejected.add(text + ": missing version");
					continue;
				}
				String profileName = resolveVersion(version);
				if (profileName == null) {
					rejected.add(text + ": unknown version '" + version
							+ "' (use " + versionList() + ")");
					continue;
				}
				BenchmarkSelector.Kind kind = null;
				if (el.hasAttribute("kind")) {
					String k = attr(el, "kind");
					kind = resolveKind(k);
					if (kind == null) {
						rejected.add(text + ": unknown kind '"
								+ (k == null ? "" : k) + "' (use " + KIND_LIST
								+ ")");
						continue;
					}
				}
				if (kind == null) {
					if (instancePin) {
						rejected.add(text + ": duplicate instance Profile (the "
								+ "first one is used)");
						continue;
					}
					instancePin = true;
				} else {
					if (!kindPins.add(kind)) {
						rejected.add(text + ": duplicate Profile for this kind "
								+ "(the first one is used)");
						continue;
					}
				}
				entries.add(new Entry(Type.PROFILE, null, null, profileName,
						kind, text));
				continue;
			}
			String control = attr(el, "control");
			if (control == null) {
				rejected.add(text + ": missing control");
				continue;
			}
			if (type == Type.SKIP) {
				if (!skipped.add(control)) {
					rejected.add(text + ": duplicate Skip");
					continue;
				}
				entries.add(new Entry(Type.SKIP, control, null, null, null,
						text));
				continue;
			}
			// OVERRIDE. The expected attribute must be present; its value is
			// checked per control later (resolve), against the profiles.
			if (!el.hasAttribute("expected")) {
				rejected.add(text + ": missing expected");
				continue;
			}
			if (!overridden.add(control)) {
				rejected.add(text + ": duplicate Override for this control "
						+ "(the first one is used)");
				continue;
			}
			entries.add(new Entry(Type.OVERRIDE, control,
					el.getAttribute("expected").trim(), null, null, text));
		}
		return new Parsed(entries, rejected);
	}

	/** Throws on every problem instead of printing to stderr. */
	private static final org.xml.sax.ErrorHandler SILENT =
			new org.xml.sax.ErrorHandler() {
				@Override
				public void warning(org.xml.sax.SAXParseException e) {
					// ignored
				}

				@Override
				public void error(org.xml.sax.SAXParseException e)
						throws org.xml.sax.SAXException {
					throw e;
				}

				@Override
				public void fatalError(org.xml.sax.SAXParseException e)
						throws org.xml.sax.SAXException {
					throw e;
				}
			};

	private static DocumentBuilderFactory secureFactory() throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(false);
		dbf.setValidating(false);
		dbf.setXIncludeAware(false);
		dbf.setExpandEntityReferences(false);
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		// A DOCTYPE is refused outright; the two entity features are a
		// second guard for parsers that ignore the first.
		dbf.setFeature(
				"http://apache.org/xml/features/disallow-doctype-decl", true);
		trySetFeature(dbf,
				"http://xml.org/sax/features/external-general-entities", false);
		trySetFeature(dbf,
				"http://xml.org/sax/features/external-parameter-entities",
				false);
		trySetFeature(dbf,
				"http://apache.org/xml/features/nonvalidating/load-external-dtd",
				false);
		try {
			dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		} catch (IllegalArgumentException ignored) {
			// not supported by this parser; the features above still apply
		}
		return dbf;
	}

	private static void trySetFeature(DocumentBuilderFactory dbf, String f,
			boolean v) {
		try {
			dbf.setFeature(f, v);
		} catch (Exception ignored) {
			// not supported by this parser
		}
	}

	private static Set<String> set(String... names) {
		return new LinkedHashSet<>(java.util.Arrays.asList(names));
	}

	private static String unknownAttribute(Element el, Set<String> allowed) {
		NamedNodeMap attrs = el.getAttributes();
		for (int i = 0; i < attrs.getLength(); i++) {
			String name = attrs.item(i).getNodeName();
			if (!allowed.contains(name)) return name;
		}
		return null;
	}

	/** Trimmed attribute value; null when absent or blank. */
	private static String attr(Element el, String name) {
		if (!el.hasAttribute(name)) return null;
		String v = el.getAttribute(name).trim();
		return v.isEmpty() ? null : v;
	}

	/** The entry as written, e.g. {@code <Skip control="x"/>}. */
	static String describe(Element el) {
		StringBuilder sb = new StringBuilder("<").append(el.getTagName());
		NamedNodeMap attrs = el.getAttributes();
		for (int i = 0; i < attrs.getLength(); i++) {
			Node a = attrs.item(i);
			sb.append(' ').append(a.getNodeName()).append("=\"")
					.append(a.getNodeValue()).append('"');
		}
		return sb.append("/>").toString();
	}

	/**
	 * A Profile version as written ({@code SCG 9.0}, {@code SCG_9.0},
	 * {@code VMware_SCG_9.0}, {@code 9.0}) to its bundled profile name, or
	 * null when no bundled profile has that version.
	 */
	static String resolveVersion(String version) {
		if (version == null) return null;
		Matcher m = VERSION.matcher(version.trim());
		if (!m.matches()) return null;
		String name = "VMware_SCG_" + m.group(1);
		return BenchmarkLoader.BUNDLED_PROFILES.contains(name) ? name : null;
	}

	/** The valid version names, for messages and the template. */
	static String versionList() {
		StringBuilder sb = new StringBuilder();
		for (String p : BenchmarkLoader.BUNDLED_PROFILES) {
			if (sb.length() > 0) sb.append(", ");
			sb.append("SCG ").append(BenchmarkSelector.scgOfProfileName(p));
		}
		return sb.toString();
	}

	static final String KIND_LIST = "HostSystem, VirtualMachine, vCenter, "
			+ "ClusterComputeResource, DistributedVirtualSwitch, "
			+ "DistributedVirtualPortgroup";

	private static final Map<String, BenchmarkSelector.Kind> KINDS;
	static {
		Map<String, BenchmarkSelector.Kind> m = new LinkedHashMap<>();
		for (String k : new String[] {"hostsystem", "host", "esx", "esxhost"}) {
			m.put(k, BenchmarkSelector.Kind.HOST);
		}
		for (String k : new String[] {"virtualmachine", "vm"}) {
			m.put(k, BenchmarkSelector.Kind.VM);
		}
		for (String k : new String[] {"vcenter", "vcenteradapterinstance",
				"vmwareadapterinstance"}) {
			m.put(k, BenchmarkSelector.Kind.VCENTER);
		}
		for (String k : new String[] {"clustercomputeresource", "cluster"}) {
			m.put(k, BenchmarkSelector.Kind.CLUSTER);
		}
		for (String k : new String[] {"distributedvirtualswitch",
				"vmwaredistributedvirtualswitch", "distributedswitch", "vds"}) {
			m.put(k, BenchmarkSelector.Kind.VDS);
		}
		for (String k : new String[] {"distributedvirtualportgroup",
				"distributedportgroup", "portgroup", "dvpg"}) {
			m.put(k, BenchmarkSelector.Kind.PORTGROUP);
		}
		KINDS = Collections.unmodifiableMap(m);
	}

	/**
	 * A Profile kind as written to the object kind: the canonical
	 * resource_kind tokens, the VCF Ops kind keys and the short names
	 * (host, vm, vcenter, cluster, vds, portgroup), case, spaces and
	 * underscores ignored. Null when unknown.
	 */
	static BenchmarkSelector.Kind resolveKind(String kind) {
		if (kind == null) return null;
		String k = kind.toLowerCase(Locale.ROOT).replace(" ", "")
				.replace("_", "").replace("-", "");
		return KINDS.get(k);
	}

	// ----- value check (Override) ------------------------------------------

	private static final Pattern INTEGER = Pattern.compile("^[-+]?\\d+$");
	private static final Pattern OR_UNDEFINED = Pattern.compile(
			"(?i)^(.*?)\\s+or\\s+(?:undefined|not present)$");

	/**
	 * Whether {@code value} can be the expected value of control {@code c}:
	 * null when it can, otherwise why not. The comparison mode is taken from
	 * the value's form (the modes the evaluator knows, CANONICAL_SCHEMA.md);
	 * the plain value inside it must fit the control's {@code value_type}:
	 *
	 * <ul>
	 *   <li>{@code (non-empty)}: any value type.</li>
	 *   <li>{@code not:<v>}: {@code <v>} checked as a plain value.</li>
	 *   <li>{@code vmx-N or higher}: string controls only.</li>
	 *   <li>{@code Not Present} and {@code <v> or Undefined}: advanced
	 *       settings only (the only read where "not set" is visible).</li>
	 *   <li>plain {@code integer}: whole number; {@code boolean}: true or
	 *       false (advanced settings also 1 or 0); {@code string}: any
	 *       non-empty text other than N/A.</li>
	 * </ul>
	 */
	public static String checkValue(BenchmarkProfile.Control c, String value) {
		String v = value == null ? "" : value.trim();
		if (v.isEmpty()) return "empty expected value";
		if ("n/a".equalsIgnoreCase(v)) return "N/A is not a value";
		if (ControlEvaluator.isNonEmptyMode(v)) return null;
		if (ControlEvaluator.isNotEqualMode(v)) {
			String target = ControlEvaluator.notEqualTarget(v);
			String why = checkPlain(c, target);
			return why == null ? null : "not:" + target + ": " + why;
		}
		if (ControlEvaluator.isVmxMinimumMode(v)) {
			return "string".equals(c.valueType) ? null
					: "'vmx-N or higher' needs a string control, this one is "
							+ c.valueType;
		}
		boolean advanced = "advanced_setting".equals(c.parameterKind);
		if (ControlEvaluator.requiresAbsence(v)) {
			return advanced ? null
					: "'Not Present' works only for advanced settings";
		}
		Matcher m = OR_UNDEFINED.matcher(v);
		if (m.matches()) {
			if (!advanced) {
				return "'or Undefined' works only for advanced settings";
			}
			return checkPlain(c, m.group(1).trim());
		}
		return checkPlain(c, v);
	}

	private static String checkPlain(BenchmarkProfile.Control c, String v) {
		if (v == null || v.trim().isEmpty()) return "empty value";
		String t = v.trim();
		switch (c.valueType) {
			case "integer":
				return INTEGER.matcher(t).matches() ? null
						: "'" + t + "' is not a whole number";
			case "boolean": {
				String l = t.toLowerCase(Locale.ROOT);
				if ("true".equals(l) || "false".equals(l)) return null;
				if ("advanced_setting".equals(c.parameterKind)
						&& ("1".equals(l) || "0".equals(l))) {
					return null;
				}
				return "'" + t + "' is not true or false";
			}
			default:
				if ("n/a".equalsIgnoreCase(t)) return "N/A is not a value";
				if ("advanced_setting".equals(c.parameterKind)) {
					return checkTextAdvanced(c, t);
				}
				return null;
		}
	}

	/**
	 * Build 90 (N6): the explicit-empty forms on a text advanced setting.
	 * The evaluator passes a present, empty value against an expected value
	 * of {@code ""} or {@code NULL}, so those forms would turn that pass on
	 * for any control. {@code NULL} (any case) reads like a literal value
	 * and is rejected; a quoted blank such as {@code " "} is rejected; a
	 * bare {@code ""} is accepted only when the guide's own value for the
	 * control is itself empty ({@code esx.network-dvfilter}).
	 */
	private static String checkTextAdvanced(BenchmarkProfile.Control c,
			String t) {
		if ("null".equalsIgnoreCase(t)) {
			return "NULL is not a value; write \"\" for an explicitly empty "
					+ "setting where the guide allows it";
		}
		if (t.length() >= 2 && t.charAt(0) == '"'
				&& t.charAt(t.length() - 1) == '"') {
			String inner = t.substring(1, t.length() - 1);
			if (inner.trim().isEmpty()) {
				if (!inner.isEmpty()) return "a blank quoted value is not a value";
				return ControlEvaluator.expectsExplicitEmpty(c.suggestedValue)
						? null
						: "\"\" (explicitly empty) is accepted only where the "
								+ "guide's own value is empty";
			}
		}
		return null;
	}

	// ----- resolve against the loaded profiles ----------------------------

	/** The file applied to this cycle's profiles. */
	public static final class Resolved {
		public static final Resolved EMPTY = new Resolved(
				Collections.<String>emptySet(),
				Collections.<String, String>emptyMap(), null,
				Collections.<BenchmarkSelector.Kind, String>emptyMap(),
				Collections.<String>emptyList(),
				Collections.<String>emptyList());

		/** Control ids skipped. */
		public final Set<String> skipped;
		/** Control id to the accepted expected value. */
		public final Map<String, String> overridden;
		/** Instance-wide pin (bundled profile name), or null. */
		public final String instancePin;
		/** Per-kind pins (bundled profile names). */
		public final Map<BenchmarkSelector.Kind, String> kindPins;
		/** Every rejected entry, parse-time and resolve-time, one message each. */
		public final List<String> rejected;
		/** Every applied entry, for the per-cycle INFO line. */
		public final List<String> applied;

		Resolved(Set<String> skipped, Map<String, String> overridden,
				String instancePin, Map<BenchmarkSelector.Kind, String> kindPins,
				List<String> rejected, List<String> applied) {
			this.skipped = Collections.unmodifiableSet(skipped);
			this.overridden = Collections.unmodifiableMap(overridden);
			this.instancePin = instancePin;
			this.kindPins = Collections.unmodifiableMap(kindPins);
			this.rejected = Collections.unmodifiableList(rejected);
			this.applied = Collections.unmodifiableList(applied);
		}

		public boolean changesProfiles() {
			return !skipped.isEmpty() || !overridden.isEmpty();
		}

		/**
		 * The profile name pinned for {@code kind}: its own pin, else the
		 * instance pin, else null (no pin: the instance's mode applies).
		 */
		public String pinFor(BenchmarkSelector.Kind kind) {
			String p = kindPins.get(kind);
			return p != null ? p : instancePin;
		}

		/**
		 * Build 90 (review N1): the skipped ids in force for this instance.
		 * A control kind is scored from its pinned profile when the file pins
		 * that kind, otherwise from the instance's own profiles ({@code
		 * base}: every bundled one in Auto, the one chosen otherwise). An id
		 * counts when one of those profiles scores it for its kind. Both
		 * arguments are the profiles BEFORE adjustment, since a skip removes
		 * the control. A Skip accepted only because some other bundled
		 * profile carries the control changes nothing here and is not
		 * counted.
		 *
		 * @param base the instance's own profiles, unadjusted
		 * @param pins the pinned profile per kind, unadjusted (may be empty)
		 */
		public Set<String> skippedIn(Collection<BenchmarkProfile> base,
				Map<BenchmarkSelector.Kind, BenchmarkProfile> pins) {
			return inForce(skipped, base, pins);
		}

		/** As {@link #skippedIn}, for the overridden ids. */
		public Set<String> overriddenIn(Collection<BenchmarkProfile> base,
				Map<BenchmarkSelector.Kind, BenchmarkProfile> pins) {
			return inForce(overridden.keySet(), base, pins);
		}

		private static Set<String> inForce(Set<String> ids,
				Collection<BenchmarkProfile> base,
				Map<BenchmarkSelector.Kind, BenchmarkProfile> pins) {
			Set<String> out = new TreeSet<>();
			if (ids.isEmpty()) return out;
			List<BenchmarkProfile> candidates = new ArrayList<>();
			if (base != null) candidates.addAll(base);
			if (pins != null) candidates.addAll(pins.values());
			for (BenchmarkProfile p : candidates) {
				if (p == null) continue;
				for (BenchmarkProfile.Control c : p.controls) {
					if (!ids.contains(c.controlId) || !scored(c)) continue;
					BenchmarkSelector.Kind k = kindOfControl(c);
					BenchmarkProfile pinned = pins == null ? null : pins.get(k);
					boolean governs = pinned != null ? pinned == p
							: base != null && base.contains(p);
					if (governs) out.add(c.controlId);
				}
			}
			return out;
		}

		/**
		 * Copies of {@code in} with the skipped controls removed and the
		 * overridden expected values in place. {@code in} itself is returned
		 * when nothing changes the profiles. Names and order are kept.
		 */
		public Map<String, BenchmarkProfile> adjust(
				Map<String, BenchmarkProfile> in) {
			if (!changesProfiles() || in == null) return in;
			Map<String, BenchmarkProfile> out = new LinkedHashMap<>();
			for (Map.Entry<String, BenchmarkProfile> e : in.entrySet()) {
				out.put(e.getKey(), adjust(e.getValue()));
			}
			return Collections.unmodifiableMap(out);
		}

		/** One profile, adjusted as in {@link #adjust(Map)}. */
		public BenchmarkProfile adjust(BenchmarkProfile p) {
			if (!changesProfiles() || p == null) return p;
			List<BenchmarkProfile.Control> controls = new ArrayList<>();
			for (BenchmarkProfile.Control c : p.controls) {
				if (skipped.contains(c.controlId)) continue;
				String v = overridden.get(c.controlId);
				controls.add(v == null ? c : c.withSiteExpected(v));
			}
			return new BenchmarkProfile(p.name, controls);
		}

		/**
		 * The pinned profile per kind, taken from {@code byName} (the
		 * cycle's adjusted bundled profiles). A pin whose profile is not in
		 * {@code byName} is left out.
		 */
		public Map<BenchmarkSelector.Kind, BenchmarkProfile> pins(
				Map<String, BenchmarkProfile> byName) {
			Map<BenchmarkSelector.Kind, BenchmarkProfile> out =
					new EnumMap<>(BenchmarkSelector.Kind.class);
			if (byName == null) return out;
			for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
				String name = pinFor(k);
				if (name == null) continue;
				BenchmarkProfile p = byName.get(name);
				if (p != null) out.put(k, p);
			}
			return out;
		}
	}

	/**
	 * Check the parsed entries against every loaded profile.
	 *
	 * <ul>
	 *   <li>A control id no loaded profile carries is rejected.</li>
	 *   <li>A Skip or Override of a control no loaded profile scores (manual
	 *       review, or no way to read it) is rejected: it would have no
	 *       effect.</li>
	 *   <li>An Override whose value fails {@link #checkValue} for the
	 *       control in any profile that scores it is rejected (the SCG value
	 *       stays everywhere).</li>
	 *   <li>An Override of a skipped control is rejected (the Skip wins).</li>
	 * </ul>
	 *
	 * @param parsed   the parsed file (null: nothing to apply)
	 * @param profiles every profile loaded this cycle (bundled, and the
	 *                 instance's own when it is not bundled)
	 */
	public static Resolved resolve(Parsed parsed,
			Collection<BenchmarkProfile> profiles) {
		if (parsed == null) return Resolved.EMPTY;
		List<String> rejected = new ArrayList<>(parsed.rejected);
		List<String> applied = new ArrayList<>();
		Set<String> skipped = new TreeSet<>();
		Map<String, String> overridden = new LinkedHashMap<>();
		String instancePin = null;
		Map<BenchmarkSelector.Kind, String> kindPins =
				new EnumMap<>(BenchmarkSelector.Kind.class);

		Map<String, List<BenchmarkProfile.Control>> byId = new LinkedHashMap<>();
		if (profiles != null) {
			for (BenchmarkProfile p : profiles) {
				for (BenchmarkProfile.Control c : p.controls) {
					byId.computeIfAbsent(c.controlId,
							k -> new ArrayList<>()).add(c);
				}
			}
		}
		Set<String> skipIds = new TreeSet<>();
		for (Entry e : parsed.entries) {
			if (e.type == Type.SKIP) skipIds.add(e.control);
		}

		for (Entry e : parsed.entries) {
			switch (e.type) {
				case PROFILE:
					if (e.kind == null) {
						instancePin = e.profileName;
						applied.add("profile " + e.profileName
								+ " for every kind");
					} else {
						kindPins.put(e.kind, e.profileName);
						applied.add("profile " + e.profileName + " for "
								+ e.kind.rollupName);
					}
					break;
				case SKIP: {
					String why = scoredProblem(byId.get(e.control));
					if (why != null) {
						rejected.add(e.text + ": " + why);
						break;
					}
					skipped.add(e.control);
					applied.add("skip " + e.control);
					break;
				}
				default: {   // OVERRIDE
					if (skipIds.contains(e.control)) {
						rejected.add(e.text + ": the control is also skipped "
								+ "(the Skip wins)");
						break;
					}
					List<BenchmarkProfile.Control> cs = byId.get(e.control);
					String why = scoredProblem(cs);
					if (why == null) {
						for (BenchmarkProfile.Control c : cs) {
							if (!scored(c)) continue;
							String bad = checkValue(c, e.expected);
							if (bad != null) {
								why = bad + " (control value type "
										+ c.valueType + "); the guide's value "
										+ "is kept";
								break;
							}
						}
					}
					if (why != null) {
						rejected.add(e.text + ": " + why);
						break;
					}
					overridden.put(e.control, e.expected);
					applied.add("override " + e.control + " expected "
							+ e.expected);
					break;
				}
			}
		}
		return new Resolved(skipped, overridden, instancePin, kindPins,
				rejected, applied);
	}

	/**
	 * True when the collector for the control's object kind scores it
	 * ({@link BenchmarkSelector#evaluatedFor}).
	 */
	static boolean scored(BenchmarkProfile.Control c) {
		BenchmarkSelector.Kind k = kindOfControl(c);
		return k != null && BenchmarkSelector.evaluatedFor(k, c);
	}

	/** The object kind a control applies to; null for an unknown kind. */
	static BenchmarkSelector.Kind kindOfControl(BenchmarkProfile.Control c) {
		if (c.isHostControl()) return BenchmarkSelector.Kind.HOST;
		if (c.isVmControl()) return BenchmarkSelector.Kind.VM;
		if (c.isVCenterControl()) return BenchmarkSelector.Kind.VCENTER;
		if (c.isClusterControl()) return BenchmarkSelector.Kind.CLUSTER;
		if (c.isDvsControl()) return BenchmarkSelector.Kind.VDS;
		if (c.isDvpgControl()) return BenchmarkSelector.Kind.PORTGROUP;
		return null;
	}

	/** Why a Skip or Override of these controls would do nothing; null if fine. */
	private static String scoredProblem(List<BenchmarkProfile.Control> cs) {
		if (cs == null || cs.isEmpty()) {
			return "unknown control id (control ids are listed in REFERENCE.md "
					+ "and the bundled profiles)";
		}
		for (BenchmarkProfile.Control c : cs) {
			if (scored(c)) return null;
		}
		return "the pack does not check this control automatically (manual "
				+ "review, or no way to read it), so the entry has no effect";
	}
}
