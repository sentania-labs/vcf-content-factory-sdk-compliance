package com.vcfcf.adapters.compliance;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Raw-SOAP esxcli reader that rides the adapter's <b>existing vCenter
 * session</b> — no host credentials, no per-host SOAP session, no
 * tickets. It reproduces the proven {@code ReflectManagedMethodExecuter
 * .ExecuteSoap} encoding from
 * {@code context/investigations/esxcli-soap-reflect-executer-spike.md}
 * §0 verbatim.
 *
 * <p><b>Why raw SOAP and not JAX-WS stubs.</b> The reflect / dynamic
 * esxcli types ({@code ReflectManagedMethodExecuter}, the
 * {@code vim.EsxCLI.*} dynamic managed types) are NOT in the bundled
 * vim25 bindings (they live in the internal {@code urn:reflect} WSDL,
 * version {@code vim.version.version5}, which neither stock binding
 * ships). So there is no generated stub to call and — by construction —
 * no concrete type to cast to. This client hand-builds the SOAP
 * envelope, POSTs it to the vCenter {@code /sdk} with the live vCenter
 * session cookie, and parses the response DOM generically. That matches
 * the skill's "reflection-tolerant / never cast" posture: a missing
 * field is null (skip), never an exception and never a default.
 *
 * <p><b>The three-call sequence</b> (all over the one vCenter session):
 * <ol>
 *   <li>{@code RetrieveManagedMethodExecuter} with {@code _this
 *       type="HostSystem"} = the host MoRef -> the executer MoRef.</li>
 *   <li>{@code ExecuteSoap} on that executer: {@code moid =
 *       "ha-cli-handler-" + namespace-with-dashes}; {@code version =
 *       "urn:vim25/5.0"} (constant — the spike fix); {@code method =
 *       "vim.EsxCLI." + namespace-dotted}; {@code argument} omitted for
 *       a no-arg {@code get}.</li>
 *   <li>The response {@code returnval/response} holds XML-escaped inner
 *       {@code <obj>}; this client unescapes (the parser does it for
 *       free since {@code response} is text-content) and reads the
 *       PascalCase child elements.</li>
 * </ol>
 *
 * <p><b>Per-cycle, per-host, per-command cache.</b> One esxcli command
 * returns many fields, and many controls may reference the same command
 * ({@code system.syslog.config.get}). {@link #readCommandResult} caches
 * the parsed field map per (hostMoid, namespace.command) until the next
 * {@link #beginCycle}, so multiple controls cost exactly one
 * {@code ExecuteSoap} per host per cycle. The executer MoRef (call 1) is
 * cached per host the same way.
 *
 * <p>Build 86: a per-host negative entry for the cycle. The first
 * transport failure on a request for a host (read or connect timeout,
 * refused or reset connection, any I/O error; every request goes to
 * vCenter's {@code /sdk}, which relays it to the host, so the failure may
 * be vCenter's rather than the host's) or an executer lookup that returns
 * no executer marks that host unreachable until the next
 * {@link #beginCycle}; its remaining commands fail at once, without a
 * network call, and keep the first failure as their reason. A command
 * that the host answered with a fault (unknown command, esxcli fault,
 * HTTP 500) fails that command only. Without this a connected host that
 * stopped answering cost one 120 s read timeout per distinct command, up
 * to 7 per host per cycle.
 *
 * <p>Build 85: this client lives as long as the vCenter SOAP session,
 * which the per-cycle keepalive can hold open indefinitely, so the
 * caches are emptied at the start of every cycle by {@link #beginCycle}
 * (via {@code VSphereClient.beginCycle}). Before build 85 nothing emptied
 * them while the session survived, so a cached result could be served
 * for the life of the session.
 */
final class EsxcliSoapClient {

	/**
	 * Sentinel returned by {@link #readField} when the command call
	 * itself failed (unknown command / SOAP fault / parse failure) — as
	 * opposed to the command succeeding but not carrying the requested
	 * field. Both map to UNREADABLE upstream, but the distinction is
	 * preserved in logs.
	 */
	static final String COMMAND_FAILED = "__esxcli_command_failed__";

	private final String sdkUrl;
	private final String sessionCookie;
	private final SSLSocketFactory sslFactory;

	// Per-cycle caches, emptied by beginCycle() at the start of every
	// collection cycle (this client itself lives as long as the session).
	//   hostMoid -> executer MoRef value (call 1)
	private final Map<String, String> executerByHost = new HashMap<>();
	//   hostMoid + "|" + namespace.command -> parsed result (struct OR
	//   rows). A FAILED ParsedResult is cached so a second control
	//   referencing the same command does NOT re-issue the call.
	private final Map<String, ParsedResult> resultCache = new HashMap<>();
	//   hostMoid -> why the host is skipped for the rest of the cycle
	//   (build 86: first transport failure, or no executer returned).
	private final Map<String, String> unreachableHosts = new HashMap<>();
	//   hosts whose unreachable entry has already been handed to the
	//   adapter's WARN this cycle (build 87: one WARN per host per cycle).
	private final Set<String> unreachableReported = new HashSet<>();

	/** Longest exception message kept in a reason (log line hygiene). */
	static final int REASON_MESSAGE_MAX = 160;

	/**
	 * Parsed esxcli command result. Exactly one of {@code struct}
	 * (a {@code get} command's single field map) or {@code rows} (a
	 * {@code list} command's {@code ArrayOfDataObject} rows) is non-null
	 * on success; {@code failed} is true (and both null) when the
	 * command call itself failed (unknown command / fault / parse error).
	 * Cached per (host, command) for the cycle.
	 */
	static final class ParsedResult {
		final boolean failed;
		final Map<String, String> struct;          // get -> field map
		final List<Map<String, String>> rows;       // list -> row field maps

		private ParsedResult(boolean failed, Map<String, String> struct,
				List<Map<String, String>> rows) {
			this.failed = failed;
			this.struct = struct;
			this.rows = rows;
		}

		static ParsedResult ofStruct(Map<String, String> struct) {
			return new ParsedResult(false, struct, null);
		}

		static ParsedResult ofRows(List<Map<String, String>> rows) {
			return new ParsedResult(false, null, rows);
		}

		static ParsedResult ofFailure() {
			return new ParsedResult(true, null, null);
		}
	}

	/**
	 * The two uncached SOAP calls; a seam for the tests (build 86: split so
	 * the executer cache and the per-host negative entry are observable).
	 * An {@link java.io.IOException} from either call is a transport
	 * failure and marks the host unreachable for the cycle.
	 */
	interface Transport {
		/** Call 1. Null when vCenter returned no executer (a fault). */
		String lookupExecuter(String hostMoid) throws Exception;

		/** Call 2. A FAILED result when the host answered with a fault. */
		ParsedResult execute(String executer, String namespaceCommand)
				throws Exception;
	}

	private final Transport transport;

	EsxcliSoapClient(String sdkUrl, String sessionCookie,
			SSLSocketFactory sslFactory) {
		this.sdkUrl = sdkUrl;
		this.sessionCookie = sessionCookie;
		this.sslFactory = sslFactory;
		this.transport = new Transport() {
			@Override
			public String lookupExecuter(String hostMoid) throws Exception {
				return lookupExecuterLive(hostMoid);
			}

			@Override
			public ParsedResult execute(String executer,
					String namespaceCommand) throws Exception {
				return executeCommand(executer, namespaceCommand);
			}
		};
	}

	/** Test-only: no network, every uncached call goes to {@code transport}. */
	EsxcliSoapClient(Transport transport) {
		this.sdkUrl = null;
		this.sessionCookie = null;
		this.sslFactory = null;
		this.transport = transport;
	}

	/**
	 * Build 86: the cycle start for a possibly absent client (no session
	 * yet). {@code VSphereClient.beginCycle} is exactly this call, so the
	 * delegation is testable without the VCF Ops SDK on the classpath.
	 */
	static void beginCycleOn(EsxcliSoapClient client) {
		if (client != null) client.beginCycle();
	}

	/**
	 * Build 85: start a new collection cycle. Empties the result cache and
	 * the executer cache so every (host, command) is read again this cycle;
	 * within the cycle the cache still dedupes. A cached FAILED result is
	 * dropped too, so a host that was unreachable last cycle is retried.
	 * Build 86: the per-host unreachable entries are dropped as well.
	 *
	 * <p>Why: unreadable-is-not-compliant cuts both ways. A stale pass is a
	 * false pass: a host read compliant once and changed since would keep
	 * reporting compliant, and a read that failed once would keep the host
	 * unreadable, for as long as the vCenter session lived. No vCenter
	 * login is involved; the session and its cookie are unchanged.
	 */
	synchronized void beginCycle() {
		resultCache.clear();
		executerByHost.clear();
		unreachableHosts.clear();
		unreachableReported.clear();
	}

	/**
	 * Build 86: why this host's esxcli reads are being skipped for the rest
	 * of the cycle, or null when they are not. Diagnostics only: the reads
	 * themselves already return {@link #COMMAND_FAILED} (UNREADABLE).
	 */
	synchronized String unreachableReason(String hostMoid) {
		return unreachableHosts.get(hostMoid);
	}

	/**
	 * Build 87: the unreachable reason for this host the first time it is
	 * asked for after the host was marked in this cycle, null on every
	 * later call until the next {@link #beginCycle} (and null when the host
	 * is not marked). The adapter logs one WARN per host per cycle from
	 * this, naming the host.
	 */
	synchronized String takeUnreachableToReport(String hostMoid) {
		String reason = unreachableHosts.get(hostMoid);
		if (reason == null || !unreachableReported.add(hostMoid)) {
			return null;
		}
		return reason;
	}

	/**
	 * Build 87: the unreadable reason for a {@link #COMMAND_FAILED} read.
	 * {@code unreachable} is {@link #unreachableReason} for the host (null
	 * when the host is not marked); {@code lastFault} is the last fault text
	 * seen, or null. A marked host gets {@code esxcli-host-unreachable}, any
	 * other failure {@code esxcli-command-failed}.
	 */
	static String commandFailedReason(String namespaceCommand,
			String unreachable, String lastFault) {
		if (unreachable != null) {
			return "esxcli-host-unreachable: " + namespaceCommand
					+ " (host skipped for the rest of this cycle after: "
					+ unreachable + ")";
		}
		return "esxcli-command-failed: " + namespaceCommand
				+ (lastFault != null ? " (" + lastFault + ")" : "");
	}

	/**
	 * Read a single PascalCase field from an esxcli {@code get} command
	 * for a host. Returns the field's text value, or {@code null} when
	 * the command succeeded but the field is absent, or
	 * {@link #COMMAND_FAILED} when the command call itself failed
	 * (unknown command / fault / parse error). Upstream maps both
	 * {@code null} and {@code COMMAND_FAILED} to the UNREADABLE outcome.
	 *
	 * @param hostMoid          the {@code host-N} MoRef value
	 * @param namespaceCommand  dotted, e.g. {@code system.syslog.config.get}
	 * @param field             PascalCase result field, e.g.
	 *                          {@code LocalLogOutputIsPersistent}
	 */
	String readField(String hostMoid, String namespaceCommand, String field) {
		ParsedResult parsed = readCommandResult(hostMoid, namespaceCommand);
		if (parsed == null || parsed.failed) {
			return COMMAND_FAILED;
		}
		// A get-struct exposes its fields directly; a list exposes none at
		// the top level, so a plain field read on a list returns null (the
		// caller must use the row-selecting overload). Build-36 callers
		// only ever read get-struct fields, so this is unchanged for them.
		if (parsed.struct != null) {
			return fieldIgnoreCase(parsed.struct, field);
		}
		return null;
	}

	/**
	 * Build 74: exact field name first, then a case-insensitive match
	 * (esxcli struct field names come from the vendor SCG audit script
	 * for some rows, e.g. {@code system.settings.encryption.get}, and are
	 * not yet confirmed on the wire). Null when absent either way.
	 */
	static String fieldIgnoreCase(Map<String, String> struct, String field) {
		if (struct == null || field == null) return null;
		String v = struct.get(field);
		if (v != null) return v;
		for (Map.Entry<String, String> e : struct.entrySet()) {
			if (e.getKey() != null && e.getKey().equalsIgnoreCase(field)) {
				return e.getValue();
			}
		}
		return null;
	}

	/** Field names the command's struct actually carries (diagnostics). */
	synchronized java.util.Set<String> structFields(String hostMoid,
			String namespaceCommand) {
		ParsedResult cached = resultCache.get(hostMoid + "|" + namespaceCommand);
		if (cached == null || cached.struct == null) {
			return java.util.Collections.emptySet();
		}
		return new java.util.TreeSet<>(cached.struct.keySet());
	}

	/**
	 * Build-37 row-selecting read for {@code list} commands that return
	 * {@code ArrayOfDataObject} rows (e.g.
	 * {@code system.ssh.server.config.list},
	 * {@code system.account.list}). Finds the first row whose
	 * {@code selectorField} text equals {@code selectorValue}
	 * (case-insensitive) and returns that row's {@code field} text.
	 *
	 * <p>Returns {@code null} when the command succeeded but no row
	 * matched the selector, or the matched row lacks {@code field}, or
	 * the command returned a get-struct rather than a list (a selector
	 * was applied to a non-list command — a recipe authoring error,
	 * surfaced as UNREADABLE rather than guessed). Returns
	 * {@link #COMMAND_FAILED} when the command call itself failed.
	 * Both null and COMMAND_FAILED fold to UNREADABLE upstream — never
	 * a false pass (the build-35 contract).
	 *
	 * @param selectorField  PascalCase row field to match on, e.g.
	 *                       {@code Key} (ssh config) / {@code UserID}
	 *                       (accounts)
	 * @param selectorValue  the row value to match, e.g. {@code ciphers}
	 *                       / {@code dcui}
	 * @param field          PascalCase row field to return, e.g.
	 *                       {@code Value} / {@code Shellaccess}
	 */
	String readRowField(String hostMoid, String namespaceCommand,
			String selectorField, String selectorValue, String field) {
		ParsedResult parsed = readCommandResult(hostMoid, namespaceCommand);
		if (parsed == null || parsed.failed) {
			return COMMAND_FAILED;
		}
		if (parsed.rows == null) {
			// A selector was applied to a command that did not return a
			// list — not readable as a row. UNREADABLE upstream.
			return null;
		}
		for (Map<String, String> row : parsed.rows) {
			String sel = row.get(selectorField);
			if (sel != null && sel.trim().equalsIgnoreCase(selectorValue)) {
				return row.get(field);
			}
		}
		// No matching row — the selector value isn't present. UNREADABLE.
		return null;
	}

	/**
	 * Execute (and cache) one esxcli command on one host. The first call
	 * for a given (host, command) issues the two SOAP calls; subsequent
	 * calls within the cycle hit the cache (until {@link #beginCycle}).
	 * Returns a FAILED
	 * {@link ParsedResult} (cached so it isn't retried this cycle) on any
	 * failure, else a struct ({@code get}) or rows ({@code list}) result.
	 */
	synchronized ParsedResult readCommandResult(String hostMoid,
			String namespaceCommand) {
		String cacheKey = hostMoid + "|" + namespaceCommand;
		ParsedResult cached = resultCache.get(cacheKey);
		if (cached != null) {
			return cached;
		}

		ParsedResult result = null;
		if (!unreachableHosts.containsKey(hostMoid)) {
			try {
				String executer = getExecuter(hostMoid);
				if (executer == null) {
					// No executer, so no command can run on this host.
					unreachableHosts.put(hostMoid, "no executer returned by "
							+ "RetrieveManagedMethodExecuter");
				} else {
					result = transport.execute(executer, namespaceCommand);
				}
			} catch (java.io.IOException e) {
				// Build 86: timeout / connect / I/O on the request to
				// vCenter's /sdk for this host (vCenter or the host). The
				// host's other commands would pay the same timeout; skip
				// them this cycle.
				unreachableHosts.put(hostMoid, describe(e));
			} catch (Exception e) {
				// Any other failure fails this command only, cached so a
				// second control on the same command does not re-issue it.
				result = null;
			}
		}
		if (result == null) {
			result = ParsedResult.ofFailure();
		}
		resultCache.put(cacheKey, result);
		return result;
	}

	/** {@code Class: message}, message capped and on one line. */
	static String describe(Exception e) {
		String msg = e.getMessage();
		String out = e.getClass().getSimpleName();
		if (msg != null && !msg.trim().isEmpty()) {
			String m = msg.replaceAll("\\s+", " ").trim();
			if (m.length() > REASON_MESSAGE_MAX) {
				m = m.substring(0, REASON_MESSAGE_MAX) + "...";
			}
			out += ": " + m;
		}
		return out;
	}

	// ----- Call 1: RetrieveManagedMethodExecuter --------------------------

	/** Cached per host for the cycle; null when none was returned. */
	private synchronized String getExecuter(String hostMoid) throws Exception {
		String cached = executerByHost.get(hostMoid);
		if (cached != null) return cached;
		String executer = transport.lookupExecuter(hostMoid);
		if (executer == null) return null;
		executerByHost.put(hostMoid, executer);
		return executer;
	}

	private String lookupExecuterLive(String hostMoid) throws Exception {
		String body =
				"<RetrieveManagedMethodExecuter xmlns=\"urn:vim25\">"
				+ "<_this type=\"HostSystem\">" + xmlEscape(hostMoid) + "</_this>"
				+ "</RetrieveManagedMethodExecuter>";
		Document resp = post(body, "urn:vim25/RetrieveManagedMethodExecuter");
		if (resp == null) return null;
		// Response: <RetrieveManagedMethodExecuterResponse><returnval
		//   type="ReflectManagedMethodExecuter">ManagedMethodExecuter-N
		//   </returnval></...>
		Element returnval = firstChildByLocalName(resp.getDocumentElement(),
				"returnval");
		if (returnval == null) return null;
		String executer = textOf(returnval);
		if (executer == null || executer.trim().isEmpty()) return null;
		return executer.trim();
	}

	// ----- Call 2: ExecuteSoap (no-arg get OR list) -----------------------

	/**
	 * Execute an esxcli {@code get} or {@code list} command via
	 * {@code ExecuteSoap} and parse the inner {@code <obj>} into either a
	 * struct field map ({@code get}) or a list of row field maps
	 * ({@code list} -> {@code ArrayOfDataObject}). Returns a FAILED
	 * {@link ParsedResult} on a SOAP fault, an esxcli-level
	 * {@code <fault>}, or a missing/empty {@code <response>}.
	 *
	 * <p>moid / method / version derivation (spike §0.4), mechanical:
	 * for command parts {@code [p0 ... pN]},
	 * {@code namespace = p0..p(N-1)}; {@code moid = "ha-cli-handler-" +
	 * namespace joined by "-"}; {@code method = "vim.EsxCLI." +
	 * p0..pN joined by "."}; {@code version = "urn:vim25/5.0"}.
	 *
	 * <p>Build 37 only handles NO-ARG commands ({@code get} / {@code
	 * list} with no key). Argument-bearing commands (e.g. firewall
	 * {@code allowedip.list} with a {@code rulesetid}) are not issued by
	 * any current recipe; see the held-controls note in the build log.
	 */
	private ParsedResult executeCommand(String executer,
			String namespaceCommand) throws Exception {
		String[] parts = namespaceCommand.split("\\.");
		if (parts.length < 2) {
			// Need at least <namespace>.<command>.
			return ParsedResult.ofFailure();
		}
		StringBuilder nsDashes = new StringBuilder();
		for (int i = 0; i < parts.length - 1; i++) {
			if (i > 0) nsDashes.append('-');
			nsDashes.append(parts[i]);
		}
		String moid = "ha-cli-handler-" + nsDashes;
		String method = "vim.EsxCLI." + namespaceCommand;
		String version = "urn:vim25/5.0";

		String body =
				"<ExecuteSoap xmlns=\"urn:vim25\">"
				+ "<_this type=\"ReflectManagedMethodExecuter\">"
				+ xmlEscape(executer) + "</_this>"
				+ "<moid>" + xmlEscape(moid) + "</moid>"
				+ "<version>" + xmlEscape(version) + "</version>"
				+ "<method>" + xmlEscape(method) + "</method>"
				// <argument> omitted for a no-arg get/list (spike §0.2).
				+ "</ExecuteSoap>";

		Document resp = post(body, "urn:vim25/ExecuteSoap");
		if (resp == null) return ParsedResult.ofFailure();

		Element returnval = firstChildByLocalName(resp.getDocumentElement(),
				"returnval");
		if (returnval == null) return ParsedResult.ofFailure();

		// An esxcli-level error comes back as <fault> inside returnval
		// (faultMsg / faultDetail); treat as command-failed.
		Element fault = firstChildByLocalName(returnval, "fault");
		if (fault != null) {
			return ParsedResult.ofFailure();
		}

		Element response = firstChildByLocalName(returnval, "response");
		if (response == null) return ParsedResult.ofFailure();
		String innerXml = textOf(response);
		if (innerXml == null || innerXml.trim().isEmpty()) {
			return ParsedResult.ofFailure();
		}

		// The text content of <response> IS the (already-unescaped by the
		// XML parser) inner <obj> document. Parse it as a standalone doc.
		// It carries an xsi:type without a namespace declaration for the
		// xsi prefix, so parse non-namespace-aware and read by local name.
		Document inner = parseXml(innerXml.trim());
		if (inner == null) return ParsedResult.ofFailure();
		Element obj = inner.getDocumentElement();
		if (obj == null) return ParsedResult.ofFailure();

		// Disambiguate get vs list by the inner obj's xsi:type
		// (spike §0.3): "ArrayOfDataObject" -> list of <DataObject> rows;
		// anything else -> a single get struct.
		String xsiType = obj.getAttribute("xsi:type");
		boolean isList = xsiType != null
				&& xsiType.contains("ArrayOfDataObject");
		// Defensive: even without the attribute, if the obj's element
		// children are ALL <DataObject>, treat it as a list.
		if (!isList && hasDataObjectChildren(obj)) {
			isList = true;
		}

		if (isList) {
			List<Map<String, String>> rows = new ArrayList<>();
			NodeList children = obj.getChildNodes();
			for (int i = 0; i < children.getLength(); i++) {
				Node n = children.item(i);
				if (n.getNodeType() != Node.ELEMENT_NODE) continue;
				Element row = (Element) n;
				// Each row is a <DataObject> (some bindings drop the
				// element name to the row's own type — accept any element
				// child as a row when we've decided this is a list).
				rows.add(parseFieldMap(row));
			}
			return ParsedResult.ofRows(rows);
		}

		// get -> single struct: PascalCase fields are direct children.
		return ParsedResult.ofStruct(parseFieldMap(obj));
	}

	/** True iff every element child of {@code obj} is a {@code DataObject}. */
	private static boolean hasDataObjectChildren(Element obj) {
		NodeList children = obj.getChildNodes();
		boolean sawElement = false;
		for (int i = 0; i < children.getLength(); i++) {
			Node n = children.item(i);
			if (n.getNodeType() != Node.ELEMENT_NODE) continue;
			sawElement = true;
			if (!"DataObject".equals(localName((Element) n))) {
				return false;
			}
		}
		return sawElement;
	}

	/** Parse direct element children of {@code parent} into a field map. */
	private static Map<String, String> parseFieldMap(Element parent) {
		Map<String, String> fields = new HashMap<>();
		NodeList children = parent.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node n = children.item(i);
			if (n.getNodeType() != Node.ELEMENT_NODE) continue;
			Element child = (Element) n;
			String name = localName(child);
			if (name == null) continue;
			fields.put(name, textOf(child));
		}
		return fields;
	}

	// ----- HTTP / XML plumbing -------------------------------------------

	/**
	 * POST a SOAP body to the vCenter {@code /sdk} with the live vCenter
	 * session cookie and return the parsed response Document, or
	 * {@code null} on a non-2xx response (a SOAP fault HTTP 500 included
	 * — the caller maps any failure to command-failed). Reuses the
	 * adapter's trust-all SSL factory.
	 */
	private Document post(String soapBody, String soapAction) throws Exception {
		String envelope =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<soapenv:Envelope "
				+ "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
				+ "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
				+ "<soapenv:Body>" + soapBody + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

		URL url = new URL(sdkUrl);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		if (conn instanceof HttpsURLConnection && sslFactory != null) {
			((HttpsURLConnection) conn).setSSLSocketFactory(sslFactory);
		}
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setConnectTimeout(30000);
		conn.setReadTimeout(120000);
		conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
		conn.setRequestProperty("SOAPAction", soapAction);
		if (sessionCookie != null && !sessionCookie.isEmpty()) {
			conn.setRequestProperty("Cookie", sessionCookie);
		}

		byte[] payload = envelope.getBytes(StandardCharsets.UTF_8);
		try (OutputStream os = conn.getOutputStream()) {
			os.write(payload);
		}

		int code = conn.getResponseCode();
		InputStream is = (code >= 200 && code < 300)
				? conn.getInputStream() : conn.getErrorStream();
		byte[] respBytes = drain(is);
		conn.disconnect();
		if (code < 200 || code >= 300) {
			// SOAP fault (500) or auth failure — command-failed upstream.
			return null;
		}
		if (respBytes == null || respBytes.length == 0) return null;
		return parseXml(new String(respBytes, StandardCharsets.UTF_8));
	}

	private static byte[] drain(InputStream is) throws Exception {
		if (is == null) return null;
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] buf = new byte[8192];
			int n;
			while ((n = is.read(buf)) >= 0) {
				bos.write(buf, 0, n);
			}
			return bos.toByteArray();
		} finally {
			// Close even if the read throws mid-stream, so the underlying
			// connection's input is released rather than left dangling.
			try {
				is.close();
			} catch (Exception ignored) {}
		}
	}

	private static Document parseXml(String xml) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			// Non-namespace-aware: we read by LOCAL name throughout, and
			// the inner <obj> uses an xsi: prefix without a declaration on
			// the standalone fragment (a namespace-aware parse would
			// reject it). Disable external entities defensively.
			dbf.setNamespaceAware(false);
			try {
				dbf.setFeature(
						"http://apache.org/xml/features/disallow-doctype-decl",
						true);
			} catch (Exception ignored) { /* not all impls support it */ }
			try {
				dbf.setFeature(
						"http://xml.org/sax/features/external-general-entities",
						false);
			} catch (Exception ignored) {}
			try {
				dbf.setFeature(
						"http://xml.org/sax/features/external-parameter-entities",
						false);
			} catch (Exception ignored) {}
			DocumentBuilder db = dbf.newDocumentBuilder();
			return db.parse(new java.io.ByteArrayInputStream(
					xml.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception e) {
			return null;
		}
	}

	/** First direct-child Element whose local name equals {@code name}. */
	private static Element firstChildByLocalName(Element parent, String name) {
		if (parent == null) return null;
		// Search the whole subtree shallowly first (direct children), then
		// fall back to a descendant search so we tolerate the SOAP Body /
		// Envelope wrapping without binding to the exact nesting depth.
		Element direct = firstDirectChild(parent, name);
		if (direct != null) return direct;
		NodeList all = parent.getElementsByTagName("*");
		for (int i = 0; i < all.getLength(); i++) {
			Node n = all.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE
					&& name.equals(localName((Element) n))) {
				return (Element) n;
			}
		}
		return null;
	}

	private static Element firstDirectChild(Element parent, String name) {
		NodeList kids = parent.getChildNodes();
		for (int i = 0; i < kids.getLength(); i++) {
			Node n = kids.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE
					&& name.equals(localName((Element) n))) {
				return (Element) n;
			}
		}
		return null;
	}

	/** Local name (strip any prefix) of an element. */
	private static String localName(Element e) {
		String ln = e.getLocalName();
		if (ln != null) return ln;
		String tag = e.getTagName();
		int colon = tag.indexOf(':');
		return colon >= 0 ? tag.substring(colon + 1) : tag;
	}

	/** Concatenated text content of an element. */
	private static String textOf(Element e) {
		if (e == null) return null;
		return e.getTextContent();
	}

	private static String xmlEscape(String s) {
		if (s == null) return "";
		StringBuilder sb = new StringBuilder(s.length());
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '&': sb.append("&amp;"); break;
				case '<': sb.append("&lt;"); break;
				case '>': sb.append("&gt;"); break;
				case '"': sb.append("&quot;"); break;
				case '\'': sb.append("&apos;"); break;
				default: sb.append(c);
			}
		}
		return sb.toString();
	}
}
