package com.vcfcf.adapters.compliance;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.integrien.alive.common.adapter3.Logger;

/**
 * Raw-SOAP vSphere (vim25) client — build 43 rewrite.
 *
 * <p><b>Why raw SOAP, not JAX-WS.</b> The previous implementation built
 * vim25 SOAP stubs through JAX-WS ({@code VimService} / {@code
 * javax.xml.ws.Service}). On VCF Ops 9.1 the platform pairs a javax
 * {@code jaxws-api-2.3.1} with a jakarta {@code jaxws-rt-4.0.3}; parent-first
 * delegation resolves {@code com.sun.xml.ws.spi.ProviderImpl} to the jakarta
 * class, which does not extend the javax {@code Provider} the lookup expects
 * → {@code "Error while searching for service [javax.xml.ws.spi.Provider]"}
 * every cycle (the adapter has NEVER collected on 9.1). See
 * {@code context/investigations/prod_91_jaxws_provider_failure.md}.
 *
 * <p>This rewrite removes JAX-WS entirely: every vim25 operation is a
 * hand-built SOAP 1.1 envelope POSTed to the vCenter {@code /sdk} over
 * {@link HttpURLConnection}, parsed with JDK-built-in JAXP DOM (the collision
 * was JAX-WS service discovery, NOT JAXP — DOM/SAX are safe). It drops
 * {@code vim25.jar}, {@code vim-vmodl-bindings-8.0.2.jar}, {@code
 * jaxws-api-2.1.jar}, {@code jaxws-rt-2.3.1.jar}, {@code
 * javax.xml.soap-api-1.4.0.jar} from {@code lib/}. The proven
 * {@link EsxcliSoapClient} (already raw SOAP since build 36) is the template
 * and is reused unchanged for the esxcli slice.
 *
 * <p><b>Value semantics preserved.</b> The public method surface, the
 * {@link #UNREADABLE} sentinel, the recipe grammar, and every style's
 * compliant/non-compliant/unreadable outcome are byte-for-byte identical to
 * the JAX-WS implementation (golden comparison gate vs build 41). Where the
 * old code walked vim25 binding objects with reflective getters, this code
 * walks the response DOM by element local-name — the same node, the same
 * value, no concrete-type casts (the "reflection-tolerant / never cast"
 * posture carries over: a missing element is null/skip, never an exception
 * and never a sentinel pass).
 *
 * <p><b>The MOID / type discipline.</b> {@link MoRef} carries the
 * managed-object {@code type} + {@code value} pair exactly as vim25's
 * {@code ManagedObjectReference} did. PropertyCollector requests carry the
 * object's {@code type} so the server resolves the right property set.
 */
public final class VSphereClient {

	private final String vcenterUrl;       // https://<host>/sdk
	private final String username;
	private final String password;
	private final SSLSocketFactory sslFactory;
	private final Logger log;              // nullable — standalone use logs nothing

	// SOAP session state.
	private volatile String sessionCookie;     // vmware_soap_session=...
	private volatile MoRef propertyCollector;
	private volatile MoRef viewManager;
	private volatile MoRef rootFolder;
	private volatile MoRef sessionManager;
	private volatile MoRef settingOptionMgr;   // ServiceContent.setting
	private volatile String aboutInstanceUuid;
	private volatile String aboutFullName;

	// esxcli reader (build 36) — rides THIS vCenter session. Rebuilt on
	// every (re)connect so it carries the live cookie and a fresh per-cycle
	// command cache. Lazily used on first esxcli recipe read.
	private volatile EsxcliSoapClient esxcli;

	public VSphereClient(String vcenterHost, String username, String password) {
		this(vcenterHost, username, password, null);
	}

	/**
	 * @param log adapter logger for SOAP-walk breadcrumbs (response-shape per
	 *            RetrieveProperties, inventory counts). May be null (standalone
	 *            / test use), in which case the client logs nothing.
	 */
	public VSphereClient(String vcenterHost, String username, String password,
			Logger log) {
		this.vcenterUrl = "https://" + vcenterHost + "/sdk";
		this.username = username;
		this.password = password;
		this.sslFactory = trustAllSslFactory();
		this.log = log;
	}

	private void logInfo(String msg)  { if (log != null) log.info(msg); }
	private void logDebug(String msg) { if (log != null) log.debug(msg); }
	private void logWarn(String msg)  { if (log != null) log.warn(msg); }

	// -----------------------------------------------------------------------
	// Session lifecycle
	// -----------------------------------------------------------------------

	public void connect() throws Exception {
		// RetrieveServiceContent does not require a session cookie.
		String body =
				"<RetrieveServiceContent xmlns=\"urn:vim25\">"
				+ "<_this type=\"ServiceInstance\">ServiceInstance</_this>"
				+ "</RetrieveServiceContent>";
		Document resp = post(body, "urn:vim25/RetrieveServiceContent", false);
		if (resp == null) {
			throw new Exception("RetrieveServiceContent failed (no response)");
		}
		Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
		if (rv == null) {
			throw new Exception("RetrieveServiceContent: no returnval");
		}
		this.propertyCollector = moRefOf(rv, "propertyCollector");
		this.viewManager = moRefOf(rv, "viewManager");
		this.rootFolder = moRefOf(rv, "rootFolder");
		this.sessionManager = moRefOf(rv, "sessionManager");
		this.settingOptionMgr = moRefOf(rv, "setting");
		Element about = firstDirectChild(rv, "about");
		if (about != null) {
			this.aboutInstanceUuid = childText(about, "instanceUuid");
			this.aboutFullName = childText(about, "fullName");
		}
		if (sessionManager == null || propertyCollector == null
				|| rootFolder == null) {
			throw new Exception("RetrieveServiceContent: incomplete content "
					+ "(sessionManager/propertyCollector/rootFolder missing)");
		}

		// Login — establishes the vmware_soap_session cookie.
		String loginBody =
				"<Login xmlns=\"urn:vim25\">"
				+ "<_this type=\"SessionManager\">"
				+ xmlEscape(sessionManager.value) + "</_this>"
				+ "<userName>" + xmlEscape(username) + "</userName>"
				+ "<password>" + xmlEscape(password) + "</password>"
				+ "</Login>";
		Document loginResp = post(loginBody, "urn:vim25/Login", false);
		if (loginResp == null) {
			throw new Exception("Login failed (no response / SOAP fault)");
		}
		if (sessionCookie == null) {
			throw new Exception("Login succeeded but no session cookie was "
					+ "returned");
		}

		// esxcli reader rides this session cookie; fresh per-cycle cache.
		this.esxcli = new EsxcliSoapClient(vcenterUrl, sessionCookie,
				sslFactory);
	}

	public void disconnect() {
		if (sessionManager != null && sessionCookie != null) {
			try {
				String body =
						"<Logout xmlns=\"urn:vim25\">"
						+ "<_this type=\"SessionManager\">"
						+ xmlEscape(sessionManager.value) + "</_this>"
						+ "</Logout>";
				post(body, "urn:vim25/Logout", true);
			} catch (Exception ignored) {}
		}
		sessionCookie = null;
		propertyCollector = null;
		viewManager = null;
		rootFolder = null;
		sessionManager = null;
		settingOptionMgr = null;
		aboutInstanceUuid = null;
		aboutFullName = null;
		esxcli = null;
	}

	public void ensureConnected() throws Exception {
		if (sessionCookie == null || propertyCollector == null) {
			connect();
			return;
		}
		// Keepalive: CurrentTime is a cheap call that fails if the session
		// lapsed. On any failure, reconnect.
		try {
			String body =
					"<CurrentTime xmlns=\"urn:vim25\">"
					+ "<_this type=\"ServiceInstance\">ServiceInstance</_this>"
					+ "</CurrentTime>";
			Document resp = post(body, "urn:vim25/CurrentTime", true);
			if (resp == null
					|| firstByLocalName(resp.getDocumentElement(),
							"returnval") == null) {
				disconnect();
				connect();
			}
		} catch (Exception e) {
			disconnect();
			connect();
		}
	}

	// -----------------------------------------------------------------------
	// Inventory walkers (HostSystem / VM / DVS / DVPG / Cluster)
	// -----------------------------------------------------------------------

	public List<HostInfo> getHosts() throws Exception {
		ensureConnected();
		List<HostInfo> result = new ArrayList<>();
		for (MoRef ref : listView("HostSystem")) {
			String name = getStringProperty(ref, "name");
			if (name != null) result.add(new HostInfo(ref, name, ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " hosts");
		if (result.isEmpty()) {
			logWarn("vSphere SOAP: ContainerView returned 0 HostSystem — a "
					+ "vCenter inventory should have at least one host; "
					+ "check the RetrieveProperties walk");
		}
		return result;
	}

	public List<VmInfo> getVms() throws Exception {
		ensureConnected();
		List<VmInfo> result = new ArrayList<>();
		for (MoRef ref : listView("VirtualMachine")) {
			String name = getStringProperty(ref, "name");
			if (name != null) result.add(new VmInfo(ref, name, ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " VMs");
		return result;
	}

	/**
	 * Enumerate distributed virtual switches. Some environments expose only
	 * the base {@code DistributedVirtualSwitch} type; we ask for the Vmware
	 * subtype first and fall back to the base, mirroring the v1 behaviour.
	 */
	public List<DvsInfo> getDvSwitches() throws Exception {
		ensureConnected();
		List<DvsInfo> result = new ArrayList<>();
		List<MoRef> refs = listView("VmwareDistributedVirtualSwitch");
		if (refs.isEmpty()) {
			refs = listView("DistributedVirtualSwitch");
		}
		for (MoRef ref : refs) {
			String name = getStringProperty(ref, "name");
			if (name != null) result.add(new DvsInfo(ref, name, ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " DVS");
		return result;
	}

	public List<DvpgInfo> getDvPortgroups() throws Exception {
		ensureConnected();
		List<DvpgInfo> result = new ArrayList<>();
		for (MoRef ref : listView("DistributedVirtualPortgroup")) {
			String name = getStringProperty(ref, "name");
			if (name != null) result.add(new DvpgInfo(ref, name, ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " DVPG");
		return result;
	}

	public List<ClusterInfo> getClusters() throws Exception {
		ensureConnected();
		List<ClusterInfo> result = new ArrayList<>();
		for (MoRef ref : listView("ClusterComputeResource")) {
			String name = getStringProperty(ref, "name");
			if (name != null) result.add(new ClusterInfo(ref, name, ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " Clusters");
		return result;
	}

	// -----------------------------------------------------------------------
	// Advanced settings (OptionManager.QueryOptions)
	// -----------------------------------------------------------------------

	/**
	 * Thrown by {@link #getAdvancedSettings(MoRef)} when the host's
	 * {@code configManager.advancedOption} OptionManager MoRef cannot be
	 * resolved (build 47). This is the disconnected/flapping-host signature:
	 * {@code PropertyCollector} returns the host's {@code configManager}
	 * without a live {@code advancedOption} MoRef, so the advanced-setting
	 * channel is <b>unreadable</b>, not empty. Distinguishing the two is the
	 * whole point — an empty map (host read OK, no keys) and an unreadable
	 * channel (could not read at all) must NOT collapse to the same outcome,
	 * or every advanced_setting control silently vanishes from the
	 * denominator (the build-46 esx04 partial-collection regression). The
	 * caller folds every advanced_setting control to UNREADABLE instead of
	 * scoring a flattering partial subset.
	 */
	public static final class AdvancedSettingsUnreadableException
			extends Exception {
		private static final long serialVersionUID = 1L;
		public AdvancedSettingsUnreadableException(String message) {
			super(message);
		}
	}

	/**
	 * Host advanced settings via {@code configManager.advancedOption} ->
	 * {@code QueryOptions(null)}. Returns the full key/value map; values are
	 * stringified exactly as {@code String.valueOf(OptionValue.value)} did
	 * (the SOAP {@code <value>} text content).
	 *
	 * <p>Build 47: a null {@code advancedOption} MoRef is a <b>read
	 * failure</b> (disconnected host), NOT an empty result. It throws
	 * {@link AdvancedSettingsUnreadableException} so the caller can fold the
	 * advanced_setting channel to UNREADABLE rather than evaluate every
	 * control against a silently-empty map (which drops them from the score
	 * denominator entirely). A host that genuinely has zero advanced options
	 * but a live OptionManager still returns an empty map normally — only the
	 * unresolvable-MoRef case signals unreadable.
	 */
	public Map<String, String> getAdvancedSettings(MoRef hostRef)
			throws Exception {
		ensureConnected();
		MoRef optMgr = getMoRefProperty(hostRef,
				"configManager.advancedOption");
		if (optMgr == null) {
			throw new AdvancedSettingsUnreadableException(
					"configManager.advancedOption MoRef is null — host's "
					+ "advanced-settings channel is unreadable (host likely "
					+ "disconnected / not responding)");
		}
		return queryOptions(optMgr);
	}

	/**
	 * Read a host's {@code runtime.connectionState} (build 47). Returns the
	 * raw vim25 {@code HostSystemConnectionState} enum string
	 * ({@code "connected"} / {@code "disconnected"} / {@code "notResponding"})
	 * or {@code null} when the property could not be read. Reflection-tolerant
	 * DOM read — a missing element returns null (caller treats null as
	 * "unknown", proceeds with normal evaluation), never throws.
	 */
	public String getHostConnectionState(MoRef hostRef) throws Exception {
		ensureConnected();
		return getStringProperty(hostRef, "runtime.connectionState");
	}

	/**
	 * VM advanced settings via {@code config.extraConfig} — the VMX
	 * OptionValue list. Returned as a key/value map with the same
	 * stringification the v1 reader produced.
	 */
	public Map<String, String> getVmExtraConfig(MoRef vmRef) throws Exception {
		ensureConnected();
		Map<String, String> result = new HashMap<>();
		Element val = getRawPropertyElement(vmRef, "config.extraConfig");
		if (val == null) return result;
		// extraConfig is an array of OptionValue; each child element carries
		// <key> and <value>.
		for (Element item : childElements(val)) {
			String key = childText(item, "key");
			String value = childText(item, "value");
			if (key != null && value != null) {
				result.put(key, value);
			}
		}
		return result;
	}

	/**
	 * vCenter-level advanced settings via {@code ServiceContent.setting} ->
	 * {@code QueryOptions(null)}.
	 */
	public Map<String, String> getVCenterAdvancedSettings() throws Exception {
		ensureConnected();
		if (settingOptionMgr == null) return new HashMap<>();
		return queryOptions(settingOptionMgr);
	}

	private Map<String, String> queryOptions(MoRef optionMgr) throws Exception {
		Map<String, String> result = new HashMap<>();
		String body =
				"<QueryOptions xmlns=\"urn:vim25\">"
				+ "<_this type=\"" + xmlEscape(optionMgr.type) + "\">"
				+ xmlEscape(optionMgr.value) + "</_this>"
				+ "</QueryOptions>";
		Document resp = post(body, "urn:vim25/QueryOptions", true);
		if (resp == null) return result;
		// Each <returnval> is an OptionValue with <key> and <value>. Deep
		// search — the returnvals are nested under Envelope > Body >
		// QueryOptionsResponse, not direct children of the document element
		// (build 44 fix, same defect class as the inventory walk).
		for (Element rv : descendantsByLocalName(resp.getDocumentElement(),
				"returnval")) {
			String key = childText(rv, "key");
			String value = childText(rv, "value");
			if (key != null && value != null) {
				result.put(key, value);
			}
		}
		return result;
	}

	// -----------------------------------------------------------------------
	// vCenter "about" info
	// -----------------------------------------------------------------------

	public String getVCenterInstanceUuid() throws Exception {
		ensureConnected();
		return aboutInstanceUuid;
	}

	public String getVCenterDisplayName() throws Exception {
		ensureConnected();
		return aboutFullName;
	}

	// -----------------------------------------------------------------------
	// vSAN presence probe (ClusterComputeResource.configurationEx)
	// -----------------------------------------------------------------------

	/**
	 * Whether a cluster has a vSAN config object at all. Distinguishes a
	 * NON-vSAN cluster (vSAN controls genuinely N/A → skip silently) from a
	 * vSAN cluster where a field read back null (a real coverage gap →
	 * unreadable). Returns false when {@code configurationEx} or its
	 * {@code vsanConfigInfo} child is absent. DOM walk; never casts.
	 */
	public boolean hasVsanConfig(MoRef clusterRef) throws Exception {
		ensureConnected();
		if (clusterRef == null) return false;
		Element configEx = getRawPropertyElement(clusterRef, "configurationEx");
		if (configEx == null) return false;
		Element vsanCfg = firstDirectChild(configEx, "vsanConfigInfo");
		return vsanCfg != null;
	}

	// -----------------------------------------------------------------------
	// Generic recipe-driven vim_property reader (canonical column 13)
	// -----------------------------------------------------------------------

	/**
	 * Sentinel placed in the result map when a control declared a recipe but
	 * the read could not produce a value. Distinct from "key absent"
	 * (non-evaluable, no recipe) and from a real {@code Boolean.FALSE}. The
	 * evaluator treats this as the explicit {@code unreadable} outcome —
	 * never a pass.
	 */
	public static final Object UNREADABLE = new Object() {
		@Override public String toString() { return "(unreadable)"; }
	};

	/**
	 * Generic, recipe-driven reader. Same contract as the JAX-WS version:
	 * <ul>
	 *   <li>recipe resolves to a typed value -> that value (Boolean / String /
	 *       Number) under the control's {@code parameter} key.</li>
	 *   <li>recipe present + evaluable but read found null / unknown style ->
	 *       {@link #UNREADABLE} (counted as unreadable, NEVER a pass).</li>
	 *   <li>recipe empty / not a recipe kind -> key absent (skipped).</li>
	 * </ul>
	 */
	public Map<String, Object> readVimProperties(
			MoRef moRef,
			List<BenchmarkProfile.Control> controls) throws Exception {
		ensureConnected();
		Map<String, Object> result = new HashMap<>();
		if (moRef == null || controls == null) return result;

		for (BenchmarkProfile.Control c : controls) {
			if (!"vim_property".equals(c.parameterKind)
					&& !"esxcli".equals(c.parameterKind)) {
				continue;
			}
			String recipe = c.readRecipe;
			if (recipe == null || recipe.trim().isEmpty()) {
				continue;
			}
			Object value;
			try {
				value = readByRecipe(moRef, recipe.trim());
			} catch (Exception e) {
				value = null;
			}
			result.put(c.parameter, value != null ? value : UNREADABLE);
		}
		return result;
	}

	/**
	 * Read one recipe ({@code <style>:<vim_path>}) against a resource MoRef.
	 * Returns the typed value or null (-> UNREADABLE). The grammar and the
	 * per-style outcomes are identical to the JAX-WS implementation; the only
	 * change is the walk substrate (DOM elements instead of binding objects).
	 */
	Object readByRecipe(MoRef moRef, String recipe) throws Exception {
		int colon = recipe.indexOf(':');
		if (colon <= 0 || colon >= recipe.length() - 1) {
			return null;
		}
		String style = recipe.substring(0, colon).trim();
		String path = recipe.substring(colon + 1).trim();
		if (path.isEmpty()) return null;

		// esxcli and service_state carry a three-part grammar; handle before
		// the generic dotted-path split.
		if ("esxcli".equals(style)) {
			return readEsxcliRecipe(moRef, path);
		}
		if ("service_state".equals(style)) {
			return readServiceStateRecipe(moRef, path);
		}

		String[] segments = path.split("\\.");
		switch (style) {
			case "scalar":
				return readScalarRecipe(moRef, segments);
			case "bool":
				return readBoolRecipe(moRef, segments);
			case "bool_policy":
				return readBoolPolicyRecipe(moRef, segments);
			case "string_list_join":
				return readStringListJoinRecipe(moRef, segments);
			case "vm_hardware_device_absent":
				return readDeviceAbsentRecipe(moRef, segments);
			case "list_empty":
				return readListEmptyRecipe(moRef, segments);
			case "vlan_id_not":
				return readVlanIdNotRecipe(moRef, segments);
			default:
				return null;   // unknown style -> UNREADABLE, never a guess
		}
	}

	// ----- esxcli style (delegates to the proven raw-SOAP esxcli client) ---

	private Object readEsxcliRecipe(MoRef moRef, String path) throws Exception {
		if (esxcli == null) {
			return null;
		}
		int sep = path.lastIndexOf(':');
		if (sep <= 0 || sep >= path.length() - 1) {
			return null;
		}
		String namespaceCommand = path.substring(0, sep).trim();
		String fieldSpec = path.substring(sep + 1).trim();
		if (namespaceCommand.isEmpty() || fieldSpec.isEmpty()) return null;

		String hostMoid = moRef != null ? moRef.value : null;
		if (hostMoid == null || hostMoid.isEmpty()) return null;

		String value;
		int lb = fieldSpec.indexOf('[');
		if (lb > 0 && fieldSpec.endsWith("]")) {
			String field = fieldSpec.substring(0, lb).trim();
			String selector = fieldSpec.substring(lb + 1,
					fieldSpec.length() - 1).trim();
			int eq = selector.indexOf('=');
			if (eq <= 0 || eq >= selector.length() - 1) {
				return null;
			}
			String selectorField = selector.substring(0, eq).trim();
			String selectorValue = selector.substring(eq + 1).trim();
			if (field.isEmpty() || selectorField.isEmpty()
					|| selectorValue.isEmpty()) {
				return null;
			}
			value = esxcli.readRowField(hostMoid, namespaceCommand,
					selectorField, selectorValue, field);
		} else {
			value = esxcli.readField(hostMoid, namespaceCommand, fieldSpec);
		}
		if (value == null
				|| EsxcliSoapClient.COMMAND_FAILED.equals(value)) {
			return null;
		}
		String trimmed = value.trim();
		if ("true".equalsIgnoreCase(trimmed)) return Boolean.TRUE;
		if ("false".equalsIgnoreCase(trimmed)) return Boolean.FALSE;
		return trimmed;
	}

	// ----- service_state style ---------------------------------------------

	/**
	 * service_state:&lt;service_key&gt;:&lt;field&gt;. Walks the host service
	 * list at {@code config.service.service}, finds the entry whose {@code
	 * key} matches, and returns {@code running} (Boolean) or {@code policy}
	 * (String). A missing service is UNREADABLE (cannot prove its state),
	 * NEVER a "stopped/compliant" pass — identical to v1.
	 */
	private Object readServiceStateRecipe(MoRef moRef, String path)
			throws Exception {
		int sep = path.lastIndexOf(':');
		if (sep <= 0 || sep >= path.length() - 1) {
			return null;
		}
		String serviceKey = path.substring(0, sep).trim();
		String field = path.substring(sep + 1).trim();
		if (serviceKey.isEmpty() || field.isEmpty()) return null;
		if (!"running".equals(field) && !"policy".equals(field)) {
			return null;
		}
		if (moRef == null) return null;

		// config.service resolves to a HostServiceInfo; its <service> children
		// are the HostService entries.
		Element serviceInfo = getRawPropertyElement(moRef, "config.service");
		if (serviceInfo == null) return null;

		for (Element svc : childrenByLocalName(serviceInfo, "service")) {
			String key = childText(svc, "key");
			if (key == null || !serviceKey.equals(key)) continue;

			if ("running".equals(field)) {
				return parseBool(childText(svc, "running"));
			}
			String policy = childText(svc, "policy");
			if (policy == null) return null;
			policy = policy.trim();
			return policy.isEmpty() ? null : policy;
		}
		// No matching service entry — UNREADABLE, not "stopped/compliant".
		return null;
	}

	// ----- scalar / bool / bool_policy / string_list_join ------------------

	private Object readScalarRecipe(MoRef moRef, String[] segments)
			throws Exception {
		Element node = walkToNode(moRef, segments);
		if (node == null) return null;
		String text = elementText(node);
		return (text == null || text.isEmpty()) ? null : text;
	}

	/**
	 * bool style — walk to the final-segment element, read it as a boolean.
	 * Reproduces the vSAN reader (configurationEx -> vsanConfigInfo ->
	 * enabled / objectChecksumEnabled / ...). DOM: the leaf element's text is
	 * {@code true}/{@code false}.
	 */
	private Boolean readBoolRecipe(MoRef moRef, String[] segments)
			throws Exception {
		Element node = walkToNode(moRef, segments);
		if (node == null) return null;
		return parseBool(elementText(node));
	}

	/**
	 * bool_policy style — walk to the PARENT of the final segment (a
	 * DVSSecurityPolicy), then read the final segment (a BoolPolicy wrapper)
	 * -> its {@code value} child. Reproduces readSecurityPolicy:
	 * config.defaultPortConfig -> securityPolicy -> &lt;field&gt; (BoolPolicy)
	 * -> value.
	 */
	private Boolean readBoolPolicyRecipe(MoRef moRef, String[] segments)
			throws Exception {
		Element parent = walkToParent(moRef, segments);
		if (parent == null) return null;
		String field = segments[segments.length - 1];
		Element wrapper = firstDirectChild(parent, field);
		if (wrapper == null) return null;
		// BoolPolicy.value child. Absent value -> null (not present), never
		// false.
		String v = childText(wrapper, "value");
		return parseBool(v);
	}

	private String readStringListJoinRecipe(MoRef moRef, String[] segments)
			throws Exception {
		// The final segment names a repeated element; walk to its PARENT and
		// collect every direct child of that name. An empty list -> null
		// (coverage gap, never a "(non-empty)" pass) — identical to v1.
		Element parent = walkToParent(moRef, segments);
		if (parent == null) return null;
		String field = segments[segments.length - 1];
		List<Element> items = childrenByLocalName(parent, field);
		if (items.isEmpty()) return null;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < items.size(); i++) {
			if (i > 0) sb.append(',');
			String t = elementText(items.get(i));
			sb.append(t != null ? t : "");
		}
		return sb.toString();
	}

	// ----- list styles (cardinal-trap: confirmed read vs failed fetch) -----

	/**
	 * Result of a list read. {@code confirmed} is true only when the owning
	 * container node was positively read (so an empty list is a genuine
	 * reading); {@code !confirmed} is the failed-fetch case the cardinal rule
	 * forbids treating as compliant.
	 */
	private static final class ListRead {
		final boolean confirmed;
		final List<Element> items;
		private ListRead(boolean confirmed, List<Element> items) {
			this.confirmed = confirmed;
			this.items = items;
		}
		static ListRead failed() { return new ListRead(false, null); }
		static ListRead of(List<Element> l) { return new ListRead(true, l); }
	}

	/**
	 * Positively obtain the repeated-element list named by the final segment.
	 * Reaching a non-null container node is the proof that lets an empty list
	 * count as a real reading. If the container node could not be read ->
	 * {@code failed()} (caller -> UNREADABLE).
	 */
	private ListRead readListConfirmed(MoRef moRef, String[] segments)
			throws Exception {
		if (segments == null || segments.length == 0) return ListRead.failed();
		Element container = walkToParent(moRef, segments);
		if (container == null) {
			return ListRead.failed();
		}
		String field = segments[segments.length - 1];
		// A confirmed container with zero matching children is a real empty
		// list (e.g. no devices / no vspan sessions) — distinct from a failed
		// fetch (container null above).
		return ListRead.of(childrenByLocalName(container, field));
	}

	/**
	 * vm_hardware_device_absent — compliant iff the device list was read AND
	 * contains no element of the requested device type. DOM type matching is
	 * by the element's {@code xsi:type} (the wire type name), the analogue of
	 * v1's {@code getClass().getSimpleName()} — never an instanceof against a
	 * concrete subclass.
	 */
	private Boolean readDeviceAbsentRecipe(MoRef moRef, String[] segments)
			throws Exception {
		if (segments.length < 2) return null;
		String typeName = segments[segments.length - 1];
		String[] listPath = new String[segments.length - 1];
		System.arraycopy(segments, 0, listPath, 0, segments.length - 1);

		ListRead read = readListConfirmed(moRef, listPath);
		if (!read.confirmed) {
			return null;   // failed fetch -> UNREADABLE, never "absent"
		}
		for (Element dev : read.items) {
			if (typeName.equals(xsiType(dev))) {
				return Boolean.FALSE;   // prohibited device present
			}
		}
		return Boolean.TRUE;   // confirmed and type absent -> compliant
	}

	/**
	 * list_empty — compliant iff the list was read AND has zero elements;
	 * non-compliant iff ≥1; UNREADABLE iff the list could not be obtained.
	 */
	private Boolean readListEmptyRecipe(MoRef moRef, String[] segments)
			throws Exception {
		ListRead read = readListConfirmed(moRef, segments);
		if (!read.confirmed) {
			return null;
		}
		return read.items.isEmpty() ? Boolean.TRUE : Boolean.FALSE;
	}

	/**
	 * vlan_id_not — VGT (virtual guest tagging) detection. A trunk spec
	 * ({@code ...TrunkVlanSpec}) is VGT -> non-compliant. A plain id spec
	 * ({@code ...VlanIdSpec}) with {@code vlanId == 4095} is VGT ->
	 * non-compliant; any other id is compliant. An unreadable / unrecognized
	 * spec type is UNREADABLE, never a guess. Type discrimination is by the
	 * element {@code xsi:type} substring (Trunk / VlanId).
	 */
	private Boolean readVlanIdNotRecipe(MoRef moRef, String[] segments)
			throws Exception {
		Element specNode = walkToNode(moRef, segments);
		if (specNode == null) {
			return null;
		}
		String typeName = xsiType(specNode);
		if (typeName == null) return null;
		if (typeName.contains("Trunk")) {
			return Boolean.FALSE;
		}
		if (typeName.contains("VlanId")) {
			String idText = childText(specNode, "vlanId");
			if (idText == null) return null;
			try {
				int vlanId = Integer.parseInt(idText.trim());
				return vlanId == 4095 ? Boolean.FALSE : Boolean.TRUE;
			} catch (NumberFormatException e) {
				return null;
			}
		}
		return null;   // unrecognized spec type -> UNREADABLE
	}

	// -----------------------------------------------------------------------
	// DOM path walking
	// -----------------------------------------------------------------------

	/**
	 * Walk to the element identified by the FULL segment path, returning the
	 * leaf element (or null on any missing element). PropertyCollector
	 * resolves the longest dotted prefix it can; the remaining tail is walked
	 * by DOM child local-name.
	 */
	private Element walkToNode(MoRef moRef, String[] segments)
			throws Exception {
		int[] consumed = new int[1];
		Element node = getLongestPrefixElement(moRef, segments,
				segments.length, consumed);
		for (int i = consumed[0]; i < segments.length; i++) {
			if (node == null) return null;
			node = firstDirectChild(node, segments[i]);
		}
		return node;
	}

	/**
	 * Walk to the parent of the final path segment. PropertyCollector is
	 * capped at {@code segments.length - 1} so it never resolves the leaf
	 * directly — the bool / bool_policy / list styles need the leaf element
	 * (and its xsi:type / wrapper) intact, read off the parent.
	 */
	private Element walkToParent(MoRef moRef, String[] segments)
			throws Exception {
		int[] consumed = new int[1];
		Element node = getLongestPrefixElement(moRef, segments,
				segments.length - 1, consumed);
		for (int i = consumed[0]; i < segments.length - 1; i++) {
			if (node == null) return null;
			node = firstDirectChild(node, segments[i]);
		}
		return node;
	}

	/**
	 * Try PropertyCollector against progressively shorter dotted prefixes of
	 * {@code segments} (longest first, no longer than {@code maxLen}) and
	 * return the first {@code <val>} element that resolves, writing the
	 * number of segments consumed into {@code consumedOut[0]}. Returns null /
	 * consumed=0 when no prefix resolves.
	 */
	private Element getLongestPrefixElement(MoRef moRef, String[] segments,
			int maxLen, int[] consumedOut) throws Exception {
		int start = Math.min(maxLen, segments.length);
		for (int len = start; len >= 1; len--) {
			StringBuilder p = new StringBuilder();
			for (int i = 0; i < len; i++) {
				if (i > 0) p.append('.');
				p.append(segments[i]);
			}
			Element v;
			try {
				v = getRawPropertyElement(moRef, p.toString());
			} catch (Exception e) {
				v = null;
			}
			if (v != null) {
				consumedOut[0] = len;
				return v;
			}
		}
		consumedOut[0] = 0;
		return null;
	}

	// -----------------------------------------------------------------------
	// PropertyCollector primitives (RetrieveProperties)
	// -----------------------------------------------------------------------

	/**
	 * Retrieve a single property's {@code <val>} element for an object.
	 * Returns the DOM element of the property value (carrying its xsi:type
	 * and children), or null when the property is absent / unreadable.
	 */
	private Element getRawPropertyElement(MoRef moRef, String propPath)
			throws Exception {
		Document resp = retrieveProperties(moRef.type, moRef.value, propPath);
		if (resp == null) return null;
		Element returnval = firstByLocalName(resp.getDocumentElement(),
				"returnval");
		if (returnval == null) return null;
		// <returnval> (ObjectContent): <obj/> then one or more <propSet>.
		for (Element propSet : childrenByLocalName(returnval, "propSet")) {
			String name = childText(propSet, "name");
			if (propPath.equals(name)) {
				return firstDirectChild(propSet, "val");
			}
		}
		return null;
	}

	/**
	 * String form of a single property (used for inventory {@code name}).
	 */
	private String getStringProperty(MoRef moRef, String propPath)
			throws Exception {
		Element val = getRawPropertyElement(moRef, propPath);
		if (val == null) return null;
		String t = elementText(val);
		return (t == null || t.isEmpty()) ? null : t;
	}

	/**
	 * Resolve a property whose value is itself a ManagedObjectReference
	 * (e.g. {@code configManager.advancedOption}). The {@code <val>}
	 * element's {@code type} attribute carries the MoRef type; its text is
	 * the value.
	 */
	private MoRef getMoRefProperty(MoRef moRef, String propPath)
			throws Exception {
		Element val = getRawPropertyElement(moRef, propPath);
		if (val == null) return null;
		String type = val.getAttribute("type");
		String value = elementText(val);
		if (value == null || value.isEmpty()) return null;
		return new MoRef(type != null && !type.isEmpty() ? type
				: "ManagedObject", value);
	}

	/**
	 * RetrieveProperties for one object and one property path (no traversal).
	 */
	private Document retrieveProperties(String type, String value,
			String propPath) throws Exception {
		String body =
				"<RetrieveProperties xmlns=\"urn:vim25\">"
				+ "<_this type=\"PropertyCollector\">"
				+ xmlEscape(propertyCollector.value) + "</_this>"
				+ "<specSet>"
				+ "<propSet>"
				+ "<type>" + xmlEscape(type) + "</type>"
				+ "<pathSet>" + xmlEscape(propPath) + "</pathSet>"
				+ "</propSet>"
				+ "<objectSet>"
				+ "<obj type=\"" + xmlEscape(type) + "\">"
				+ xmlEscape(value) + "</obj>"
				+ "<skip>false</skip>"
				+ "</objectSet>"
				+ "</specSet>"
				+ "</RetrieveProperties>";
		return post(body, "urn:vim25/RetrieveProperties", true);
	}

	// -----------------------------------------------------------------------
	// ContainerView inventory listing
	// -----------------------------------------------------------------------

	/**
	 * Create a ContainerView over the root folder for {@code type},
	 * RetrieveProperties the view members' {@code name}, then destroy the
	 * view. Returns the member MoRefs. The view is always destroyed even on
	 * a mid-walk failure.
	 */
	private List<MoRef> listView(String type) throws Exception {
		MoRef view = createContainerView(type);
		if (view == null) return new ArrayList<>();
		try {
			return retrieveViewMembers(view, type);
		} finally {
			destroyViewQuietly(view);
		}
	}

	private MoRef createContainerView(String type) throws Exception {
		String body =
				"<CreateContainerView xmlns=\"urn:vim25\">"
				+ "<_this type=\"ViewManager\">"
				+ xmlEscape(viewManager.value) + "</_this>"
				+ "<container type=\"Folder\">"
				+ xmlEscape(rootFolder.value) + "</container>"
				+ "<type>" + xmlEscape(type) + "</type>"
				+ "<recursive>true</recursive>"
				+ "</CreateContainerView>";
		Document resp = post(body, "urn:vim25/CreateContainerView", true);
		if (resp == null) return null;
		Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
		if (rv == null) return null;
		String val = elementText(rv);
		if (val == null || val.trim().isEmpty()) return null;
		String t = rv.getAttribute("type");
		return new MoRef(t != null && !t.isEmpty() ? t : "ContainerView",
				val.trim());
	}

	/**
	 * RetrieveProperties over a ContainerView with a traversal spec walking
	 * its {@code view} property; returns the member MoRefs (read from each
	 * ObjectContent's {@code <obj>}).
	 */
	private List<MoRef> retrieveViewMembers(MoRef view, String type)
			throws Exception {
		List<MoRef> refs = new ArrayList<>();
		String body =
				"<RetrieveProperties xmlns=\"urn:vim25\">"
				+ "<_this type=\"PropertyCollector\">"
				+ xmlEscape(propertyCollector.value) + "</_this>"
				+ "<specSet>"
				+ "<propSet>"
				+ "<type>" + xmlEscape(type) + "</type>"
				+ "<pathSet>name</pathSet>"
				+ "</propSet>"
				+ "<objectSet>"
				+ "<obj type=\"ContainerView\">"
				+ xmlEscape(view.value) + "</obj>"
				+ "<skip>true</skip>"
				+ "<selectSet xsi:type=\"TraversalSpec\">"
				+ "<name>view</name>"
				+ "<type>ContainerView</type>"
				+ "<path>view</path>"
				+ "<skip>false</skip>"
				+ "</selectSet>"
				+ "</objectSet>"
				+ "</specSet>"
				+ "</RetrieveProperties>";
		Document resp = post(body, "urn:vim25/RetrieveProperties", true);
		if (resp == null) {
			logWarn("listView(" + type + "): RetrieveProperties returned no "
					+ "response (HTTP error / SOAP fault) — 0 entities");
			return refs;
		}
		// Deep search: <returnval> (ObjectContent) entries are nested under
		// Envelope > Body > RetrievePropertiesResponse — NOT direct children of
		// the document element. (build 44 fix: build 43 used a direct-children
		// search here and silently found zero.)
		List<Element> returnvals = descendantsByLocalName(
				resp.getDocumentElement(), "returnval");
		logInfo("listView(" + type + "): RetrieveProperties -> "
				+ returnvals.size() + " objectContent");
		for (Element rv : returnvals) {
			Element obj = firstDirectChild(rv, "obj");
			if (obj == null) continue;
			String value = elementText(obj);
			if (value == null || value.trim().isEmpty()) continue;
			String t = obj.getAttribute("type");
			MoRef ref = new MoRef(t != null && !t.isEmpty() ? t : type,
					value.trim());
			if (refs.isEmpty() && log != null && log.isDebugEnabled()) {
				logDebug("listView(" + type + "): first object type="
						+ ref.type + " value=" + ref.value);
			}
			refs.add(ref);
		}
		return refs;
	}

	private void destroyViewQuietly(MoRef view) {
		if (view == null) return;
		try {
			String body =
					"<DestroyView xmlns=\"urn:vim25\">"
					+ "<_this type=\"" + xmlEscape(view.type) + "\">"
					+ xmlEscape(view.value) + "</_this>"
					+ "</DestroyView>";
			post(body, "urn:vim25/DestroyView", true);
		} catch (Exception ignored) {}
	}

	// -----------------------------------------------------------------------
	// SOAP HTTP transport + DOM helpers
	// -----------------------------------------------------------------------

	/**
	 * POST a SOAP body to the vCenter {@code /sdk}. Sends the live session
	 * cookie when {@code authenticated}; captures any {@code Set-Cookie}
	 * vmware_soap_session from the response (login path). Returns the parsed
	 * response Document, or null on a non-2xx / SOAP fault (callers map any
	 * failure to null/unreadable, never a default).
	 */
	private Document post(String soapBody, String soapAction,
			boolean authenticated) throws Exception {
		String envelope =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<soapenv:Envelope "
				+ "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
				+ "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
				+ "<soapenv:Body>" + soapBody + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

		URL url = new URL(vcenterUrl);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		if (conn instanceof HttpsURLConnection && sslFactory != null) {
			((HttpsURLConnection) conn).setSSLSocketFactory(sslFactory);
			((HttpsURLConnection) conn).setHostnameVerifier((h, s) -> true);
		}
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setConnectTimeout(30000);
		conn.setReadTimeout(120000);
		conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
		conn.setRequestProperty("SOAPAction", soapAction);
		if (authenticated && sessionCookie != null
				&& !sessionCookie.isEmpty()) {
			conn.setRequestProperty("Cookie", sessionCookie);
		}

		byte[] payload = envelope.getBytes(StandardCharsets.UTF_8);
		try (OutputStream os = conn.getOutputStream()) {
			os.write(payload);
		}

		int code = conn.getResponseCode();
		// Capture the session cookie from any response (the login response
		// carries it). Take name=value up to the first ';'.
		captureCookie(conn);

		InputStream is = (code >= 200 && code < 300)
				? conn.getInputStream() : conn.getErrorStream();
		byte[] respBytes = drain(is);
		conn.disconnect();
		if (code < 200 || code >= 300) {
			return null;   // SOAP fault (500) / auth failure -> null upstream
		}
		if (respBytes == null || respBytes.length == 0) return null;
		return parseXml(new String(respBytes, StandardCharsets.UTF_8));
	}

	private void captureCookie(HttpURLConnection conn) {
		try {
			List<String> setCookies = conn.getHeaderFields()
					.get("Set-Cookie");
			if (setCookies == null) {
				// Header keys can be case-insensitive; scan manually.
				for (Map.Entry<String, List<String>> e
						: conn.getHeaderFields().entrySet()) {
					if (e.getKey() != null
							&& "set-cookie".equalsIgnoreCase(e.getKey())) {
						setCookies = e.getValue();
						break;
					}
				}
			}
			if (setCookies == null) return;
			for (String c : setCookies) {
				if (c == null) continue;
				String pair = c;
				int semi = pair.indexOf(';');
				if (semi >= 0) pair = pair.substring(0, semi);
				pair = pair.trim();
				if (pair.startsWith("vmware_soap_session")) {
					this.sessionCookie = pair;
					return;
				}
			}
		} catch (Exception ignored) {
			// Cookie capture failure surfaces as a failed authenticated call
			// downstream (null -> unreadable), never a false pass.
		}
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
			try { is.close(); } catch (Exception ignored) {}
		}
	}

	private static Document parseXml(String xml) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			// Non-namespace-aware: read by LOCAL name throughout; harden
			// against external entities (the collision was JAX-WS service
			// discovery, NOT JAXP — DOM is safe here).
			dbf.setNamespaceAware(false);
			trySetFeature(dbf,
					"http://apache.org/xml/features/disallow-doctype-decl", true);
			trySetFeature(dbf,
					"http://xml.org/sax/features/external-general-entities", false);
			trySetFeature(dbf,
					"http://xml.org/sax/features/external-parameter-entities", false);
			DocumentBuilder db = dbf.newDocumentBuilder();
			return db.parse(new java.io.ByteArrayInputStream(
					xml.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception e) {
			return null;
		}
	}

	private static void trySetFeature(DocumentBuilderFactory dbf, String f,
			boolean v) {
		try { dbf.setFeature(f, v); } catch (Exception ignored) {}
	}

	/** First descendant element (direct child preferred) by local name. */
	private static Element firstByLocalName(Element parent, String name) {
		if (parent == null) return null;
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

	/** First direct-child element by local name. */
	private static Element firstDirectChild(Element parent, String name) {
		if (parent == null) return null;
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

	/** All direct-child elements by local name. */
	private static List<Element> childrenByLocalName(Element parent,
			String name) {
		List<Element> out = new ArrayList<>();
		if (parent == null) return out;
		NodeList kids = parent.getChildNodes();
		for (int i = 0; i < kids.getLength(); i++) {
			Node n = kids.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE
					&& name.equals(localName((Element) n))) {
				out.add((Element) n);
			}
		}
		return out;
	}

	/**
	 * All descendant elements by local name (whole subtree). Unlike
	 * {@link #childrenByLocalName} (direct children only), this tolerates the
	 * SOAP {@code Envelope > Body > <op>Response} wrapping without binding to
	 * the exact nesting depth — the multi-element analogue of
	 * {@link #firstByLocalName}.
	 *
	 * <p><b>Why this exists (build 44 regression fix).</b> The build-43
	 * inventory walk and {@code QueryOptions} reader iterated
	 * {@code childrenByLocalName(resp.getDocumentElement(), "returnval")}.
	 * {@code getDocumentElement()} is the {@code <soapenv:Envelope>}, but the
	 * {@code <returnval>} elements live two levels deeper (under {@code Body >
	 * RetrievePropertiesResponse}). A direct-children-only search found ZERO —
	 * so every ContainerView walk silently yielded an empty host/VM/DVS/DVPG/
	 * cluster set with no fault and no parse error ("connects clean, zero
	 * results"). Single-object reads were unaffected because they used the
	 * deep-search {@link #firstByLocalName}. This restores the same deep search
	 * for the multi-{@code returnval} responses.
	 */
	private static List<Element> descendantsByLocalName(Element parent,
			String name) {
		List<Element> out = new ArrayList<>();
		if (parent == null) return out;
		// Direct children first (the common shape once unwrapped), then any
		// remaining deeper matches — preserving document order without
		// double-counting a direct child.
		NodeList all = parent.getElementsByTagName("*");
		for (int i = 0; i < all.getLength(); i++) {
			Node n = all.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE
					&& name.equals(localName((Element) n))) {
				out.add((Element) n);
			}
		}
		return out;
	}

	/** All direct-child elements (any name). */
	private static List<Element> childElements(Element parent) {
		List<Element> out = new ArrayList<>();
		if (parent == null) return out;
		NodeList kids = parent.getChildNodes();
		for (int i = 0; i < kids.getLength(); i++) {
			Node n = kids.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE) {
				out.add((Element) n);
			}
		}
		return out;
	}

	/** Text of a named direct child element, or null when absent. */
	private static String childText(Element parent, String name) {
		Element c = firstDirectChild(parent, name);
		if (c == null) return null;
		return elementText(c);
	}

	/**
	 * Trimmed text content of an element. For a complex element this returns
	 * the concatenated descendant text, which callers never use (they read
	 * named children), so scalar reads stay exact.
	 */
	private static String elementText(Element e) {
		if (e == null) return null;
		String t = e.getTextContent();
		return t == null ? null : t.trim();
	}

	/**
	 * The {@code xsi:type} attribute (the wire type discriminator), or null.
	 * Non-namespace-aware parse keeps the prefixed attribute name verbatim.
	 */
	private static String xsiType(Element e) {
		if (e == null) return null;
		String t = e.getAttribute("xsi:type");
		if (t == null || t.isEmpty()) {
			t = e.getAttribute("type");   // some servers drop the xsi prefix
		}
		return (t == null || t.isEmpty()) ? null : t;
	}

	/** Local name (strip any prefix) of an element. */
	private static String localName(Element e) {
		String ln = e.getLocalName();
		if (ln != null) return ln;
		String tag = e.getTagName();
		int colon = tag.indexOf(':');
		return colon >= 0 ? tag.substring(colon + 1) : tag;
	}

	/**
	 * Parse a vim25 boolean text value. Returns {@code Boolean.TRUE}/{@code
	 * FALSE} for {@code true}/{@code false} (case-insensitive, also accepts
	 * {@code 1}/{@code 0}); null for anything else or null input (-> the
	 * caller folds null to UNREADABLE, never a guess).
	 */
	private static Boolean parseBool(String text) {
		if (text == null) return null;
		String t = text.trim();
		if (t.isEmpty()) return null;
		if ("true".equalsIgnoreCase(t) || "1".equals(t)) return Boolean.TRUE;
		if ("false".equalsIgnoreCase(t) || "0".equals(t)) return Boolean.FALSE;
		return null;
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

	private static javax.net.ssl.SSLSocketFactory trustAllSslFactory() {
		try {
			javax.net.ssl.SSLContext ctx =
					javax.net.ssl.SSLContext.getInstance("TLS");
			ctx.init(null, new javax.net.ssl.TrustManager[]{
					new javax.net.ssl.X509TrustManager() {
						public void checkClientTrusted(
								java.security.cert.X509Certificate[] c,
								String a) {}
						public void checkServerTrusted(
								java.security.cert.X509Certificate[] c,
								String a) {}
						public java.security.cert.X509Certificate[]
								getAcceptedIssuers() {
							return new java.security.cert.X509Certificate[0];
						}
					}
			}, null);
			return ctx.getSocketFactory();
		} catch (Exception e) {
			throw new RuntimeException("SSL setup failed", e);
		}
	}

	// -----------------------------------------------------------------------
	// Public value types — MoRef replaces vim25 ManagedObjectReference
	// -----------------------------------------------------------------------

	/**
	 * Lightweight managed-object reference: the {@code type} + {@code value}
	 * pair that vim25's {@code ManagedObjectReference} carried. No vim25
	 * binding dependency.
	 */
	public static final class MoRef {
		public final String type;
		public final String value;

		public MoRef(String type, String value) {
			this.type = type;
			this.value = value;
		}
	}

	/** Build a MoRef from a named MoRef-valued child of {@code parent}. */
	private static MoRef moRefOf(Element parent, String childName) {
		Element c = firstDirectChild(parent, childName);
		if (c == null) return null;
		String value = c.getTextContent();
		if (value == null || value.trim().isEmpty()) return null;
		String type = c.getAttribute("type");
		return new MoRef(type != null && !type.isEmpty() ? type
				: "ManagedObject", value.trim());
	}

	public static final class HostInfo {
		public final MoRef moRef;
		public final String name;
		public final String moid;

		public HostInfo(MoRef moRef, String name, String moid) {
			this.moRef = moRef;
			this.name = name;
			this.moid = moid;
		}
	}

	public static final class VmInfo {
		public final MoRef moRef;
		public final String name;
		public final String moid;

		public VmInfo(MoRef moRef, String name, String moid) {
			this.moRef = moRef;
			this.name = name;
			this.moid = moid;
		}
	}

	public static final class DvsInfo {
		public final MoRef moRef;
		public final String name;
		public final String moid;

		public DvsInfo(MoRef moRef, String name, String moid) {
			this.moRef = moRef;
			this.name = name;
			this.moid = moid;
		}
	}

	public static final class DvpgInfo {
		public final MoRef moRef;
		public final String name;
		public final String moid;

		public DvpgInfo(MoRef moRef, String name, String moid) {
			this.moRef = moRef;
			this.name = name;
			this.moid = moid;
		}
	}

	public static final class ClusterInfo {
		public final MoRef moRef;
		public final String name;
		public final String moid;

		public ClusterInfo(MoRef moRef, String name, String moid) {
			this.moRef = moRef;
			this.name = name;
			this.moid = moid;
		}
	}
}
