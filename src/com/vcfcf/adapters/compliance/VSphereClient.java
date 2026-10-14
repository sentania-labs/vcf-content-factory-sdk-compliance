package com.vcfcf.adapters.compliance;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
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
 *
 * <p><b>Build 95 (issue #17).</b> No SDK dependency (the logger is the
 * {@link Log} interface), so the client is tested against a local HTTP
 * server. One CurrentTime keepalive per cycle (the adapter's
 * {@link #ensureConnected}); every other call only logs in when there is
 * no session, and a call answered NotAuthenticated logs in again and is
 * retried once. Inventory names come from the listing call. Connections
 * are reused (no disconnect after a successful call). The longest-prefix
 * fallback is bounded ({@link #minPrefixSegments}, {@link
 * #MAX_PREFIX_ATTEMPTS}). {@link #retrieveBulk} is the paged bulk read used
 * by the shadow comparison.
 */
public final class VSphereClient {

	/**
	 * Build 95: the logging the client needs, so it carries no SDK type.
	 * The adapter adapts its platform logger; tests pass null or a stub.
	 */
	public interface Log {
		void info(String msg);
		void debug(String msg);
		void warn(String msg);
		boolean isDebugEnabled();
	}

	private final String vcenterUrl;       // https://<host>/sdk
	private final String username;
	private final String password;
	private final SSLSocketFactory sslFactory;
	private final Log log;                 // nullable: standalone use logs nothing

	// Build 95: this cycle's measurement (null: nothing is counted).
	private volatile CycleMetrics metrics;
	// Build 95: true while a NotAuthenticated call is logging in again, so
	// the login itself never triggers another one.
	private volatile boolean reloggingIn;
	// Build 95: the property named by the last InvalidProperty fault.
	private volatile String lastInvalidProperty;
	private volatile boolean lastNotAuthenticated;
	// Build 95 (issue #24): the last call's response was over the cap.
	private volatile boolean lastTooLarge;
	// Build 95 review W3: why the last connect() failed, kept until the
	// next cycle (beginCycle, ensureConnected). While set, no read logs in
	// again: with bad credentials every SOAP call would otherwise send one
	// more Login and could trip the SSO lockout policy.
	private volatile String loginFailure;
	// Build 95 review W3: the cookie a connect() in progress captured; it
	// becomes the session only once Login has succeeded.
	private volatile boolean connecting;
	private volatile String pendingCookie;
	// Build 95 review W4: set by disconnect(). A closed client never logs
	// in again, so a cycle still running on it after an instance edit (or
	// discard) fails its remaining reads cleanly (UNREADABLE) instead of
	// opening a session nobody logs out.
	private volatile boolean closed;

	/**
	 * Build 95 review W4: the Logout sent by {@link #disconnect} waits at
	 * most this long to connect and this long to read, so configure is not
	 * held for the 30 s + 120 s of a normal call by an unreachable old
	 * vCenter. A Logout that times out leaves an idle session for vCenter
	 * to expire.
	 */
	static final int LOGOUT_TIMEOUT_MS = 5000;

	private volatile int logoutTimeoutMs = LOGOUT_TIMEOUT_MS;
	private volatile int readTimeoutMs = READ_TIMEOUT_MS;

	/** Test seam (review N2): a shorter read timeout for normal calls. */
	void setReadTimeoutMs(int ms) {
		this.readTimeoutMs = ms;
	}

	/** Test seam (review W4): a shorter Logout wait. */
	void setLogoutTimeoutMs(int ms) {
		this.logoutTimeoutMs = ms;
	}

	/** Normal SOAP call timeouts. */
	private static final int CONNECT_TIMEOUT_MS = 30000;
	private static final int READ_TIMEOUT_MS = 120000;

	/**
	 * Build 95 (issue #24): the most bytes of one SOAP response read into
	 * memory. The largest legitimate responses are bulk pages (200 VMs with
	 * their extraConfig and device lists, or 10 hosts with their whole
	 * advanced-option lists), a few MB to a few tens of MB; 64 MB leaves
	 * headroom while keeping one response from exhausting the collector
	 * JVM every adapter shares. A response over it fails the call (its
	 * controls are UNREADABLE with reason response-too-large), never a
	 * partial read.
	 */
	static final long MAX_SOAP_RESPONSE_BYTES = 64L * 1024 * 1024;

	/** Build 95: fault bodies read at most this much (they are small). */
	static final int MAX_FAULT_BODY_BYTES = 1024 * 1024;

	private volatile long maxResponseBytes = MAX_SOAP_RESPONSE_BYTES;

	/** Test seam (build 95): a smaller response cap. */
	void setMaxResponseBytes(long max) {
		this.maxResponseBytes = max;
	}

	// SOAP session state.
	private volatile String sessionCookie;     // vmware_soap_session=...
	private volatile MoRef propertyCollector;
	private volatile MoRef viewManager;
	private volatile MoRef rootFolder;
	private volatile MoRef sessionManager;
	private volatile MoRef settingOptionMgr;   // ServiceContent.setting
	private volatile String aboutInstanceUuid;
	private volatile String aboutFullName;
	private volatile String aboutVersion;      // ServiceContent.about.version

	// Build 74 diagnostics. lastFault: the faultstring (with HTTP status) of
	// the most recent failed SOAP call. readFailure: why the current recipe
	// read returned nothing, set at the point of failure (category first,
	// see UnreadableReasons). lastReasons: parameter -> reason for the
	// unreadable controls of the most recent readVimProperties call.
	private volatile String lastFault;
	private volatile String readFailure;
	private final Map<String, String> lastReasons = new HashMap<>();
	private final java.util.Set<String> warnedEsxciFields =
			java.util.Collections.newSetFromMap(
					new java.util.concurrent.ConcurrentHashMap<>());

	// esxcli reader (build 36), rides THIS vCenter session. Rebuilt on
	// every (re)connect so it carries the live cookie; its command cache is
	// emptied every cycle by beginCycle() (build 85), because the session,
	// and so this object, can outlive any number of cycles.
	private volatile EsxcliSoapClient esxcli;
	// Build 95 review N3: the esxcli client a mid-cycle re-login dropped,
	// whose unreachable-host marks the next one takes over.
	private volatile EsxcliSoapClient retiredEsxcli;

	/**
	 * The {@link SSLSocketFactory} is chosen by the adapter
	 * ({@code ComplianceAdapter.sslSocketFactoryFor}): the platform trust
	 * path with the certificate name enforced
	 * ({@link VCenterCertificates#nameChecking}), always (build 93 removed
	 * the Allow Insecure SSL opt-out, its trust-all factory and its
	 * hostname-verification bypass). The same factory is threaded into the
	 * per-cycle {@link EsxcliSoapClient} so the esxcli slice validates
	 * identically, and every connection also sets
	 * {@link VCenterCertificates#strictHostnameVerifier} (through
	 * {@link VCenterCertificates#secure}).
	 *
	 * @param sslFactory the socket factory to use for the HTTPS SOAP
	 *                    connection. Must not be null on the production path.
	 * @param log        adapter logger for SOAP-walk breadcrumbs (response-shape
	 *                   per RetrieveProperties, inventory counts). May be null
	 *                   (standalone / test use), in which case the client logs
	 *                   nothing.
	 */
	public VSphereClient(String vcenterHost, String username, String password,
			SSLSocketFactory sslFactory, Log log) {
		this("https://" + vcenterHost + "/sdk", username, password,
				sslFactory, log, true);
	}

	/** Test seam (build 95): the full /sdk URL, e.g. a local http server. */
	VSphereClient(String sdkUrl, String username, String password,
			SSLSocketFactory sslFactory, Log log, boolean fullUrl) {
		this.vcenterUrl = sdkUrl;
		this.username = username;
		this.password = password;
		this.sslFactory = sslFactory;
		this.log = log;
	}

	/**
	 * Build 95: count this cycle's SOAP calls (esxcli included) into
	 * {@code m}; null stops counting.
	 */
	public void setMetrics(CycleMetrics m) {
		this.metrics = m;
		EsxcliSoapClient c = esxcli;
		if (c != null) c.setMetrics(m);
	}

	private void logInfo(String msg)  { if (log != null) log.info(msg); }
	private void logDebug(String msg) { if (log != null) log.debug(msg); }
	private void logWarn(String msg)  { if (log != null) log.warn(msg); }

	// -----------------------------------------------------------------------
	// Session lifecycle
	// -----------------------------------------------------------------------

	/**
	 * Log in: RetrieveServiceContent, then Login. Build 95 review W3: the
	 * session fields (the cookie, the PropertyCollector and the other
	 * ServiceContent references, the about values, the esxcli client) are
	 * set only after Login succeeds, so a failed Login never leaves a
	 * half-made session that {@link #ensureSession} would take for a live
	 * one. A failure is remembered ({@link #loginFailure}) until the next
	 * cycle, and no read logs in again before then.
	 */
	public void connect() throws Exception {
		if (closed) {
			throw new VimOptions.ReadFault(CLOSED);
		}
		connecting = true;
		pendingCookie = null;
		try {
			connectOnce();
			loginFailure = null;
		} catch (Exception e) {
			loginFailure = e.getClass().getSimpleName() + ": "
					+ e.getMessage();
			throw e;
		} finally {
			connecting = false;
			pendingCookie = null;
		}
	}

	private void connectOnce() throws Exception {
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
		MoRef pc = moRefOf(rv, "propertyCollector");
		MoRef vm = moRefOf(rv, "viewManager");
		MoRef rf = moRefOf(rv, "rootFolder");
		MoRef sm = moRefOf(rv, "sessionManager");
		MoRef setting = moRefOf(rv, "setting");
		String uuid = null;
		String fullName = null;
		String version = null;
		Element about = firstDirectChild(rv, "about");
		if (about != null) {
			uuid = childText(about, "instanceUuid");
			fullName = childText(about, "fullName");
			version = childText(about, "version");
		}
		if (sm == null || pc == null || rf == null) {
			throw new Exception("RetrieveServiceContent: incomplete content "
					+ "(sessionManager/propertyCollector/rootFolder missing)");
		}

		// Login: establishes the vmware_soap_session cookie. A cookie set
		// on RetrieveServiceContent is not a session until Login succeeds.
		pendingCookie = null;
		String loginBody =
				"<Login xmlns=\"urn:vim25\">"
				+ "<_this type=\"SessionManager\">"
				+ xmlEscape(sm.value) + "</_this>"
				+ "<userName>" + xmlEscape(username) + "</userName>"
				+ "<password>" + xmlEscape(password) + "</password>"
				+ "</Login>";
		Document loginResp = post(loginBody, "urn:vim25/Login", false);
		if (loginResp == null) {
			throw new Exception("Login failed (no response / SOAP fault)");
		}
		String cookie = pendingCookie;
		if (cookie == null) {
			throw new Exception("Login succeeded but no session cookie was "
					+ "returned");
		}

		// Login succeeded: only now does the client hold a session.
		this.propertyCollector = pc;
		this.viewManager = vm;
		this.rootFolder = rf;
		this.sessionManager = sm;
		this.settingOptionMgr = setting;
		this.aboutInstanceUuid = uuid;
		this.aboutFullName = fullName;
		this.aboutVersion = version;
		this.sessionCookie = cookie;

		// esxcli reader rides this session cookie; its cache is emptied
		// per cycle by beginCycle(). Review N3: a re-login keeps the
		// cycle's unreachable-host marks.
		EsxcliSoapClient fresh = new EsxcliSoapClient(vcenterUrl, cookie,
				sslFactory);
		EsxcliSoapClient prev = esxcli != null ? esxcli : retiredEsxcli;
		fresh.carryUnreachableFrom(prev);
		fresh.setMetrics(metrics);
		this.esxcli = fresh;
		this.retiredEsxcli = null;

		if (closed) {
			// Review W4: closed while this login was in flight; log the
			// new session straight out rather than leave it behind.
			logoutAndClear(logoutTimeoutMs, logoutTimeoutMs);
			throw new VimOptions.ReadFault(CLOSED);
		}
	}

	/** Build 95 review W4: why a closed client's call failed. */
	static final String CLOSED = "vCenter client closed (the instance was "
			+ "edited or removed); not logging in again";

	/**
	 * Close the client for good: mark it closed (no call logs in again,
	 * review W4), then log the session out within
	 * {@link #LOGOUT_TIMEOUT_MS} and forget it. Never throws.
	 */
	public void disconnect() {
		closed = true;
		logoutAndClear(logoutTimeoutMs, logoutTimeoutMs);
	}

	/** Build 95 review W4: whether {@link #disconnect} was called. */
	public boolean isClosed() {
		return closed;
	}

	/**
	 * Log the session out (waits bounded by the two timeouts) and clear
	 * the session state. The keepalive path uses it before logging
	 * in again; {@link #disconnect} before closing.
	 */
	private void logoutAndClear(int connectTimeoutMs, int readTimeoutMs) {
		MoRef sm = sessionManager;
		if (sm != null && sessionCookie != null) {
			try {
				String body =
						"<Logout xmlns=\"urn:vim25\">"
						+ "<_this type=\"SessionManager\">"
						+ xmlEscape(sm.value) + "</_this>"
						+ "</Logout>";
				postOnce(body, "urn:vim25/Logout", true, connectTimeoutMs,
						readTimeoutMs);
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
		aboutVersion = null;
		esxcli = null;
		retiredEsxcli = null;
	}

	/**
	 * Build 85: call once at the start of every collection cycle, after
	 * {@link #ensureConnected}. Empties the esxcli result cache so this
	 * cycle reads every host's esxcli commands again (a stale cached pass
	 * would be a false pass). No login, no vCenter call. A no-op when there
	 * is no session. Build 86: the esxcli part is exactly the SDK-free
	 * helper, so EsxcliCycleCacheTest covers the delegation. Build 95
	 * review W3: a new cycle may log in again after a failed login.
	 */
	public void beginCycle() {
		loginFailure = null;
		EsxcliSoapClient.beginCycleOn(esxcli);
	}

	/**
	 * Build 87: the first cause when this host's esxcli reads were skipped
	 * this cycle (esxcli-host-unreachable), returned once per host per
	 * cycle so the adapter logs one WARN naming the host; null otherwise.
	 */
	public String takeEsxcliUnreachable(String hostMoid) {
		EsxcliSoapClient c = esxcli;
		return c == null || hostMoid == null ? null
				: c.takeUnreachableToReport(hostMoid);
	}

	/**
	 * The adapter's once-per-cycle session check: logs in when there is no
	 * session, otherwise one CurrentTime keepalive and a fresh login if it
	 * fails. Build 95 (issue #17): only the adapter calls this, once at the
	 * start of a cycle; every read calls {@link #ensureSession} instead, so
	 * a cycle makes one keepalive, not one per public call. A session that
	 * lapses mid-cycle is caught by {@link #post} (NotAuthenticated: log in
	 * again, retry once).
	 */
	public void ensureConnected() throws Exception {
		// Build 95 review W3: the cycle's one session check always tries
		// (one Login per cycle at most when the credential is bad).
		loginFailure = null;
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
				logoutAndClear(CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS);
				connect();
			}
		} catch (Exception e) {
			logoutAndClear(CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS);
			connect();
		}
	}

	/**
	 * Build 95: log in only when there is no session (no keepalive). Every
	 * read starts here.
	 */
	private void ensureSession() throws Exception {
		if (closed) {
			throw new VimOptions.ReadFault(CLOSED);   // review W4
		}
		if (sessionCookie == null || propertyCollector == null) {
			String failed = loginFailure;
			if (failed != null) {
				// Build 95 review W3: one failed login per cycle, never one
				// per read (SSO lockout). The read fails, so its controls
				// are UNREADABLE, never a default.
				throw new VimOptions.ReadFault("vCenter login failed earlier "
						+ "this cycle (" + failed + "); not logging in again "
						+ "until the next cycle");
			}
			connect();
		}
	}

	/** Build 95 review W3: why login failed this cycle, or null. */
	String loginFailure() {
		return loginFailure;
	}

	// -----------------------------------------------------------------------
	// Inventory walkers (HostSystem / VM / DVS / DVPG / Cluster)
	// -----------------------------------------------------------------------

	public List<HostInfo> getHosts() throws Exception {
		ensureSession();
		List<HostInfo> result = new ArrayList<>();
		for (ViewRow row : listView("HostSystem")) {
			result.add(new HostInfo(row.ref, nameOf(row), row.ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " hosts");
		if (result.isEmpty()) {
			logWarn("vSphere SOAP: ContainerView returned 0 HostSystem — a "
					+ "vCenter inventory should have at least one host; "
					+ "check the RetrieveProperties walk");
		}
		return result;
	}

	/**
	 * VMs with name and host MOID. Build 58 (review N1): {@code name} and
	 * {@code runtime.host} come back in the ONE container-view
	 * RetrieveProperties, not one extra round trip per VM. If the bulk read
	 * returns nothing the pre-58 walk (listView + per-VM name) is used and
	 * {@link VmInfo#hostRead} is false, so the caller reads the host per VM.
	 * Build 88: {@code config.guestId} comes back in the same call, so a
	 * vSphere Pod VM (guest id crx*) is recognised at no extra cost. On the
	 * fallback walk the guest id is not read (null), so a Pod is handled as
	 * a VM there, and, having no VirtualMachine resource in VCF Ops, is
	 * reported as unmatched rather than skipped.
	 */
	public List<VmInfo> getVms() throws Exception {
		ensureSession();
		List<VmInfo> result = new ArrayList<>();
		List<ViewRow> rows = null;
		MoRef view = createContainerView("VirtualMachine");
		if (view != null) {
			try {
				rows = retrieveViewRows(view, "VirtualMachine",
						"name", "runtime.host", "config.guestId");
				if (rows == null) {
					// Build 88: a fault on the call with the added path must
					// not push every VM onto the per-VM fallback walk; retry
					// the pre-88 paths once (guest id then unknown, so Pods
					// are reported as unmatched instead of skipped).
					logWarn("vSphere SOAP: bulk VM read with config.guestId "
							+ "failed" + (lastFault != null ? " (" + lastFault
							+ ")" : "") + "; retrying without the guest id "
							+ "(vSphere Pod VMs not recognised this cycle)");
					rows = retrieveViewRows(view, "VirtualMachine",
							"name", "runtime.host");
				}
			} finally {
				destroyViewQuietly(view);
			}
		}
		if (rows != null && !rows.isEmpty()) {
			for (ViewRow row : rows) {
				String name = row.values.get("name");
				if (name == null) name = nameOrMoid(row.ref);
				result.add(new VmInfo(row.ref, name, row.ref.value,
						row.values.get("runtime.host"), true,
						row.values.get("config.guestId")));
			}
		} else {
			for (ViewRow row : listView("VirtualMachine")) {
				result.add(new VmInfo(row.ref, nameOf(row), row.ref.value));
			}
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
		ensureSession();
		List<DvsInfo> result = new ArrayList<>();
		List<ViewRow> rows = listView("VmwareDistributedVirtualSwitch");
		if (rows.isEmpty()) {
			rows = listView("DistributedVirtualSwitch");
		}
		for (ViewRow row : rows) {
			result.add(new DvsInfo(row.ref, nameOf(row), row.ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " DVS");
		return result;
	}

	public List<DvpgInfo> getDvPortgroups() throws Exception {
		ensureSession();
		List<DvpgInfo> result = new ArrayList<>();
		for (ViewRow row : listView("DistributedVirtualPortgroup")) {
			result.add(new DvpgInfo(row.ref, nameOf(row), row.ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " DVPG");
		return result;
	}

	public List<ClusterInfo> getClusters() throws Exception {
		ensureSession();
		List<ClusterInfo> result = new ArrayList<>();
		for (ViewRow row : listView("ClusterComputeResource")) {
			result.add(new ClusterInfo(row.ref, nameOf(row), row.ref.value));
		}
		logInfo("vSphere SOAP: " + result.size() + " Clusters");
		return result;
	}

	/**
	 * Build 95 (issue #17): the name the listing call returned with the
	 * object; only when it is missing is it read on its own
	 * ({@link #nameOrMoid}).
	 */
	private String nameOf(ViewRow row) throws Exception {
		String name = row.values.get("name");
		return name != null ? name : nameOrMoid(row.ref);
	}

	/**
	 * Build 77: an object's display name, or its MOID when the name read
	 * fails (logged). An object is never dropped from inventory because one
	 * property read faulted: it is still evaluated, and it still stitches by
	 * MOID.
	 */
	private String nameOrMoid(MoRef ref) throws Exception {
		String name = getStringProperty(ref, "name");
		if (name == null) {
			logWarn("vSphere SOAP: name of " + ref.type + " " + ref.value
					+ " unreadable" + (lastFault != null ? " (" + lastFault + ")"
					: "") + "; using its MOID");
			return ref.value;
		}
		return name;
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
		ensureSession();
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
		ensureSession();
		return getStringProperty(hostRef, "runtime.connectionState");
	}

	/**
	 * VM advanced settings via {@code config.extraConfig} — the VMX
	 * OptionValue list. Returned as a key/value map with the same
	 * stringification the v1 reader produced.
	 */
	public Map<String, String> getVmExtraConfig(MoRef vmRef) throws Exception {
		ensureSession();
		// Build 77: a failed read THROWS (VimOptions.ReadFault) instead of
		// returning an empty map, which the evaluator would read as "nothing
		// set" and pass every "X or Undefined" control. Empty now means only
		// "read OK, property unset".
		lastFault = null;
		Document resp = retrieveProperties(vmRef.type, vmRef.value,
				"config.extraConfig");
		return VimOptions.fromPropertyOptions(resp, "config.extraConfig",
				"RetrieveProperties config.extraConfig on " + vmRef.value,
				lastFault);
	}

	/**
	 * vCenter-level advanced settings via {@code ServiceContent.setting} ->
	 * {@code QueryOptions(null)}.
	 */
	public Map<String, String> getVCenterAdvancedSettings() throws Exception {
		ensureSession();
		if (settingOptionMgr == null) {
			// Build 77: no setting manager means the vCenter settings cannot
			// be read at all; never an empty "nothing set" map.
			throw new VimOptions.ReadFault("vCenter setting manager "
					+ "(ServiceContent.setting) missing");
		}
		return queryOptions(settingOptionMgr);
	}

	private Map<String, String> queryOptions(MoRef optionMgr) throws Exception {
		String body =
				"<QueryOptions xmlns=\"urn:vim25\">"
				+ "<_this type=\"" + xmlEscape(optionMgr.type) + "\">"
				+ xmlEscape(optionMgr.value) + "</_this>"
				+ "</QueryOptions>";
		lastFault = null;
		Document resp = post(body, "urn:vim25/QueryOptions", true);
		// Build 77: a SOAP fault (host stopped responding after the
		// connection check, session fault) THROWS instead of returning an
		// empty map; callers fold the advanced-setting controls to
		// UNREADABLE. Returnvals are nested under Envelope > Body >
		// QueryOptionsResponse (deep search, build 44).
		return VimOptions.fromQueryOptions(resp,
				"QueryOptions on " + optionMgr.value, lastFault);
	}

	// -----------------------------------------------------------------------
	// vCenter "about" info
	// -----------------------------------------------------------------------

	public String getVCenterInstanceUuid() throws Exception {
		ensureSession();
		return aboutInstanceUuid;
	}

	public String getVCenterDisplayName() throws Exception {
		ensureSession();
		return aboutFullName;
	}

	/**
	 * v3: vCenter product version ({@code ServiceContent.about.version},
	 * e.g. {@code "8.0.3"}). Governs benchmark choice for the vCenter,
	 * clusters, distributed switches and portgroups. Null when the about
	 * block carried no version (never guessed).
	 */
	public String getVCenterVersion() throws Exception {
		ensureSession();
		return aboutVersion;
	}

	/**
	 * v3: a host's ESX product version (e.g. {@code "8.0.3"} for 8.0 U3).
	 * Reads {@code summary.config.product.version} first (vCenter keeps it
	 * for disconnected hosts too), then {@code config.product.version}.
	 * Null when neither resolves; the caller treats null as "version
	 * unreadable", never as a default version.
	 */
	public String getHostProductVersion(MoRef hostRef) throws Exception {
		ensureSession();
		if (hostRef == null) return null;
		String v = getStringProperty(hostRef, "summary.config.product.version");
		if (v == null) {
			v = getStringProperty(hostRef, "config.product.version");
		}
		return v;
	}

	/**
	 * v3: the MOID of the host a VM is registered on
	 * ({@code runtime.host}). Null when unset (e.g. an orphaned VM).
	 */
	public String getVmHostMoid(MoRef vmRef) throws Exception {
		ensureSession();
		if (vmRef == null) return null;
		MoRef host = getMoRefProperty(vmRef, "runtime.host");
		return host == null ? null : host.value;
	}

	// -----------------------------------------------------------------------
	// vSAN presence probe (ClusterComputeResource.configurationEx)
	// -----------------------------------------------------------------------

	/**
	 * Whether vSAN is ENABLED on a cluster (build 74: {@link VsanGate}).
	 * False means the vSAN controls are not applicable (no score, no
	 * unreadable). Throws when {@code configurationEx} cannot be read, so the
	 * caller folds the controls to UNREADABLE. DOM walk; never casts.
	 */
	public boolean hasVsanConfig(MoRef clusterRef) throws Exception {
		ensureSession();
		if (clusterRef == null) {
			throw new Exception("no cluster MoRef");
		}
		Element configEx = getRawPropertyElement(clusterRef, "configurationEx");
		if (configEx == null) {
			// Build 74: every cluster has configurationEx; a null here is a
			// FAILED read (SOAP fault / missing propSet), not "no vSAN".
			// Throwing makes the caller fold the vSAN controls to
			// UNREADABLE instead of quietly calling them not applicable.
			throw new Exception("configurationEx unreadable"
					+ (lastFault != null ? " (" + lastFault + ")" : ""));
		}
		// Build 74: vSAN enabled only when vsanConfigInfo/enabled is true.
		// vCenter 9.x returns vsanConfigInfo (enabled=false) on non-vSAN
		// clusters too, so "element present" scored them on vSAN controls.
		return VsanGate.vsanEnabled(configEx);
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
		ensureSession();
		Map<String, Object> result = new HashMap<>();
		synchronized (lastReasons) {
			lastReasons.clear();
		}
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
			readFailure = null;
			lastFault = null;
			try {
				value = readByRecipe(new SoapSource(moRef), recipe.trim());
			} catch (Exception e) {
				value = null;
				readFailure = "exception: " + e.getClass().getSimpleName()
						+ ": " + e.getMessage();
			}
			if (value == null) {
				String why = readFailure;
				if (why == null) {
					why = lastFault != null ? faultReason(recipe.trim())
							: "value-absent: " + recipe.trim();
				}
				synchronized (lastReasons) {
					lastReasons.put(c.parameter, why);
				}
			}
			result.put(c.parameter, value != null ? value : UNREADABLE);
		}
		return result;
	}

	/**
	 * Build 74: parameter -> reason for each control the most recent
	 * {@link #readVimProperties} call could not read (a copy).
	 */
	public Map<String, String> lastReadReasons() {
		synchronized (lastReasons) {
			return new HashMap<>(lastReasons);
		}
	}

	/**
	 * Read one recipe ({@code <style>:<vim_path>}) against a resource MoRef.
	 * Returns the typed value or null (-> UNREADABLE). The grammar and the
	 * per-style outcomes are identical to the JAX-WS implementation; the only
	 * change is the walk substrate (DOM elements instead of binding objects).
	 */
	Object readByRecipe(MoRef moRef, String recipe) throws Exception {
		return readByRecipe(new SoapSource(moRef), recipe);
	}

	/**
	 * Build 95: one recipe against a property source, the per-object SOAP
	 * reads ({@link SoapSource}) or one object of a bulk page
	 * ({@link BulkRow}). The style readers are the same for both, so the
	 * shadow comparison differs only in where the data came from.
	 */
	Object readByRecipe(PropSource src, String recipe) throws Exception {
		int colon = recipe.indexOf(':');
		if (colon <= 0 || colon >= recipe.length() - 1) {
			readFailure = "recipe-malformed: " + recipe;
			return null;
		}
		String style = recipe.substring(0, colon).trim();
		String path = recipe.substring(colon + 1).trim();
		if (path.isEmpty()) {
			readFailure = "recipe-malformed: " + recipe;
			return null;
		}

		// esxcli and service_state carry a three-part grammar; handle before
		// the generic dotted-path split.
		if ("esxcli".equals(style)) {
			MoRef moRef = src.moRef();
			if (src instanceof BulkRow) {
				readFailure = "esxcli-not-bulk: " + path;
				return null;   // esxcli stays per object (a command, not a property)
			}
			return readEsxcliRecipe(moRef, path);
		}
		if ("service_state".equals(style)) {
			return readServiceStateRecipe(src, path);
		}

		String[] segments = path.split("\\.");
		switch (style) {
			case "scalar":
				return readScalarRecipe(src, segments);
			case "bool":
				return readBoolRecipe(src, segments);
			case "bool_policy":
				return readBoolPolicyRecipe(src, segments);
			case "string_list_join":
				return readStringListJoinRecipe(src, segments);
			case "vm_hardware_device_absent":
				return readDeviceAbsentRecipe(src, segments);
			case "list_empty":
				return readListEmptyRecipe(src, segments);
			case "vlan_id_not":
				return readVlanIdNotRecipe(src, segments);
			default:
				readFailure = "recipe-unknown-style: " + style;
				return null;   // unknown style -> UNREADABLE, never a guess
		}
	}

	// ----- esxcli style (delegates to the proven raw-SOAP esxcli client) ---

	private Object readEsxcliRecipe(MoRef moRef, String path) throws Exception {
		if (esxcli == null) {
			readFailure = "esxcli-unavailable: no esxcli session";
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
		// Build 95 (issue #17): esxcli time and calls are their own phase.
		try (CycleMetrics.Scope ph = CycleMetrics.scope(metrics,
				CycleMetrics.Phase.ESXCLI)) {
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
		}
		if (EsxcliSoapClient.COMMAND_FAILED.equals(value)) {
			// Build 86: a host whose esxcli request (made through vCenter)
			// timed out or could not connect once this cycle is skipped for
			// its other commands; say why, with the first cause. Build 87:
			// the label choice is the SDK-free helper, so it is tested.
			readFailure = EsxcliSoapClient.commandFailedReason(
					namespaceCommand, esxcli.unreachableReason(hostMoid),
					lastFault);
			return null;
		}
		if (value == null) {
			java.util.Set<String> have = esxcli.structFields(hostMoid,
					namespaceCommand);
			readFailure = "esxcli-field-missing: " + namespaceCommand + " "
					+ fieldSpec + (have.isEmpty() ? "" : " (fields: " + have + ")");
			// Build 74: say so once per (command, field) per collector
			// session; field names for some rows come from the vendor audit
			// script and are not yet confirmed on the wire.
			if (warnedEsxciFields.add(namespaceCommand + "|" + fieldSpec)) {
				logWarn("esxcli " + namespaceCommand + ": field '" + fieldSpec
						+ "' not in the result" + (have.isEmpty() ? ""
						: " (fields returned: " + have + ")")
						+ "; controls reading it are UNREADABLE");
			}
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
	private Object readServiceStateRecipe(PropSource src, String path)
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
		if (src == null) return null;

		// config.service resolves to a HostServiceInfo; its <service> children
		// are the HostService entries.
		Element serviceInfo = src.exact("config.service");
		if (serviceInfo == null) {
			readFailure = src.missingReason("config.service");
			return null;
		}

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

	private Object readScalarRecipe(PropSource src, String[] segments)
			throws Exception {
		Element node = walkToNode(src, segments);
		if (node == null) return null;
		String text = elementText(node);
		if (text == null || text.isEmpty()) {
			readFailure = "empty-value: " + String.join(".", segments);
			return null;
		}
		return text;
	}

	/**
	 * bool style — walk to the final-segment element, read it as a boolean.
	 * Reproduces the vSAN reader (configurationEx -> vsanConfigInfo ->
	 * enabled / objectChecksumEnabled / ...). DOM: the leaf element's text is
	 * {@code true}/{@code false}.
	 */
	private Boolean readBoolRecipe(PropSource src, String[] segments)
			throws Exception {
		Element node = walkToNode(src, segments);
		if (node == null) return null;
		Boolean b = parseBool(elementText(node));
		if (b == null) {
			readFailure = "unparsable-value: " + String.join(".", segments);
		}
		return b;
	}

	/**
	 * bool_policy style — walk to the PARENT of the final segment (a
	 * DVSSecurityPolicy), then read the final segment (a BoolPolicy wrapper)
	 * -> its {@code value} child. Reproduces readSecurityPolicy:
	 * config.defaultPortConfig -> securityPolicy -> &lt;field&gt; (BoolPolicy)
	 * -> value.
	 */
	private Boolean readBoolPolicyRecipe(PropSource src, String[] segments)
			throws Exception {
		Element parent = walkToParent(src, segments);
		if (parent == null) return null;
		String field = segments[segments.length - 1];
		Element wrapper = firstDirectChild(parent, field);
		if (wrapper == null) return null;
		// BoolPolicy.value child. Absent value -> null (not present), never
		// false.
		String v = childText(wrapper, "value");
		return parseBool(v);
	}

	private String readStringListJoinRecipe(PropSource src, String[] segments)
			throws Exception {
		// The final segment names a repeated element; walk to its PARENT and
		// collect every direct child of that name. An empty list -> null
		// (coverage gap, never a "(non-empty)" pass) — identical to v1.
		Element parent = walkToParent(src, segments);
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
	private ListRead readListConfirmed(PropSource src, String[] segments)
			throws Exception {
		if (segments == null || segments.length == 0) return ListRead.failed();
		Element container = walkToParent(src, segments);
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
	private Boolean readDeviceAbsentRecipe(PropSource src, String[] segments)
			throws Exception {
		if (segments.length < 2) return null;
		String typeName = segments[segments.length - 1];
		String[] listPath = new String[segments.length - 1];
		System.arraycopy(segments, 0, listPath, 0, segments.length - 1);

		ListRead read = readListConfirmed(src, listPath);
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
	private Boolean readListEmptyRecipe(PropSource src, String[] segments)
			throws Exception {
		ListRead read = readListConfirmed(src, segments);
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
	private Boolean readVlanIdNotRecipe(PropSource src, String[] segments)
			throws Exception {
		Element specNode = walkToNode(src, segments);
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
	private Element walkToNode(PropSource src, String[] segments)
			throws Exception {
		int[] consumed = new int[1];
		Element node = src.longest(segments, segments.length, consumed);
		if (node == null) {
			readFailure = src.noPrefixReason(segments, segments.length);
			return null;
		}
		for (int i = consumed[0]; i < segments.length; i++) {
			Element next = firstDirectChild(node, segments[i]);
			if (next == null) {
				readFailure = "missing-element: '" + segments[i] + "' in "
						+ String.join(".", segments);
				return null;
			}
			node = next;
		}
		return node;
	}

	/**
	 * Walk to the parent of the final path segment. PropertyCollector is
	 * capped at {@code segments.length - 1} so it never resolves the leaf
	 * directly — the bool / bool_policy / list styles need the leaf element
	 * (and its xsi:type / wrapper) intact, read off the parent.
	 */
	private Element walkToParent(PropSource src, String[] segments)
			throws Exception {
		int[] consumed = new int[1];
		Element node = src.longest(segments, segments.length - 1, consumed);
		if (node == null) {
			readFailure = src.noPrefixReason(segments, segments.length - 1);
			return null;
		}
		for (int i = consumed[0]; i < segments.length - 1; i++) {
			Element next = firstDirectChild(node, segments[i]);
			if (next == null) {
				readFailure = "missing-element: '" + segments[i] + "' in "
						+ String.join(".", segments);
				return null;
			}
			node = next;
		}
		return node;
	}

	/**
	 * Build 95 (issue #17): the most prefix lengths the per-object fallback
	 * tries for one path (longest first). The longest recipe today needs
	 * four (a cluster vSAN path that resolves only at
	 * {@code configurationEx}).
	 */
	static final int MAX_PREFIX_ATTEMPTS = 4;

	/**
	 * Build 95 (issue #17): the shortest prefix the fallback may fetch for
	 * an object of {@code type}. For HostSystem and VirtualMachine it is 2,
	 * so a path that does not resolve never pulls the whole {@code config}
	 * (HostConfigInfo / VirtualMachineConfigInfo, the largest objects in
	 * the inventory); every host and VM recipe resolves at two segments or
	 * more when the data exists. Other kinds need one segment
	 * ({@code configurationEx} for the cluster vSAN paths, the switch's
	 * {@code config} for VMware-switch-only properties), so 1.
	 */
	static int minPrefixSegments(String type) {
		return "HostSystem".equals(type) || "VirtualMachine".equals(type)
				? 2 : 1;
	}

	/**
	 * Build 95: the prefix lengths to try for a path of {@code segments}
	 * capped at {@code maxLen}, longest first, within
	 * {@link #minPrefixSegments} and {@link #MAX_PREFIX_ATTEMPTS}. SDK-free
	 * arithmetic, tested directly.
	 */
	static int[] prefixLengths(String type, int segments, int maxLen) {
		int start = Math.min(maxLen, segments);
		int floor = Math.max(minPrefixSegments(type),
				start - MAX_PREFIX_ATTEMPTS + 1);
		if (start < floor) return new int[0];
		int[] out = new int[start - floor + 1];
		for (int i = 0; i < out.length; i++) out[i] = start - i;
		return out;
	}

	/**
	 * Build 95: where recipe reads get their property values. The style
	 * readers walk the returned DOM the same way whichever source it is.
	 */
	interface PropSource {
		MoRef moRef();
		/** The value of exactly {@code path}, or null. */
		Element exact(String path) throws Exception;
		/**
		 * The value of the longest resolvable prefix of {@code segments}
		 * no longer than {@code maxLen}; the segments consumed go to
		 * {@code consumedOut[0]}. Null (consumed 0) when none resolves.
		 */
		Element longest(String[] segments, int maxLen, int[] consumedOut)
				throws Exception;
		/** Why {@link #exact} returned null for {@code path}. */
		String missingReason(String path);
		/** Why {@link #longest} returned null. */
		String noPrefixReason(String[] segments, int maxLen);
	}

	/** Build 95: the per-object path, one RetrieveProperties per prefix. */
	final class SoapSource implements PropSource {
		private final MoRef ref;

		SoapSource(MoRef ref) {
			this.ref = ref;
		}

		@Override public MoRef moRef() { return ref; }

		@Override
		public Element exact(String path) throws Exception {
			return getRawPropertyElement(ref, path);
		}

		/**
		 * Try PropertyCollector against progressively shorter dotted
		 * prefixes of {@code segments} (longest first, no longer than
		 * {@code maxLen}) and return the first {@code <val>} element that
		 * resolves. Build 95 (issue #17): bounded by
		 * {@link #prefixLengths}, so it can never fetch a whole host or VM
		 * {@code config}; a path that does not resolve within the bound is
		 * UNREADABLE with a {@code prefix-cap} reason, never a pass.
		 */
		@Override
		public Element longest(String[] segments, int maxLen,
				int[] consumedOut) throws Exception {
			for (int len : prefixLengths(ref.type, segments.length, maxLen)) {
				Element v;
				try {
					v = getRawPropertyElement(ref, join(segments, len));
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

		@Override
		public String missingReason(String path) {
			return lastFault != null ? faultReason(path)
					: "missing-element: " + path + " not returned";
		}

		@Override
		public String noPrefixReason(String[] segments, int maxLen) {
			String path = String.join(".", segments);
			if (lastFault != null) {
				return faultReason(path);
			}
			int[] lens = prefixLengths(ref.type, segments.length, maxLen);
			if (lens.length == 0) {
				return "prefix-cap: " + path + " needs a prefix shorter "
						+ "than this object type may fetch";
			}
			if (lens[lens.length - 1] > 1) {
				return "prefix-cap: no prefix of " + path + " down to "
						+ lens[lens.length - 1] + " segment(s) resolved; "
						+ "shorter prefixes are not fetched";
			}
			return "missing-element: no prefix of " + path + " resolved";
		}
	}

	/**
	 * Build 95: the unreadable reason for the last failed call: category
	 * response-too-large when the response was over the cap, else
	 * soap-fault.
	 */
	private String faultReason(String what) {
		return (lastTooLarge ? "response-too-large: " : "soap-fault: ")
				+ lastFault + " (" + what + ")";
	}

	static String join(String[] segments, int len) {
		StringBuilder p = new StringBuilder();
		for (int i = 0; i < len; i++) {
			if (i > 0) p.append('.');
			p.append(segments[i]);
		}
		return p.toString();
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
	 * RetrieveProperties the view members with their {@code name}, then
	 * destroy the view. Build 95 (issue #17): the names come back in the
	 * same call and are kept (they used to be discarded and read again one
	 * object at a time). The view is always destroyed even on a mid-walk
	 * failure; a failed listing throws (build 77: never an empty
	 * inventory).
	 */
	private List<ViewRow> listView(String type) throws Exception {
		MoRef view = createContainerView(type);
		if (view == null) {
			throw new VimOptions.ReadFault("CreateContainerView(" + type
					+ ") returned no view");
		}
		try {
			lastFault = null;
			List<ViewRow> rows = retrieveViewRows(view, type, "name");
			if (rows == null) {
				// Build 77: a failed listing is not an empty inventory.
				throw new VimOptions.ReadFault("listView(" + type + "): "
						+ "RetrieveProperties failed"
						+ (lastFault != null ? ": " + lastFault : ""));
			}
			logInfo("listView(" + type + "): RetrieveProperties -> "
					+ rows.size() + " objectContent");
			if (!rows.isEmpty() && log != null && log.isDebugEnabled()) {
				logDebug("listView(" + type + "): first object type="
						+ rows.get(0).ref.type + " value="
						+ rows.get(0).ref.value);
			}
			return rows;
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
		lastFault = null;
		Document resp = post(body, "urn:vim25/CreateContainerView", true);
		if (resp == null) {
			// Build 77: a failed view is not an empty inventory.
			throw new VimOptions.ReadFault("CreateContainerView(" + type
					+ ") failed" + (lastFault != null ? ": " + lastFault : ""));
		}
		Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
		if (rv == null) return null;
		String val = elementText(rv);
		if (val == null || val.trim().isEmpty()) return null;
		String t = rv.getAttribute("type");
		return new MoRef(t != null && !t.isEmpty() ? t : "ContainerView",
				val.trim());
	}

	/** One container-view object with the text of the requested paths. */
	private static final class ViewRow {
		final MoRef ref;
		final Map<String, String> values = new HashMap<>();
		ViewRow(MoRef ref) { this.ref = ref; }
	}

	/**
	 * RetrieveProperties over a container view for several property paths
	 * at once. A MoRef-valued path yields its MOID text. Null on a failed
	 * call (caller falls back); a path absent for an object is simply
	 * missing from that row.
	 */
	private List<ViewRow> retrieveViewRows(MoRef view, String type,
			String... paths) throws Exception {
		StringBuilder pathSet = new StringBuilder();
		for (String p : paths) {
			pathSet.append("<pathSet>").append(xmlEscape(p)).append("</pathSet>");
		}
		String body =
				"<RetrieveProperties xmlns=\"urn:vim25\">"
				+ "<_this type=\"PropertyCollector\">"
				+ xmlEscape(propertyCollector.value) + "</_this>"
				+ "<specSet>"
				+ "<propSet>"
				+ "<type>" + xmlEscape(type) + "</type>"
				+ pathSet
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
		if (resp == null) return null;
		List<ViewRow> rows = new ArrayList<>();
		for (Element rv : descendantsByLocalName(resp.getDocumentElement(),
				"returnval")) {
			Element obj = firstDirectChild(rv, "obj");
			if (obj == null) continue;
			String value = elementText(obj);
			if (value == null || value.trim().isEmpty()) continue;
			String t = obj.getAttribute("type");
			ViewRow row = new ViewRow(new MoRef(
					t != null && !t.isEmpty() ? t : type, value.trim()));
			for (Element propSet : childrenByLocalName(rv, "propSet")) {
				String name = childText(propSet, "name");
				Element val = firstDirectChild(propSet, "val");
				if (name == null || val == null) continue;
				String text = elementText(val);
				if (text != null && !text.trim().isEmpty()) {
					row.values.put(name, text.trim());
				}
			}
			rows.add(row);
		}
		return rows;
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
	// Build 95: paged bulk reads (bulk-collection design build B, shadow)
	// -----------------------------------------------------------------------

	/** Corrections of an invalid bulk path set per kind, at most. */
	static final int MAX_BULK_PATH_FIXES = 64;

	/**
	 * Build 95: the property paths one bulk read must return so every
	 * vim_property recipe and the advanced settings of {@code controls} can
	 * be evaluated locally, derived from the recipes (a new control needs no
	 * code). Per style, the path the per-object reader asks for first:
	 * the full path for scalar, bool and vlan_id_not; the parent of the
	 * last segment for bool_policy, string_list_join and list_empty; two
	 * up for vm_hardware_device_absent; {@code config.service} for
	 * service_state. esxcli is not a property and stays per object. Hosts
	 * add {@code config.option} and VMs {@code config.extraConfig} when the
	 * slice has advanced settings. SDK-free, tested directly.
	 */
	static Set<String> bulkPaths(String type,
			List<BenchmarkProfile.Control> controls) {
		Set<String> out = new LinkedHashSet<>();
		boolean advanced = false;
		for (BenchmarkProfile.Control c : controls) {
			if (!c.isEvaluable()) continue;
			if ("advanced_setting".equals(c.parameterKind)) {
				advanced = true;
				continue;
			}
			if (!"vim_property".equals(c.parameterKind)) continue;
			String path = recipePath(c.readRecipe);
			String style = recipeStyle(c.readRecipe);
			if (path == null || style == null) continue;
			if ("service_state".equals(style)) {
				out.add("config.service");
				continue;
			}
			String[] seg = path.split("\\.");
			int keep;
			switch (style) {
				case "scalar": case "bool": case "vlan_id_not":
					keep = seg.length; break;
				case "bool_policy": case "string_list_join": case "list_empty":
					keep = seg.length - 1; break;
				case "vm_hardware_device_absent":
					keep = seg.length - 2; break;
				default:
					keep = 0;   // unknown style: UNREADABLE either way
			}
			if (keep >= 1) out.add(join(seg, keep));
		}
		String adv = advancedPath(type);
		if (advanced && adv != null) out.add(adv);
		return out;
	}

	/** The bulk path carrying the advanced settings of {@code type}. */
	static String advancedPath(String type) {
		if ("HostSystem".equals(type)) return "config.option";
		if ("VirtualMachine".equals(type)) return "config.extraConfig";
		return null;
	}

	private static String recipeStyle(String recipe) {
		if (recipe == null) return null;
		int c = recipe.trim().indexOf(':');
		return c <= 0 ? null : recipe.trim().substring(0, c).trim();
	}

	private static String recipePath(String recipe) {
		if (recipe == null) return null;
		String r = recipe.trim();
		int c = r.indexOf(':');
		if (c <= 0 || c >= r.length() - 1) return null;
		String p = r.substring(c + 1).trim();
		return p.isEmpty() ? null : p;
	}

	/**
	 * The bulk path to ask for instead of {@code path} after vCenter
	 * called it invalid for {@code type} (a property defined only on a
	 * subtype): its parent, or null when the parent would be shorter than
	 * {@link #minPrefixSegments} (the path is then dropped and the controls
	 * reading it are UNREADABLE in the bulk result).
	 */
	static String shortenBulkPath(String type, String path) {
		int dot = path.lastIndexOf('.');
		if (dot <= 0) return null;
		String parent = path.substring(0, dot);
		int segs = parent.split("\\.").length;
		return segs >= minPrefixSegments(type) ? parent : null;
	}

	/** One object of a bulk page; a {@link PropSource} for the readers. */
	public static final class BulkRow implements PropSource {
		public final MoRef ref;
		final Map<String, Element> values = new HashMap<>();
		final Map<String, String> missing = new HashMap<>();

		BulkRow(MoRef ref) {
			this.ref = ref;
		}

		@Override public MoRef moRef() { return ref; }

		@Override
		public Element exact(String path) {
			return values.get(path);
		}

		/**
		 * The longest requested path that is a prefix of
		 * {@code segments}, within the same lengths the per-object reader
		 * would try ({@link #prefixLengths}).
		 */
		@Override
		public Element longest(String[] segments, int maxLen,
				int[] consumedOut) {
			for (int len : prefixLengths(ref.type, segments.length, maxLen)) {
				Element v = values.get(join(segments, len));
				if (v != null) {
					consumedOut[0] = len;
					return v;
				}
			}
			consumedOut[0] = 0;
			return null;
		}

		@Override
		public String missingReason(String path) {
			String f = missing.get(path);
			return f != null ? "soap-fault: " + f + " (" + path + ")"
					: "missing-element: " + path + " not in the bulk read";
		}

		@Override
		public String noPrefixReason(String[] segments, int maxLen) {
			for (int len : prefixLengths(ref.type, segments.length, maxLen)) {
				String f = missing.get(join(segments, len));
				if (f != null) {
					return "soap-fault: " + f + " ("
							+ String.join(".", segments) + ")";
				}
			}
			return "missing-element: no prefix of "
					+ String.join(".", segments) + " in the bulk read";
		}
	}

	/** Receives one bulk page at a time; the page is not kept afterwards. */
	public interface PageHandler {
		void page(List<BulkRow> rows) throws Exception;
	}

	/** What one bulk read did. */
	public static final class BulkStats {
		public int pages;
		public int objects;
		public int pathFixes;
		public List<String> pathSet = new ArrayList<>();
		public List<String> droppedPaths = new ArrayList<>();
	}

	// type + requested paths -> the path set vCenter accepted, and the
	// paths dropped on the way (so only the first cycle pays the fixes).
	private final Map<String, BulkStats> acceptedPaths =
			new java.util.concurrent.ConcurrentHashMap<>();

	/**
	 * Build 95: every object of {@code type} under the root folder with the
	 * values of {@code paths}, in pages of about {@code pageSize} objects
	 * (RetrievePropertiesEx, then ContinueRetrievePropertiesEx while vCenter
	 * returns a token), each page handed to {@code handler} and released
	 * before the next is requested. A path vCenter rejects as
	 * InvalidProperty is shortened ({@link #shortenBulkPath}) and the call
	 * repeated; the accepted set is remembered for later cycles. Throws
	 * {@link VimOptions.ReadFault} when the view, the first page or any
	 * later page fails (the remaining pages are cancelled): a failed page
	 * is a failed read of the kind, never a short inventory.
	 */
	public BulkStats retrieveBulk(String type, Collection<String> paths,
			int pageSize, PageHandler handler) throws Exception {
		ensureSession();
		BulkStats st = new BulkStats();
		if (paths == null || paths.isEmpty()) return st;
		String cacheKey = type + "|" + String.join(",",
				new java.util.TreeSet<>(paths));
		BulkStats known = acceptedPaths.get(cacheKey);
		Set<String> set = new LinkedHashSet<>(
				known != null ? known.pathSet : paths);
		if (known != null) st.droppedPaths.addAll(known.droppedPaths);

		MoRef view = createContainerView(type);
		if (view == null) {
			throw new VimOptions.ReadFault("CreateContainerView(" + type
					+ ") returned no view");
		}
		// Review N1: the token of the retrieval still open on vCenter, set
		// as soon as a page is parsed and before its handler runs, so a
		// handler that throws (Stop, an evaluation error) cancels the next
		// page's token, not the one already consumed.
		String[] open = {null};
		try {
			Document resp;
			while (true) {
				if (set.isEmpty()) {
					throw new VimOptions.ReadFault("bulk " + type + ": no "
							+ "property path vCenter accepts (dropped "
							+ st.droppedPaths + ")");
				}
				lastFault = null;
				resp = post(retrievePropertiesExBody(view, type, set,
						pageSize), "urn:vim25/RetrievePropertiesEx", true);
				if (resp != null) break;
				String bad = lastInvalidProperty;
				if (bad == null || !set.contains(bad)
						|| st.pathFixes >= MAX_BULK_PATH_FIXES) {
					throw new VimOptions.ReadFault("RetrievePropertiesEx("
							+ type + ") failed"
							+ (lastFault != null ? ": " + lastFault : ""));
				}
				st.pathFixes++;
				set.remove(bad);
				String parent = shortenBulkPath(type, bad);
				if (parent != null) {
					set.add(parent);
				} else {
					st.droppedPaths.add(bad);
				}
			}
			st.pathSet = new ArrayList<>(set);
			BulkStats remember = new BulkStats();
			remember.pathSet = st.pathSet;
			remember.droppedPaths = new ArrayList<>(st.droppedPaths);
			acceptedPaths.put(cacheKey, remember);

			handlePage(resp, type, handler, st, open);
			while (open[0] != null) {
				String token = open[0];
				lastFault = null;
				Document next = post("<ContinueRetrievePropertiesEx "
						+ "xmlns=\"urn:vim25\">"
						+ "<_this type=\"PropertyCollector\">"
						+ xmlEscape(propertyCollector.value) + "</_this>"
						+ "<token>" + xmlEscape(token) + "</token>"
						+ "</ContinueRetrievePropertiesEx>",
						"urn:vim25/ContinueRetrievePropertiesEx", true);
				if (next == null) {
					throw new VimOptions.ReadFault("bulk " + type + ": page "
							+ (st.pages + 1) + " failed"
							+ (lastFault != null ? ": " + lastFault : ""));
				}
				handlePage(next, type, handler, st, open);
			}
			return st;
		} catch (Exception e) {
			if (open[0] != null) cancelRetrieveQuietly(open[0]);
			throw e;
		} finally {
			destroyViewQuietly(view);
		}
	}

	private String retrievePropertiesExBody(MoRef view, String type,
			Collection<String> paths, int pageSize) {
		StringBuilder pathSet = new StringBuilder();
		for (String p : paths) {
			pathSet.append("<pathSet>").append(xmlEscape(p))
					.append("</pathSet>");
		}
		return "<RetrievePropertiesEx xmlns=\"urn:vim25\">"
				+ "<_this type=\"PropertyCollector\">"
				+ xmlEscape(propertyCollector.value) + "</_this>"
				+ "<specSet>"
				+ "<propSet>"
				+ "<type>" + xmlEscape(type) + "</type>"
				+ pathSet
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
				+ "<options><maxObjects>" + Math.max(1, pageSize)
				+ "</maxObjects></options>"
				+ "</RetrievePropertiesEx>";
	}

	/**
	 * Parse one page, record its next-page token (or null) in
	 * {@code openToken[0]}, then hand the page over (review N1: the token
	 * is recorded first, so it is the one cancelled if the handler throws).
	 */
	private void handlePage(Document resp, String type, PageHandler handler,
			BulkStats st, String[] openToken) throws Exception {
		Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
		List<BulkRow> rows = new ArrayList<>();
		String token = null;
		if (rv != null) {
			String t = childText(rv, "token");
			token = t == null || t.trim().isEmpty() ? null : t.trim();
			for (Element oc : childrenByLocalName(rv, "objects")) {
				Element obj = firstDirectChild(oc, "obj");
				if (obj == null) continue;
				String value = elementText(obj);
				if (value == null || value.trim().isEmpty()) continue;
				String ot = obj.getAttribute("type");
				BulkRow row = new BulkRow(new MoRef(
						ot != null && !ot.isEmpty() ? ot : type, value.trim()));
				for (Element ps : childrenByLocalName(oc, "propSet")) {
					String name = childText(ps, "name");
					Element val = firstDirectChild(ps, "val");
					if (name != null && val != null) row.values.put(name, val);
				}
				for (Element ms : childrenByLocalName(oc, "missingSet")) {
					String path = childText(ms, "path");
					if (path == null) continue;
					String f = VimOptions.missingSetFault(oc, path);
					row.missing.put(path, f != null ? f : "unknown");
				}
				rows.add(row);
			}
		}
		st.pages++;
		st.objects += rows.size();
		openToken[0] = token;
		handler.page(rows);
	}

	private void cancelRetrieveQuietly(String token) {
		try {
			post("<CancelRetrievePropertiesEx xmlns=\"urn:vim25\">"
					+ "<_this type=\"PropertyCollector\">"
					+ xmlEscape(propertyCollector.value) + "</_this>"
					+ "<token>" + xmlEscape(token) + "</token>"
					+ "</CancelRetrievePropertiesEx>",
					"urn:vim25/CancelRetrievePropertiesEx", true);
		} catch (Exception ignored) {}
	}

	/**
	 * Build 95: the advanced-setting and vim_property control results for
	 * one bulk object, evaluated locally with the same evaluator and the
	 * same recipe readers as the per-object path (esxcli and VAMI controls
	 * are not produced). An advanced-settings value the bulk read did not
	 * return makes those controls UNREADABLE, never passes.
	 */
	public List<ControlEvaluator.ControlResult> evaluateBulkRow(BulkRow row,
			List<BenchmarkProfile.Control> controls, String name) {
		List<ControlEvaluator.ControlResult> out = new ArrayList<>();
		String advPath = advancedPath(row.ref.type);
		if (advPath != null && hasKind(controls, "advanced_setting")) {
			Element val = row.values.get(advPath);
			ControlEvaluator.ComplianceResult adv;
			if (val == null) {
				adv = ControlEvaluator.evaluateControlsUnreadable(controls,
						name);
			} else {
				Map<String, String> opts = new HashMap<>();
				for (Element item : childElements(val)) {
					String k = childText(item, "key");
					String v = childText(item, "value");
					if (k != null && v != null) opts.put(k, v);
				}
				adv = ControlEvaluator.evaluateControls(controls, opts, name);
			}
			out.addAll(adv.controlResults);
		}
		List<BenchmarkProfile.Control> vim = new ArrayList<>();
		Map<String, Object> values = new HashMap<>();
		for (BenchmarkProfile.Control c : controls) {
			if (!"vim_property".equals(c.parameterKind) || !c.isEvaluable()
					|| c.readRecipe == null || c.readRecipe.trim().isEmpty()) {
				continue;
			}
			vim.add(c);
			Object v;
			readFailure = null;
			try {
				v = readByRecipe(row, c.readRecipe.trim());
			} catch (Exception e) {
				v = null;
			}
			values.put(c.parameter, v != null ? v : UNREADABLE);
		}
		if (!vim.isEmpty()) {
			out.addAll(ControlEvaluator.evaluateVimProperties(vim, values,
					name, UNREADABLE).controlResults);
		}
		return out;
	}

	/**
	 * Build 95: the control ids {@link #evaluateBulkRow} produces for
	 * {@code controls} (advanced settings on hosts and VMs, vim
	 * properties), the ones the shadow comparison checks.
	 */
	public static Set<String> bulkComparable(String type,
			List<BenchmarkProfile.Control> controls) {
		Set<String> out = new java.util.HashSet<>();
		boolean adv = advancedPath(type) != null;
		for (BenchmarkProfile.Control c : controls) {
			if (!c.isEvaluable()) continue;
			if ("vim_property".equals(c.parameterKind)
					|| (adv && "advanced_setting".equals(c.parameterKind))) {
				out.add(c.controlId);
			}
		}
		return out;
	}

	private static boolean hasKind(List<BenchmarkProfile.Control> controls,
			String kind) {
		for (BenchmarkProfile.Control c : controls) {
			if (kind.equals(c.parameterKind) && c.isEvaluable()) return true;
		}
		return false;
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
		Document d = postOnce(soapBody, soapAction, authenticated);
		if (d == null && authenticated && lastNotAuthenticated
				&& !reloggingIn && !"urn:vim25/Logout".equals(soapAction)) {
			// Build 95 (issue #17): with one keepalive per cycle, a session
			// that lapses mid-cycle shows up here. Log in again and retry
			// this call once; a failed login leaves the call failed (null,
			// so the read is UNREADABLE), never a default. Review W3: after
			// one failed login this cycle, no call tries again.
			if (closed) {
				lastFault = CLOSED;   // review W4: fail, do not re-login
				return null;
			}
			String failed = loginFailure;
			if (failed != null) {
				lastFault = "session not authenticated; not logging in again "
						+ "this cycle (login failed: " + failed + ")";
				return null;
			}
			reloggingIn = true;
			try {
				logWarn("vSphere SOAP: session not authenticated on "
						+ soapAction + "; logging in again and retrying once");
				clearSession();
				connect();
			} catch (Exception e) {
				lastFault = "re-login failed: " + e.getClass().getSimpleName()
						+ ": " + e.getMessage();
				return null;
			} finally {
				reloggingIn = false;
			}
			d = postOnce(soapBody, soapAction, authenticated);
		}
		return d;
	}

	/** Build 95: drop the session state without a Logout call. */
	private void clearSession() {
		sessionCookie = null;
		propertyCollector = null;
		EsxcliSoapClient e = esxcli;
		if (e != null) retiredEsxcli = e;   // review N3: marks carried over
		esxcli = null;
	}

	private static final java.util.regex.Pattern INVALID_PROPERTY_NAME =
			java.util.regex.Pattern.compile(
					"InvalidProperty.*?<name>([^<]*)</name>",
					java.util.regex.Pattern.DOTALL);

	/**
	 * Build 95: the property path an InvalidProperty fault names, or null.
	 * SDK-free, tested directly.
	 */
	static String invalidPropertyName(String body) {
		if (body == null || body.isEmpty()) return null;
		java.util.regex.Matcher m = INVALID_PROPERTY_NAME.matcher(body);
		return m.find() ? m.group(1).trim() : null;
	}

	/** Build 95: whether a fault body is vim25 NotAuthenticated. */
	static boolean isNotAuthenticated(String body) {
		return body != null && body.contains("NotAuthenticated");
	}

	/**
	 * One POST. Build 95 (issue #17): the connection is not disconnected
	 * after a successful call, so the JDK keeps it alive and the next call
	 * reuses it instead of a new TCP and TLS handshake (the response stream
	 * is read to the end and closed, which is what allows reuse). A call
	 * that fails in transport disconnects, so a broken connection is never
	 * reused; the JDK also retries a POST once on a kept-alive connection
	 * the server has closed.
	 */
	private Document postOnce(String soapBody, String soapAction,
			boolean authenticated) throws Exception {
		return postOnce(soapBody, soapAction, authenticated,
				CONNECT_TIMEOUT_MS, readTimeoutMs);
	}

	private Document postOnce(String soapBody, String soapAction,
			boolean authenticated, int connectTimeoutMs, int readTimeoutMs)
			throws Exception {
		String envelope =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<soapenv:Envelope "
				+ "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
				+ "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
				+ "<soapenv:Body>" + soapBody + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

		CycleMetrics m = metrics;
		if (m != null) m.soapCall();
		lastNotAuthenticated = false;
		lastInvalidProperty = null;
		lastTooLarge = false;

		URL url = new URL(vcenterUrl);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		if (conn instanceof HttpsURLConnection) {
			// The factory checks the chain and the name; the strict
			// verifier makes the JDK check the name again (build 93, B1).
			VCenterCertificates.secure((HttpsURLConnection) conn, sslFactory);
		}
		int code;
		String faultBody = null;
		Document doc = null;
		CappedInputStream body = null;
		try {
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);
			conn.setConnectTimeout(connectTimeoutMs);
			conn.setReadTimeout(readTimeoutMs);
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

			code = conn.getResponseCode();
			// Capture the session cookie from any response (the login
			// response carries it). Take name=value up to the first ';'.
			captureCookie(conn);

			if (code >= 200 && code < 300) {
				// Build 95 (issue #24): parsed straight from the capped
				// stream, one copy (the DOM), not bytes, then a String,
				// then bytes again.
				InputStream is = conn.getInputStream();
				if (is != null) {
					body = new CappedInputStream(is, maxResponseBytes);
					// Review N2: an I/O failure mid-body (or the cap) is
					// thrown to the catch below, which drops the connection
					// and keeps the transport error.
					doc = parseXmlOrThrow(body);
					// Closing after the parse returns the connection for
					// reuse (the JDK drains what is left).
					try { body.close(); } catch (Exception ignored) {}
				}
			} else {
				faultBody = readCapped(conn.getErrorStream(),
						MAX_FAULT_BODY_BYTES);
			}
		} catch (java.io.IOException e) {
			conn.disconnect();   // never reuse a connection that failed
			if (body != null && body.exceeded()) {
				return tooLarge(soapAction);
			}
			throw e;
		}
		if (body != null && body.exceeded()) {
			conn.disconnect();   // the rest of the response was not read
			return tooLarge(soapAction);
		}
		if (code < 200 || code >= 300) {
			// Build 74: remember why (diagnostics only; the fault string is
			// vCenter's message, never contains credentials).
			lastFault = "HTTP " + code + faultString(faultBody);
			lastNotAuthenticated = isNotAuthenticated(faultBody);
			lastInvalidProperty = invalidPropertyName(faultBody);
			return null;   // SOAP fault (500) / auth failure -> null upstream
		}
		return doc;   // null when the body was empty or not XML
	}

	/** Build 95 (issue #24): a response over the cap fails the call. */
	private Document tooLarge(String soapAction) {
		lastTooLarge = true;
		lastFault = soapAction + " response over " + maxResponseBytes
				+ " bytes, not read";
		logWarn("vSphere SOAP: " + lastFault + " (MAX_SOAP_RESPONSE_BYTES); "
				+ "the call failed and what it was reading is UNREADABLE");
		return null;
	}

	/**
	 * Build 95 (issue #24): an InputStream that stops after {@code max}
	 * bytes by throwing {@link ResponseTooLarge}, remembering that it did.
	 * SDK-free; also used by the esxcli client.
	 */
	static final class CappedInputStream extends java.io.FilterInputStream {
		private final long max;
		private long read;
		private boolean exceeded;

		CappedInputStream(InputStream in, long max) {
			super(in);
			this.max = max;
		}

		boolean exceeded() {
			return exceeded;
		}

		private void count(long n) throws ResponseTooLarge {
			if (n <= 0) return;
			read += n;
			if (read > max) {
				exceeded = true;
				throw new ResponseTooLarge(max);
			}
		}

		@Override
		public int read() throws java.io.IOException {
			if (exceeded) throw new ResponseTooLarge(max);
			int b = super.read();
			if (b >= 0) count(1);
			return b;
		}

		@Override
		public int read(byte[] b, int off, int len) throws java.io.IOException {
			if (exceeded) throw new ResponseTooLarge(max);
			int n = super.read(b, off, len);
			count(n);
			return n;
		}

		@Override
		public long skip(long n) throws java.io.IOException {
			long k = super.skip(n);
			count(k);
			return k;
		}
	}

	/** Build 95: thrown by {@link CappedInputStream} past its cap. */
	static final class ResponseTooLarge extends java.io.IOException {
		private static final long serialVersionUID = 1L;

		ResponseTooLarge(long max) {
			super("response over " + max + " bytes");
		}
	}

	/** Build 95: at most {@code max} bytes of a (fault) body, decoded. */
	static String readCapped(InputStream is, int max) {
		if (is == null) return null;
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] buf = new byte[8192];
			int n;
			while (bos.size() < max
					&& (n = is.read(buf, 0, Math.min(buf.length,
							max - bos.size()))) >= 0) {
				bos.write(buf, 0, n);
			}
			return new String(bos.toByteArray(), StandardCharsets.UTF_8);
		} catch (java.io.IOException e) {
			return null;
		} finally {
			try { is.close(); } catch (Exception ignored) {}
		}
	}

	private static final java.util.regex.Pattern FAULTSTRING =
			java.util.regex.Pattern.compile(
					"<faultstring>(.*?)</faultstring>",
					java.util.regex.Pattern.DOTALL);

	/** " <faultstring>" from a SOAP fault body, or "". */
	static String faultString(String body) {
		if (body == null || body.isEmpty()) return "";
		java.util.regex.Matcher m = FAULTSTRING.matcher(body);
		if (!m.find()) return "";
		String f = m.group(1).trim();
		if (f.length() > 200) f = f.substring(0, 200) + "...";
		return " " + f;
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
					// Build 95 review W3: during connect() the cookie waits
					// for Login to succeed before it becomes the session.
					if (connecting) {
						this.pendingCookie = pair;
					} else {
						this.sessionCookie = pair;
					}
					return;
				}
			}
		} catch (Exception ignored) {
			// Cookie capture failure surfaces as a failed authenticated call
			// downstream (null -> unreadable), never a false pass.
		}
	}

	/**
	 * Build 95 (issue #24): parse straight from a stream (a
	 * {@link CappedInputStream} on the response), so the response is held
	 * once, as the DOM. Null when it is empty, not XML, or over the cap.
	 */
	static Document parseXml(InputStream in) {
		try {
			return newBuilder().parse(in);
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Build 95 review N2: as {@link #parseXml}, but an I/O failure while
	 * the body is read (a read timeout or a connection dropped mid-body,
	 * or the cap) is thrown, not folded into null, so the caller drops the
	 * connection and the read's reason names the transport error, as it
	 * did before the streaming parse. Null only when the body is empty or
	 * not XML.
	 */
	static Document parseXmlOrThrow(InputStream in) throws java.io.IOException {
		DocumentBuilder b;
		try {
			b = newBuilder();
		} catch (Exception e) {
			return null;
		}
		try {
			return b.parse(in);
		} catch (java.io.IOException e) {
			throw e;
		} catch (Exception e) {
			return null;
		}
	}

	private static DocumentBuilder newBuilder() throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		// Non-namespace-aware: read by LOCAL name throughout; harden
		// against external entities.
		dbf.setNamespaceAware(false);
		trySetFeature(dbf,
				"http://apache.org/xml/features/disallow-doctype-decl", true);
		trySetFeature(dbf,
				"http://xml.org/sax/features/external-general-entities", false);
		trySetFeature(dbf,
				"http://xml.org/sax/features/external-parameter-entities", false);
		return dbf.newDocumentBuilder();
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
		// Build 58: host MOID from the bulk enumeration (null when the VM
		// has no host); hostRead=false means the bulk read was unavailable
		// and the caller must read runtime.host itself.
		public final String hostMoid;
		public final boolean hostRead;
		// Build 88: config.guestId from the bulk enumeration; null when not
		// read (fallback walk) or unset on the VM.
		public final String guestId;

		public VmInfo(MoRef moRef, String name, String moid) {
			this(moRef, name, moid, null, false, null);
		}

		public VmInfo(MoRef moRef, String name, String moid, String hostMoid,
				boolean hostRead, String guestId) {
			this.moRef = moRef;
			this.name = name;
			this.moid = moid;
			this.hostMoid = hostMoid;
			this.hostRead = hostRead;
			this.guestId = guestId;
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
