package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.VcfCfAdapter;
import com.vcfcf.adapter.http.ManagedHttpClient;
import com.vcfcf.adapter.json.SimpleJson;
import com.vcfcf.adapter.spi.VcfCfCollector;
import com.vcfcf.adapter.spi.VcfCfDiscoverer;
import com.vcfcf.adapter.spi.VcfCfTester;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import com.integrien.alive.common.adapter3.AdapterBase;
import com.integrien.alive.common.adapter3.MetricData;
import com.integrien.alive.common.adapter3.MetricKey;
import com.integrien.alive.common.adapter3.ResourceKey;
import com.integrien.alive.common.adapter3.ResourceStatus;
import com.integrien.alive.common.adapter3.config.ResourceConfig;
import com.integrien.alive.common.adapter3.config.ResourceIdentifierConfig;
import com.integrien.alive.common.util.CommonConstants.ResourceStatusEnum;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Compliance adapter — framework v2 (build 43).
 *
 * <p><b>v1 → v2 SPI port.</b> Re-homed from aria-ops-core
 * ({@code UnlicensedAdapter} + {@code com.vmware.tvs.*}) onto
 * {@link VcfCfAdapter} (which extends {@code AdapterBase} directly) and the
 * {@code com.vcfcf.adapter.spi} roles: {@link VcfCfTester},
 * {@link VcfCfDiscoverer}, {@link VcfCfCollector}. No
 * {@code com.vmware.tvs.*}, no {@code com.vmware.vim25.*}, no JAX-WS.
 *
 * <p><b>vSphere transport.</b> {@link VSphereClient} is now raw SOAP over
 * {@link java.net.HttpURLConnection} + JDK DOM (the JAX-WS path failed every
 * cycle on 9.1 — see {@code prod_91_jaxws_provider_failure.md}).
 *
 * <p><b>Stitching transport.</b> Uses the framework {@link SuiteApiStitcher}
 * with ambient maintenance credentials (proven on devel 9.0.2 and prod 9.1 —
 * {@code suiteapi_ambient_auth_devel_2026_06_09.md}). No Suite API credential
 * fields on the adapter config in this build (ambient-only on the all-in-one
 * target; explicit fields are a documented future variant).
 *
 * <p><b>Correctness invariants preserved from v1 (golden comparison gate).</b>
 * Same property/stat keys, same value semantics, same MOID stitching identity
 * rules, and the cardinal "unreadable is NOT compliant" rule: a value the
 * adapter failed to read is never folded into a per-resource or fleet score —
 * it is surfaced as an explicit unreadable signal, and sentinel (zero-divisor)
 * scores are gated out of every average by the {@code totalCount > 0} guard.
 */
public final class ComplianceAdapter extends VcfCfAdapter<ComplianceConfig> {

	private static final String ADAPTER_KIND = "vcfcf_compliance";

	private volatile VCenterApiClient vcApi;
	private volatile VSphereClient vsphere;
	private volatile BenchmarkLoader benchmarkLoader;
	private volatile SuiteApiStitcher suiteStitcher;
	private volatile ComplianceStitcher stitcher;

	// Fix #2 (Task #17): track the profile active in the PREVIOUS cycle so a
	// profile switch can be detected and the stale-key warning emitted.
	// In-memory only: a restart resets to null and we skip cleanup on the
	// first post-restart cycle.
	private volatile String previousProfileName;

	// Task #16 — last-known per-host compliance score, keyed by the stable host
	// MOID (hostInfo.moid), NOT the display name (a host can be renamed). Scott's
	// decision: the world avg_host_score should use a host's LAST-KNOWN score
	// when the host is channel-unreadable THIS cycle, so an unreadable host does
	// not silently shrink the denominator and flatter the average. A host with NO
	// last-known score (never successfully read since this collector process
	// started) stays excluded entirely.
	//
	// IN-MEMORY ONLY — survives across collect cycles within one collector
	// process but does NOT survive a collector restart. COLLECTOR-RESTART CAVEAT:
	// after a restart the cache is empty, so the first cycle(s) average only the
	// hosts readable that cycle (readable-only), exactly as build 48 did, until
	// every host has been read at least once and the cache re-warms. This is the
	// honest degraded behavior — we never invent a score we have never observed.
	// Concurrent-collect safe: collect() runs once per cycle for the single
	// ComplianceWorld resource, but use a ConcurrentHashMap defensively.
	private final java.util.concurrent.ConcurrentHashMap<String, Double>
			lastKnownHostScore = new java.util.concurrent.ConcurrentHashMap<>();

	public ComplianceAdapter() {
		super(ADAPTER_KIND);
	}

	public ComplianceAdapter(String adapterDir, Integer adapterInstanceId) {
		super(ADAPTER_KIND, adapterDir, adapterInstanceId);
	}

	@Override
	public boolean isDynamicMetricsAllowed() {
		return true;
	}

	// -----------------------------------------------------------------------
	// onDescribe — provided by the framework base (VcfCfAdapter). The default
	// resolves the kind from the constructor-stored adapterKindKey
	// (super(ADAPTER_KIND)) — NOT getAdapterKind(), which is null during the
	// controller's bare describe phase at install time (build 44 root cause:
	// controller-side bare instantiation, no platform injection). The
	// constructor-stored key makes getAdapterDescribeFile(ADAPTER_KIND,
	// "describe.xml") resolve correctly in both controller and collector
	// contexts. See lessons/controller-describe-bare-instantiation.md.
	// -----------------------------------------------------------------------

	// -----------------------------------------------------------------------
	// configureAdapter (replaces v1 configure)
	// -----------------------------------------------------------------------

	@Override
	protected void configureAdapter(ResourceStatus status,
			ResourceConfig resourceConfig) {
		String vcenterHost = getIdentifier(resourceConfig, "vcenter_host");
		String profile = getIdentifier(resourceConfig, "benchmark_profile");
		String customPath = getIdentifier(resourceConfig, "custom_profile_path");
		String allowInsecure = getIdentifier(resourceConfig, "allowInsecure");
		String username = getCredentialField(resourceConfig, "username");
		String password = getCredentialField(resourceConfig, "password");

		this.config = new ComplianceConfig(
				vcenterHost, username, password,
				profile, customPath, allowInsecure);

		this.vcApi = new VCenterApiClient(
				config.baseUrl(), config.username, config.password,
				config.allowInsecure);

		this.vsphere = new VSphereClient(
				config.vcenterHost, config.username, config.password,
				sslSocketFactoryFor(config),
				componentLogger(VSphereClient.class),
				config.allowInsecure);

		this.benchmarkLoader = new BenchmarkLoader();

		// Ambient Suite API stitching — reads maintenanceuser.properties,
		// decrypts via the platform SDK Crypt, targets https://localhost/
		// suite-api as maintenanceAdmin. If the credential file is absent
		// (e.g. a remote collector), create() throws; stitching is then
		// disabled for the cycle and the collect path logs the gap rather
		// than aborting.
		try {
			this.suiteStitcher = SuiteApiStitcher.create(
					this, componentLogger(SuiteApiStitcher.class));
			this.stitcher = new ComplianceStitcher(
					this.suiteStitcher,
					componentLogger(ComplianceStitcher.class));
		} catch (RuntimeException e) {
			this.suiteStitcher = null;
			this.stitcher = null;
			logWarn("Ambient Suite API stitcher unavailable — compliance data "
					+ "will not be pushed onto VMWARE resources this instance: "
					+ e.getMessage());
		}

		logInfo("ComplianceAdapter configured: vcenter=" + config.vcenterHost
				+ " profile=" + config.benchmarkProfile
				+ " allowInsecure=" + config.allowInsecure
				+ " stitcher=" + (stitcher != null));
	}

	/**
	 * Task #12 — pick the SSL socket factory for the raw-SOAP
	 * {@link VSphereClient} connection in line with the framework SSL
	 * convention (migration guide §16 / {@code HttpClientBuilder}):
	 *
	 * <ul>
	 *   <li><b>platform trust by default</b> — {@link #getPlatformSslContext()}
	 *       (the same SSLContext {@code HttpClientBuilder.platformSsl(this)}
	 *       installs) so the vCenter certificate is validated against the VCF
	 *       Ops platform trust store. This is the secure default.</li>
	 *   <li><b>{@code allowInsecure} per-adapter-config opt-out</b> — only when
	 *       the instance's {@code allowInsecure} identifier is set does the
	 *       client fall back to {@link #insecureSslContext()} (trust-all),
	 *       exactly as {@code HttpClientBuilder.allowInsecure(true)} does. This
	 *       is the documented lab opt-out, surfaced in the log line above.</li>
	 * </ul>
	 *
	 * <p>Returns the {@link javax.net.ssl.SSLSocketFactory} of the chosen
	 * context. If the platform context cannot be obtained (e.g. a standalone
	 * collector with no platform trust store) the JDK default factory is used
	 * — never a silent fall-through to trust-all. The chosen factory is handed
	 * into {@link VSphereClient}, which threads it through to its per-cycle
	 * {@link EsxcliSoapClient} so the esxcli slice honours the same trust
	 * decision.
	 */
	private javax.net.ssl.SSLSocketFactory sslSocketFactoryFor(
			ComplianceConfig cfg) {
		if (cfg.allowInsecure) {
			logWarn("allowInsecure=true — vCenter SOAP TLS certificate "
					+ "validation is DISABLED for this instance (lab opt-out). "
					+ "Set allowInsecure=false to validate against the platform "
					+ "trust store.");
			return insecureSslContext().getSocketFactory();
		}
		javax.net.ssl.SSLContext platform = getPlatformSslContext();
		if (platform != null) {
			return platform.getSocketFactory();
		}
		logWarn("Platform SSL context unavailable and allowInsecure=false — "
				+ "using the JDK default trust store for the vCenter SOAP "
				+ "connection.");
		return (javax.net.ssl.SSLSocketFactory)
				javax.net.ssl.SSLSocketFactory.getDefault();
	}

	// -----------------------------------------------------------------------
	// getTester
	// -----------------------------------------------------------------------

	@Override
	protected VcfCfTester<ComplianceConfig> getTester() {
		// Build 46 onTest NPE fix: the controller invokes Test-connection on a
		// FRESH instance — onConfigure (configureAdapter) has NOT run, so the
		// instance fields (this.vcApi, this.config) are still null. The base's
		// onTest also passes the still-null this.config as `cfg`. So the tester
		// must be fully self-contained: derive everything it needs from the
		// ResourceConfig the platform carries on the TestParam, never from
		// instance state. (Pre-build-46 this lambda dereferenced this.vcApi →
		// "Cannot invoke VCenterApiClient.login() because this.vcApi is null".)
		return (cfg, http, param) -> {
			ResourceConfig rc = testResourceConfig(param);
			if (rc == null) {
				throw new Exception("Test-connection: no adapter-instance "
						+ "ResourceConfig available on TestParam — cannot read "
						+ "vCenter host/credentials to test");
			}

			String vcenterHost = getIdentifier(rc, "vcenter_host");
			String allowInsecure = getIdentifier(rc, "allowInsecure");
			String username = getCredentialField(rc, "username");
			String password = getCredentialField(rc, "password");

			ComplianceConfig testCfg = new ComplianceConfig(
					vcenterHost, username, password,
					/*profile*/ null, /*customPath*/ null, allowInsecure);

			VCenterApiClient testApi = new VCenterApiClient(
					testCfg.baseUrl(), testCfg.username, testCfg.password,
					testCfg.allowInsecure);
			testApi.login();
			try {
				SimpleJson hosts = testApi.listHosts();
				int count = 0;
				if (!hosts.isNull() && hosts.isList()) {
					count = hosts.asList().size();
				}
				logInfo("Test OK: connected to " + testCfg.vcenterHost
						+ ", " + count + " host(s) visible");
			} finally {
				testApi.logout();
			}
		};
	}

	/**
	 * Resolve the adapter-instance {@link ResourceConfig} from a
	 * {@code TestParam} so the tester can read vCenter host + credentials
	 * without relying on instance state that the controller has not yet
	 * populated (Test-connection runs on a bare instance). Returns null if the
	 * platform did not attach an adapter config (defensive — should not happen
	 * in a real Test-connection call).
	 */
	private static ResourceConfig testResourceConfig(
			com.integrien.alive.common.adapter3.TestParam param) {
		if (param == null) {
			return null;
		}
		com.integrien.alive.common.adapter3.config.AdapterConfig adConf =
				param.getAdapterConfig();
		if (adConf == null) {
			return null;
		}
		return adConf.getAdapterInstResource();
	}

	// -----------------------------------------------------------------------
	// Resource discovery — the single synthetic ComplianceWorld resource
	//
	// Task #19 — collect-path discovery (framework v2 §22). VCF Ops 9.0.2 never
	// invokes onDiscover() for adapter3-path collectors, so a FRESH instance
	// would heartbeat GREEN yet sit at zero resources forever. discoverOnCollect()
	// returning true makes the framework call enumerateResources(sink) at the top
	// of every collect cycle (registering via registerNewResource), so the
	// ComplianceWorld appears from the first cycle without depending on
	// onDiscover() ever firing. getDiscoverer() is deleted: the framework default
	// onDiscover() path also calls enumerateResources(dr::addResource), so both
	// paths share this one enumeration body.
	//
	// Resource-key STABILITY (required for idempotent re-registration): the key
	// emitted here — kind "ComplianceWorld", adapterKind ADAPTER_KIND, single
	// identifier ("world_id" = "compliance_world", isUnique=true) — is byte-for-
	// byte the same ResourceConfig the deleted getDiscoverer() emitted (it called
	// the SAME worldResourceConfig() helper). registerNewResource is idempotent on
	// the identifying-identifier set, so enumerating every cycle re-registers the
	// already-known world rather than duplicating it. The key is a constant (no
	// host/inventory input), so it cannot drift between cycles.
	// -----------------------------------------------------------------------

	@Override
	protected boolean discoverOnCollect() {
		return true;
	}

	@Override
	protected void enumerateResources(
			com.vcfcf.adapter.spi.ResourceSink sink)
			throws InterruptedException, Exception {
		logInfo("ComplianceAdapter enumerate: registering ComplianceWorld");
		sink.accept(worldResourceConfig());
	}

	private ResourceConfig worldResourceConfig() {
		ResourceKey key = new ResourceKey(
				"Compliance World", "ComplianceWorld", ADAPTER_KIND);
		key.addIdentifier(new ResourceIdentifierConfig(
				"world_id", "compliance_world", true));
		return new ResourceConfig(key);
	}

	// -----------------------------------------------------------------------
	// getCollector
	// -----------------------------------------------------------------------

	@Override
	protected VcfCfCollector<ComplianceConfig> getCollector() {
		return new VcfCfCollector<ComplianceConfig>() {
			@Override
			public void collect(ComplianceConfig cfg, ManagedHttpClient http,
					ResourceConfig rc, List<MetricData> out, AdapterBase adapter)
					throws InterruptedException, Exception {
				collectWorld(rc, out);
			}

			@Override
			public ResourceStatusEnum mapCollectException(Exception e) {
				// A connect failure to vCenter is DOWN; anything else ERROR.
				if (e instanceof java.net.ConnectException) {
					return ResourceStatusEnum.RESOURCE_STATUS_DOWN;
				}
				return ResourceStatusEnum.RESOURCE_STATUS_ERROR;
			}
		};
	}

	/**
	 * The per-cycle collection body. Runs once for the {@code ComplianceWorld}
	 * resource. Walks vSphere inventory, evaluates the active profile, pushes
	 * per-resource compliance onto matched VMWARE resources via the stitcher,
	 * and emits the world-level fleet rollups onto {@code out}.
	 */
	private void collectWorld(ResourceConfig worldRc, List<MetricData> out)
			throws Exception {
		vsphere.ensureConnected();

		Path confDir = getAdapterDescribeFile(ADAPTER_KIND, "describe.xml")
				.getParent();   // <adaptersHome>/<kind>/conf
		BenchmarkProfile profile = benchmarkLoader.load(
				config.benchmarkProfile,
				config.customProfilePath,
				confDir.toString());
		if (!profile.name.equals(config.benchmarkProfile)) {
			logWarn("Profile load divergence: requested='"
					+ config.benchmarkProfile + "' resolved='"
					+ profile.name + "' — metric tree and profile_name will "
					+ "use the resolved name");
		}

		logInfo("stitcher=" + (stitcher != null));
		if (stitcher != null) {
			loadStitcherResources();
		}

		detectProfileChange(profile.name, confDir.toString());

		HostStats hostStats = collectHosts(profile);
		VmStats vmStats = collectVms(profile);
		VCenterStats vcStats = collectVCenter(profile);
		DvsStats dvsStats = collectDvs(profile);
		DvpgStats dvpgStats = collectDvpg(profile);
		ClusterStats clusterStats = collectClusters(profile);

		long ts = System.currentTimeMillis();

		pushWorldMetric(out, "Summary|total_hosts",
				(double) hostStats.total, ts);
		// No-sentinel contract: only publish averages when at least one host
		// produced real signal.
		if (hostStats.scored > 0) {
			pushWorldMetric(out, "Summary|avg_host_score",
					hostStats.scoreSum / hostStats.scored, ts);
			pushWorldMetric(out, "Summary|hosts_below_threshold",
					(double) hostStats.belowThreshold, ts);
		} else {
			logWarn("No hosts produced real compliance signal "
					+ "(all totalCount==0); skipping Summary|avg_host_score "
					+ "and Summary|hosts_below_threshold so the scoreboard "
					+ "reads 'no data' rather than a sentinel value");
		}
		// Build 50 (review W1): first-class world-level staleness visibility.
		// Count of hosts whose avg_host_score contribution came from the
		// last-known cache this cycle (channel-unreadable but folded their
		// last-known score). 0 when every averaged host was read live. Pushed
		// EVERY cycle so an operator can see "N of M averaged hosts are stale"
		// rather than inferring it from an indirect control count.
		pushWorldMetric(out, "Summary|hosts_scored_stale",
				(double) hostStats.staleScored, ts);

		pushWorldMetric(out, "Summary|total_vms", (double) vmStats.total, ts);
		if (vmStats.scored > 0) {
			pushWorldMetric(out, "Summary|avg_vm_score",
					vmStats.scoreSum / vmStats.scored, ts);
			pushWorldMetric(out, "Summary|vms_below_threshold",
					(double) vmStats.belowThreshold, ts);
		}

		pushWorldMetric(out, "Summary|total_vcenters",
				(double) vcStats.total, ts);
		if (vcStats.scored > 0) {
			pushWorldMetric(out, "Summary|avg_vcenter_score",
					vcStats.scoreSum / vcStats.scored, ts);
			pushWorldMetric(out, "Summary|vcenters_below_threshold",
					(double) vcStats.belowThreshold, ts);
		}

		int totalUnreadable = hostStats.unreadable
				+ vmStats.unreadable
				+ vcStats.unreadable
				+ dvsStats.unreadable
				+ dvpgStats.unreadable
				+ clusterStats.unreadable;
		pushWorldMetric(out, "Summary|total_unreadable_controls",
				(double) totalUnreadable, ts);
		if (totalUnreadable > 0) {
			logWarn("Profile '" + profile.name + "' declares " + totalUnreadable
					+ " vim_property control instance(s) this adapter could "
					+ "not read this cycle (declared-but-unreadable). These are "
					+ "excluded from every compliance score. This is a coverage "
					+ "signal, not non-compliance.");
		}

		pushWorldProperty(out, "Summary|profile_name", profile.name);
		pushWorldProperty(out, "Summary|last_scan_timestamp",
				Instant.now().toString());

		logInfo("ComplianceAdapter collection complete: "
				+ hostStats.total + " hosts, "
				+ vmStats.total + " VMs, "
				+ (vcStats.matched ? "1" : "0") + " vCenter, "
				+ dvsStats.total + " DVS, "
				+ dvpgStats.total + " DVPG, "
				+ clusterStats.total + " ClusterComputeResource");

		previousProfileName = profile.name;
	}

	/** Append a numeric world metric (non-property MetricKey). */
	private static void pushWorldMetric(List<MetricData> out,
			String key, double value, long ts) {
		out.add(new MetricData(new MetricKey(key), ts, value));
	}

	/** Append a string world property (isProperty=true MetricKey). */
	private static void pushWorldProperty(List<MetricData> out,
			String key, String value) {
		out.add(new MetricData(new MetricKey(true, key),
				System.currentTimeMillis(), value));
	}

	// ----- Stitcher resource loading --------------------------------------

	private void loadStitcherResources() {
		// Pin the owning vCenter Instance UUID BEFORE loading foreign resources
		// so the loaders scope every vim25-backed kind by VMEntityVCID — a bare
		// MOID (host-12, vm-42) is not unique across vCenters and would
		// otherwise cross-stitch in a multi-vCenter VCF Ops (the MOID trap).
		// A read failure degrades to the unscoped matcher (single-vCenter safe).
		try {
			stitcher.setOwningVcUuid(vsphere.getVCenterInstanceUuid());
		} catch (Exception e) {
			stitcher.setOwningVcUuid(null);
			logWarn("Stitcher owning-vCenter UUID unavailable — foreign "
					+ "resource matching degrades to unscoped (single-vCenter "
					+ "safe): " + e.getMessage());
		}
		safeLoad(() -> stitcher.loadHostResources(),
				() -> "Stitcher loaded: " + stitcher.size() + " hosts",
				"loadHostResources");
		safeLoad(() -> stitcher.loadVmResources(),
				() -> "Stitcher loaded: "
						+ stitcher.countOfKind("VirtualMachine") + " VMs",
				"loadVmResources");
		safeLoad(() -> stitcher.loadVCenterAdapterInstance(),
				() -> "Stitcher loaded: "
						+ stitcher.countOfKind("VMwareAdapter Instance")
						+ " VMwareAdapter Instance(s)",
				"loadVCenterAdapterInstance");
		safeLoad(() -> stitcher.loadDvsResources(),
				() -> "Stitcher loaded: "
						+ stitcher.countOfKind(
								"VmwareDistributedVirtualSwitch") + " DVS",
				"loadDvsResources");
		safeLoad(() -> stitcher.loadDvpgResources(),
				() -> "Stitcher loaded: "
						+ stitcher.countOfKind("DistributedVirtualPortgroup")
						+ " DVPG",
				"loadDvpgResources");
		safeLoad(() -> stitcher.loadClusterResources(),
				() -> "Stitcher loaded: "
						+ stitcher.countOfKind("ClusterComputeResource")
						+ " ClusterComputeResource",
				"loadClusterResources");
	}

	private interface Loader { void run() throws Exception; }
	private interface Msg { String get(); }

	private void safeLoad(Loader loader, Msg ok, String label) {
		try {
			loader.run();
			logInfo(ok.get());
		} catch (Exception e) {
			logWarn("Stitcher " + label + " failed: " + e.getMessage());
		}
	}

	// ----- Profile-change detection (Fix #2) ------------------------------

	private void detectProfileChange(String currentProfileName,
			String confDir) {
		if (previousProfileName == null) {
			return;
		}
		if (previousProfileName.equals(currentProfileName)) {
			return;
		}

		List<String> oldControlKeys =
				enumerateOldProfileControlKeys(previousProfileName, confDir);

		int stitchedResources = stitcher == null ? 0
				: stitcher.countOfKind("HostSystem")
				+ stitcher.countOfKind("VirtualMachine")
				+ stitcher.countOfKind("VMwareAdapter Instance")
				+ stitcher.countOfKind("VmwareDistributedVirtualSwitch")
				+ stitcher.countOfKind("DistributedVirtualPortgroup");

		logWarn("Profile change detected: previous='" + previousProfileName
				+ "' current='" + currentProfileName + "'. "
				+ oldControlKeys.size() + " per-control property key(s) under "
				+ "namespace 'VCF-CF Compliance|" + previousProfileName
				+ "|*' will linger on each of " + stitchedResources
				+ " stitched resource(s) until VCF Ops retention ages them "
				+ "out. TOOLSET GAP: the public Suite API PropertyContent "
				+ "schema has no per-property state field, so this adapter "
				+ "cannot signal state=NotExisting on the old keys.");
	}

	private List<String> enumerateOldProfileControlKeys(
			String oldProfileName, String confDir) {
		java.util.List<String> keys = new java.util.ArrayList<>();
		if (oldProfileName == null || oldProfileName.isEmpty()) {
			return keys;
		}
		if ("Custom".equalsIgnoreCase(oldProfileName)) {
			logInfo("Skipping old-profile key enumeration: previous profile "
					+ "was 'Custom' and the old custom CSV path is not retained "
					+ "across config changes");
			return keys;
		}
		try {
			BenchmarkLoader tmpLoader = new BenchmarkLoader();
			BenchmarkProfile oldProfile = tmpLoader.load(oldProfileName,
					null, confDir);
			String prefix = "VCF-CF Compliance|" + oldProfile.name + "|";
			for (BenchmarkProfile.Control c : oldProfile.controls) {
				String ctrlPrefix = prefix + c.controlId;
				keys.add(ctrlPrefix + "|Actual");
				keys.add(ctrlPrefix + "|Expected");
				keys.add(ctrlPrefix + "|Description");
				keys.add(ctrlPrefix + "|Compliant");
			}
		} catch (RuntimeException e) {
			logWarn("Could not load old profile '" + oldProfileName
					+ "' to enumerate stale keys: " + e.getMessage());
		}
		return keys;
	}

	// ----- Per-kind collectors --------------------------------------------

	private HostStats collectHosts(BenchmarkProfile profile) throws Exception {
		HostStats stats = new HostStats();
		java.util.List<VSphereClient.HostInfo> hosts = vsphere.getHosts();
		if (hosts.isEmpty()) {
			logWarn("No hosts returned from vCenter SOAP");
			return stats;
		}
		logInfo("vSphere SOAP: " + hosts.size() + " hosts");

		java.util.List<BenchmarkProfile.Control> hostControls =
				profile.hostControls();

		for (VSphereClient.HostInfo hostInfo : hosts) {
			String hostId = hostInfo.moid;
			String hostName = hostInfo.name;

			// Build 47 — connection-state guard. A host whose vCenter link is
			// down at read time (disconnected / notResponding) cannot be read
			// honestly: its OptionManager MoRef is gone and esxcli/vim reads
			// fail. Scoring the partial subset that still resolves from
			// vCenter's cache yields a flattering, dishonest partial score
			// (the build-46 esx04 regression). Mark EVERY control for the host
			// UNREADABLE for this cycle instead — one loud WARN, no score.
			String connState;
			try {
				connState = vsphere.getHostConnectionState(hostInfo.moRef);
			} catch (Exception e) {
				connState = null;  // unknown -> proceed with normal evaluation
			}
			if (isDisconnectedState(connState)) {
				logWarn("Host " + hostName + ": connectionState='" + connState
						+ "' — host not fully connected to vCenter; ALL "
						+ "compliance controls marked UNREADABLE this cycle "
						+ "(no partial score emitted)");
				ControlEvaluator.ComplianceResult advUnread =
						ControlEvaluator.evaluateControlsUnreadable(
								hostControls, hostName);
				ControlEvaluator.ComplianceResult vimUnread =
						unreadableVimResult(hostControls, hostName);
				ControlEvaluator.ComplianceResult cr =
						mergeResults(advUnread, vimUnread);
				stats.unreadable += cr.unreadableCount;
				stats.total++;  // total attempted; not scored (totalCount==0)
				// Task #16: fold this host's LAST-KNOWN score into the world
				// average so an unreadable host keeps the denominator full
				// (never a flattering shrink). No-op when the host was never
				// read since process start.
				applyLastKnownForUnreadableHost(hostId, hostName, stats);

				logInfo("Host " + hostName + ": UNREADABLE (connectionState='"
						+ connState + "', " + cr.unreadableCount
						+ " controls)");

				if (stitcher != null) {
					ComplianceStitcher.HostEntry he =
							stitcher.matchHost(hostName, hostId);
					if (he != null) {
						pushComplianceViaClient(he.resourceId, cr, profile.name);
					}
				}
				continue;
			}

			java.util.Map<String, String> advSettings = null;
			boolean advUnreadable = false;
			try {
				advSettings = vsphere.getAdvancedSettings(hostInfo.moRef);
			} catch (VSphereClient.AdvancedSettingsUnreadableException e) {
				// Build 48 — null OptionManager MoRef means the host
				// disconnected between the connectionState check above and this
				// read (a flap). A half-connected host must never produce a
				// score: its cached vim/esxcli reads are equally suspect, so
				// scoring them live (the build-46/47 partial-score shape) is
				// dishonest. Treat the WHOLE host as unreadable, identical to
				// the connection-state branch above — fold every control
				// (advanced_setting + vim/esxcli) to UNREADABLE, emit no score,
				// and continue. logWarn routes through the framework base.
				logWarn("Host " + hostName + ": advanced-settings channel "
						+ "UNREADABLE (" + e.getMessage() + ") — host flapped "
						+ "between connection check and read; ALL compliance "
						+ "controls marked UNREADABLE this cycle (no partial "
						+ "score emitted)");
				ControlEvaluator.ComplianceResult advUnread =
						ControlEvaluator.evaluateControlsUnreadable(
								hostControls, hostName);
				ControlEvaluator.ComplianceResult vimUnread =
						unreadableVimResult(hostControls, hostName);
				ControlEvaluator.ComplianceResult cr =
						mergeResults(advUnread, vimUnread);
				stats.unreadable += cr.unreadableCount;
				stats.total++;  // total attempted; not scored (totalCount==0)
				// Task #16: fold this host's last-known score into the world
				// average (see connection-state branch above).
				applyLastKnownForUnreadableHost(hostId, hostName, stats);

				logInfo("Host " + hostName + ": UNREADABLE (adv-settings flap, "
						+ cr.unreadableCount + " controls)");

				if (stitcher != null) {
					ComplianceStitcher.HostEntry he =
							stitcher.matchHost(hostName, hostId);
					if (he != null) {
						pushComplianceViaClient(he.resourceId, cr, profile.name);
					}
				}
				continue;
			} catch (Exception e) {
				// Any other read failure (SOAP fault, transport) is likewise a
				// read failure, not an empty result — treat as unreadable.
				advUnreadable = true;
				logWarn("Host " + hostName + ": failed to read advanced "
						+ "settings (" + e.getMessage() + ") — all "
						+ "advanced_setting controls marked UNREADABLE this "
						+ "cycle (not dropped from the denominator)");
			}

			ControlEvaluator.ComplianceResult advCr = advUnreadable
					? ControlEvaluator.evaluateControlsUnreadable(
							hostControls, hostName)
					: ControlEvaluator.evaluateControls(
							hostControls, advSettings, hostName);
			ControlEvaluator.ComplianceResult vimCr =
					evaluateVimForResource(hostInfo.moRef, hostControls,
							hostName);
			ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vimCr);
			stats.unreadable += cr.unreadableCount;

			stats.total++;
			if (cr.totalCount > 0) {
				stats.scored++;
				stats.scoreSum += cr.score;
				if (cr.score < 95.0) stats.belowThreshold++;
				// Task #16: remember this host's score so a future cycle in
				// which the host is unreadable can still contribute it to the
				// world average. Keyed by stable MOID.
				// Build 50 (review W2): null-guard the write to match the read
				// side (applyLastKnownForUnreadableHost). ConcurrentHashMap.put
				// throws NPE on a null key; the per-host loop has no per-host
				// try/catch and collectHosts propagates, so an unguarded put on
				// a (theoretical) null MOID would abort the whole cycle.
				if (hostId != null) {
					lastKnownHostScore.put(hostId, cr.score);
				}
			}

			logInfo("Host " + hostName + ": score="
					+ String.format("%.1f", cr.score) + "% ("
					+ cr.passCount + " pass, " + cr.failCount + " fail, "
					+ cr.totalCount + " total)");

			if (stitcher != null) {
				ComplianceStitcher.HostEntry he =
						stitcher.matchHost(hostName, hostId);
				if (he != null) {
					pushComplianceViaClient(he.resourceId, cr, profile.name);
				}
			}
		}
		// Build 50 (review N1): evict last-known-score entries for hosts no
		// longer in the current inventory, so the cache cannot grow unboundedly
		// across host churn (a removed host would otherwise linger forever).
		// The current getHosts() set is authoritative for "what exists"; a host
		// absent this cycle because it is merely unreadable is NOT removed —
		// getHosts() still enumerates it (the connectionState/flap branches keep
		// it in `hosts`), so only genuinely de-inventoried hosts are pruned.
		evictAbsentHostScores(hosts);
		return stats;
	}

	/**
	 * Build 50 (review N1) — prune {@link #lastKnownHostScore} keys not present
	 * in the current inventory set. Keeps the map bounded by the live host count
	 * across long-running collectors with host churn. A host that is unreadable
	 * this cycle still appears in {@code hosts} (it is enumerated, just not
	 * scored), so its cached score survives; only hosts removed from vCenter
	 * entirely are evicted.
	 */
	private void evictAbsentHostScores(
			java.util.List<VSphereClient.HostInfo> hosts) {
		java.util.Set<String> live = new java.util.HashSet<>();
		for (VSphereClient.HostInfo h : hosts) {
			if (h.moid != null) live.add(h.moid);
		}
		int before = lastKnownHostScore.size();
		lastKnownHostScore.keySet().retainAll(live);
		int evicted = before - lastKnownHostScore.size();
		if (evicted > 0) {
			logInfo("Evicted " + evicted + " last-known host score(s) for "
					+ "host(s) no longer in inventory (cache now "
					+ lastKnownHostScore.size() + " entries)");
		}
	}

	/**
	 * Task #16 — when a host is channel-unreadable this cycle, fold its
	 * last-known score (if any) into the world {@code avg_host_score} so the
	 * denominator stays full and an unreadable host does not silently flatter
	 * the fleet average. A host with no last-known score (never read since
	 * process start) is left excluded — we never invent a score we have not
	 * observed. Mutates {@code stats.scored} / {@code stats.scoreSum} /
	 * {@code stats.belowThreshold} (the world-rollup inputs) only; it does NOT
	 * touch {@code stats.total} (already incremented by the caller) and does NOT
	 * change the per-host wire push, which stays build-48 (no score stat pushed
	 * for a totalCount==0 host).
	 */
	private void applyLastKnownForUnreadableHost(String hostId, String hostName,
			HostStats stats) {
		Double last = (hostId == null) ? null : lastKnownHostScore.get(hostId);
		if (last == null) {
			logInfo("Host " + hostName + ": unreadable and no last-known score "
					+ "(never read since collector start) — excluded from the "
					+ "world avg_host_score this cycle");
			return;
		}
		stats.scored++;
		stats.staleScored++;
		stats.scoreSum += last;
		if (last < 95.0) stats.belowThreshold++;
		logInfo("Host " + hostName + ": unreadable this cycle — contributing "
				+ "last-known score " + String.format("%.1f", last)
				+ "% to the world avg_host_score (denominator kept full)");
	}

	private VmStats collectVms(BenchmarkProfile profile) {
		VmStats stats = new VmStats();
		java.util.List<VSphereClient.VmInfo> vms;
		try {
			vms = vsphere.getVms();
		} catch (Exception e) {
			logWarn("Failed to enumerate VMs: " + e.getMessage());
			return stats;
		}
		if (vms.isEmpty()) {
			logInfo("No VMs returned from vCenter SOAP");
			return stats;
		}
		logInfo("vSphere SOAP: " + vms.size() + " VMs");

		java.util.List<BenchmarkProfile.Control> vmControls =
				profile.vmControls();

		for (VSphereClient.VmInfo vm : vms) {
			java.util.Map<String, String> extra;
			try {
				extra = vsphere.getVmExtraConfig(vm.moRef);
			} catch (Exception e) {
				logWarn("Failed to read extraConfig for " + vm.name + ": "
						+ e.getMessage());
				extra = new java.util.HashMap<>();
			}

			ControlEvaluator.ComplianceResult advCr =
					ControlEvaluator.evaluateControls(vmControls, extra, vm.name);
			ControlEvaluator.ComplianceResult vimCr =
					evaluateVimForResource(vm.moRef, vmControls, vm.name);
			ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vimCr);
			stats.unreadable += cr.unreadableCount;

			stats.total++;
			if (cr.totalCount > 0) {
				stats.scored++;
				stats.scoreSum += cr.score;
				if (cr.score < 95.0) stats.belowThreshold++;
			}

			if (stitcher != null) {
				ComplianceStitcher.HostEntry he =
						stitcher.matchVm(vm.name, vm.moid);
				if (he != null) {
					pushComplianceViaClient(he.resourceId, cr, profile.name);
				}
			}
		}
		logInfo("VM compliance: " + stats.total + " VMs seen, "
				+ stats.scored + " with real signal");
		return stats;
	}

	private VCenterStats collectVCenter(BenchmarkProfile profile) {
		VCenterStats stats = new VCenterStats();
		java.util.Map<String, String> vcSettings;
		try {
			vcSettings = vsphere.getVCenterAdvancedSettings();
		} catch (Exception e) {
			logWarn("Failed to read vCenter advanced settings: "
					+ e.getMessage());
			return stats;
		}
		logInfo("vCenter advanced settings: " + vcSettings.size() + " entries");

		java.util.List<BenchmarkProfile.Control> vcControls =
				profile.vCenterControls();
		String resourceName = config.vcenterHost;

		ControlEvaluator.ComplianceResult advCr =
				ControlEvaluator.evaluateControls(
						vcControls, vcSettings, resourceName);
		ControlEvaluator.ComplianceResult vamiCr =
				evaluateVamiForVCenter(vcControls, resourceName);
		ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vamiCr);
		logInfo("vCenter " + resourceName + ": score="
				+ String.format("%.1f", cr.score) + "% ("
				+ cr.passCount + " pass, " + cr.failCount + " fail, "
				+ cr.totalCount + " total)");

		stats.total++;
		stats.unreadable += cr.unreadableCount;
		if (cr.totalCount > 0) {
			stats.scored++;
			stats.scoreSum += cr.score;
			if (cr.score < 95.0) stats.belowThreshold++;
		}

		if (stitcher != null) {
			String vcInstanceUuid = null;
			try {
				vcInstanceUuid = vsphere.getVCenterInstanceUuid();
			} catch (Exception e) {
				logWarn("Could not read vCenter instance UUID for stitcher "
						+ "lookup: " + e.getMessage());
			}
			ComplianceStitcher.HostEntry he =
					stitcher.matchVCenterAdapterInstance(
							resourceName, vcInstanceUuid);
			if (he != null) {
				pushComplianceViaClient(he.resourceId, cr, profile.name);
				stats.matched = true;
				logInfo("Pushed vCenter compliance data to " + he.hostName
						+ " (resource=" + he.resourceId + ", VCURL=" + he.moid
						+ ", vcInstanceUuid=" + vcInstanceUuid + ")");
			} else {
				logWarn("Could not resolve VMwareAdapter Instance for "
						+ resourceName + " (vcInstanceUuid=" + vcInstanceUuid
						+ ") — vCenter compliance rollups will NOT appear");
			}
		}
		return stats;
	}

	private DvsStats collectDvs(BenchmarkProfile profile) {
		DvsStats stats = new DvsStats();
		java.util.List<VSphereClient.DvsInfo> switches;
		try {
			switches = vsphere.getDvSwitches();
		} catch (Exception e) {
			logWarn("Failed to enumerate DVS: " + e.getMessage());
			return stats;
		}
		if (switches.isEmpty()) {
			logInfo("No DVS returned from vCenter SOAP");
			return stats;
		}
		logInfo("vSphere SOAP: " + switches.size() + " DVS");

		java.util.List<BenchmarkProfile.Control> dvsControls =
				profile.dvsControls();
		int evaluableCount = countEvaluable(dvsControls, "vim_property");

		for (VSphereClient.DvsInfo dvs : switches) {
			stats.total++;
			if (stitcher == null) continue;
			ComplianceStitcher.HostEntry he =
					stitcher.matchDvs(dvs.name, dvs.moid);
			if (he == null) continue;

			if (evaluableCount == 0) {
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			java.util.Map<String, Object> secPol;
			try {
				secPol = vsphere.readVimProperties(dvs.moRef, dvsControls);
			} catch (Exception e) {
				logWarn("Failed to read vim properties for DVS " + dvs.name
						+ ": " + e.getMessage());
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			ControlEvaluator.ComplianceResult cr =
					ControlEvaluator.evaluateVimProperties(
							dvsControls, secPol, dvs.name,
							VSphereClient.UNREADABLE);
			stats.unreadable += cr.unreadableCount;
			pushOrProfileName(he.resourceId, cr, profile.name);
		}
		return stats;
	}

	private DvpgStats collectDvpg(BenchmarkProfile profile) {
		DvpgStats stats = new DvpgStats();
		java.util.List<VSphereClient.DvpgInfo> pgs;
		try {
			pgs = vsphere.getDvPortgroups();
		} catch (Exception e) {
			logWarn("Failed to enumerate DVPG: " + e.getMessage());
			return stats;
		}
		if (pgs.isEmpty()) {
			logInfo("No DVPG returned from vCenter SOAP");
			return stats;
		}
		logInfo("vSphere SOAP: " + pgs.size() + " DVPG");

		java.util.List<BenchmarkProfile.Control> dvpgControls =
				profile.dvpgControls();
		int evaluableCount = countEvaluable(dvpgControls, "vim_property");

		for (VSphereClient.DvpgInfo pg : pgs) {
			stats.total++;
			if (stitcher == null) continue;
			ComplianceStitcher.HostEntry he =
					stitcher.matchDvpg(pg.name, pg.moid);
			if (he == null) continue;

			if (evaluableCount == 0) {
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			java.util.Map<String, Object> secPol;
			try {
				secPol = vsphere.readVimProperties(pg.moRef, dvpgControls);
			} catch (Exception e) {
				logWarn("Failed to read vim properties for DVPG " + pg.name
						+ ": " + e.getMessage());
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			ControlEvaluator.ComplianceResult cr =
					ControlEvaluator.evaluateVimProperties(
							dvpgControls, secPol, pg.name,
							VSphereClient.UNREADABLE);
			stats.unreadable += cr.unreadableCount;
			pushOrProfileName(he.resourceId, cr, profile.name);
		}
		return stats;
	}

	/**
	 * ClusterComputeResource (vSAN) collector. Walks every cluster, probes
	 * vSAN presence (non-vSAN clusters get profile_name only — vSAN controls
	 * are genuinely N/A, not a coverage gap), reads the small slice of vSAN
	 * config plain vim25 exposes, and evaluates. The bulk of SCG's cluster
	 * controls require the vSAN Management SDK (not on this classpath) and
	 * stay manual_audit — CLASSPATH GAP, documented in the build report.
	 */
	private ClusterStats collectClusters(BenchmarkProfile profile) {
		ClusterStats stats = new ClusterStats();
		java.util.List<VSphereClient.ClusterInfo> clusters;
		try {
			clusters = vsphere.getClusters();
		} catch (Exception e) {
			logWarn("Failed to enumerate ClusterComputeResource: "
					+ e.getMessage());
			return stats;
		}
		if (clusters.isEmpty()) {
			logInfo("No ClusterComputeResource returned from vCenter SOAP");
			return stats;
		}
		logInfo("vSphere SOAP: " + clusters.size()
				+ " ClusterComputeResource");

		java.util.List<BenchmarkProfile.Control> clusterControls =
				profile.clusterControls();
		int evaluableCount = countEvaluable(clusterControls, "vim_property");

		for (VSphereClient.ClusterInfo cluster : clusters) {
			stats.total++;
			if (stitcher == null) continue;
			ComplianceStitcher.HostEntry he =
					stitcher.matchCluster(cluster.name, cluster.moid);
			if (he == null) continue;

			if (evaluableCount == 0) {
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			boolean vsanPresent;
			try {
				vsanPresent = vsphere.hasVsanConfig(cluster.moRef);
			} catch (Exception e) {
				logWarn("Failed to probe vSAN config for cluster "
						+ cluster.name + ": " + e.getMessage());
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}
			if (!vsanPresent) {
				logInfo("Cluster " + cluster.name + " has no vsanConfigInfo "
						+ "(non-vSAN cluster), pushing profile_name only");
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			java.util.Map<String, Object> vsanCfg;
			try {
				vsanCfg = vsphere.readVimProperties(
						cluster.moRef, clusterControls);
			} catch (Exception e) {
				logWarn("Failed to read vSAN config for cluster "
						+ cluster.name + ": " + e.getMessage());
				pushProfileNamePropertyOnly(he.resourceId, profile.name);
				continue;
			}

			ControlEvaluator.ComplianceResult cr =
					ControlEvaluator.evaluateVimProperties(
							clusterControls, vsanCfg, cluster.name,
							VSphereClient.UNREADABLE);
			stats.unreadable += cr.unreadableCount;
			pushOrProfileName(he.resourceId, cr, profile.name);
		}
		return stats;
	}

	// ----- shared push / evaluation helpers -------------------------------

	private void pushOrProfileName(String resourceId,
			ControlEvaluator.ComplianceResult cr, String profileName) {
		if (cr.totalCount > 0 || cr.unreadableCount > 0) {
			pushComplianceViaClient(resourceId, cr, profileName);
		} else {
			pushProfileNamePropertyOnly(resourceId, profileName);
		}
	}

	/**
	 * Build 47 — true when a host's {@code runtime.connectionState} is a
	 * not-fully-connected state ({@code disconnected} / {@code notResponding}).
	 * A null/unknown state is NOT treated as disconnected (we proceed with
	 * normal evaluation and let the per-channel UNREADABLE sentinels surface
	 * any read failures) — only an explicit not-connected enum string trips
	 * the whole-host guard. Case-insensitive; the vim25
	 * {@code HostSystemConnectionState} enum is lower-camel.
	 */
	private static boolean isDisconnectedState(String connState) {
		if (connState == null) return false;
		String s = connState.trim().toLowerCase();
		return s.equals("disconnected") || s.equals("notresponding");
	}

	/**
	 * Build 47 — fold every evaluable {@code vim_property} / {@code esxcli}
	 * control in the slice to UNREADABLE without issuing any SOAP read. Used
	 * by the whole-host connection-state guard: a disconnected host cannot be
	 * read, so its vim/esxcli channel is unreadable, not skippable. Builds a
	 * value map of {@code UNREADABLE} for every evaluable recipe control and
	 * runs it through the normal evaluator so the unreadable accounting and
	 * per-control {@code (unreadable)} ControlResults match the live path
	 * exactly.
	 */
	private static ControlEvaluator.ComplianceResult unreadableVimResult(
			java.util.List<BenchmarkProfile.Control> controls,
			String resourceName) {
		java.util.Map<String, Object> values = new java.util.HashMap<>();
		for (BenchmarkProfile.Control c : controls) {
			if (!"vim_property".equals(c.parameterKind)
					&& !"esxcli".equals(c.parameterKind)) {
				continue;
			}
			if (!c.isEvaluable()) continue;
			String param = c.configParameter;
			if (param == null || param.isEmpty() || "N/A".equals(param)) {
				continue;
			}
			if (param.contains("\n")) continue;
			values.put(param, VSphereClient.UNREADABLE);
		}
		return ControlEvaluator.evaluateVimProperties(
				controls, values, resourceName, VSphereClient.UNREADABLE);
	}

	private ControlEvaluator.ComplianceResult evaluateVimForResource(
			VSphereClient.MoRef moRef,
			java.util.List<BenchmarkProfile.Control> controls,
			String resourceName) {
		int evaluableCount = countEvaluable(controls, "vim_property")
				+ countEvaluable(controls, "esxcli");
		if (evaluableCount == 0) {
			return emptyResult(resourceName);
		}
		java.util.Map<String, Object> values;
		try {
			values = vsphere.readVimProperties(moRef, controls);
		} catch (Exception e) {
			logWarn("Failed to read vim properties for " + resourceName + ": "
					+ e.getMessage()
					+ " — vim_property controls skipped this cycle "
					+ "(advanced_setting results preserved)");
			return emptyResult(resourceName);
		}
		return ControlEvaluator.evaluateVimProperties(
				controls, values, resourceName, VSphereClient.UNREADABLE);
	}

	private ControlEvaluator.ComplianceResult evaluateVamiForVCenter(
			java.util.List<BenchmarkProfile.Control> controls,
			String resourceName) {
		int evaluableCount = countEvaluable(controls, "vami_api");
		if (evaluableCount == 0) {
			return emptyResult(resourceName);
		}

		VamiApiClient client = new VamiApiClient(
				config.baseUrl(), config.username, config.password,
				config.allowInsecure);

		java.util.Map<String, Object> values = new java.util.HashMap<>();
		for (BenchmarkProfile.Control c : controls) {
			if (!"vami_api".equals(c.parameterKind) || !c.isEvaluable()) {
				continue;
			}
			String[] parsed = parseVamiRecipe(c.readRecipe);
			if (parsed == null) {
				values.put(c.configParameter, VSphereClient.UNREADABLE);
				continue;
			}
			Object read = client.readField(parsed[0], parsed[1]);
			if (read == VamiApiClient.FAILED || read == null) {
				values.put(c.configParameter, VSphereClient.UNREADABLE);
			} else {
				values.put(c.configParameter, read);
			}
		}

		return ControlEvaluator.evaluateVimProperties(
				controls, values, resourceName, VSphereClient.UNREADABLE);
	}

	private static String[] parseVamiRecipe(String recipe) {
		if (recipe == null) return null;
		String r = recipe.trim();
		if (!r.startsWith("vami:")) return null;
		String rest = r.substring("vami:".length());
		int lastColon = rest.lastIndexOf(':');
		if (lastColon <= 0 || lastColon >= rest.length() - 1) {
			return null;
		}
		String appliancePath = rest.substring(0, lastColon).trim();
		String field = rest.substring(lastColon + 1).trim();
		if (appliancePath.isEmpty() || field.isEmpty()) return null;
		return new String[]{appliancePath, field};
	}

	/** Zero-count, score=100 sentinel result (no controls evaluated). */
	private static ControlEvaluator.ComplianceResult emptyResult(
			String resourceName) {
		return new ControlEvaluator.ComplianceResult(
				resourceName, 0, 0, 0, 0, 100.0,
				new java.util.ArrayList<ControlEvaluator.ControlResult>());
	}

	private static ControlEvaluator.ComplianceResult mergeResults(
			ControlEvaluator.ComplianceResult a,
			ControlEvaluator.ComplianceResult b) {
		int pass = a.passCount + b.passCount;
		int fail = a.failCount + b.failCount;
		int total = a.totalCount + b.totalCount;
		int unreadable = a.unreadableCount + b.unreadableCount;
		java.util.List<ControlEvaluator.ControlResult> merged =
				new java.util.ArrayList<>(a.controlResults);
		merged.addAll(b.controlResults);
		double score = total > 0 ? ((double) pass / total) * 100.0 : 100.0;
		return new ControlEvaluator.ComplianceResult(
				a.hostname, pass, fail, total, unreadable, score, merged);
	}

	private static int countEvaluable(
			java.util.List<BenchmarkProfile.Control> slice, String kind) {
		int n = 0;
		for (BenchmarkProfile.Control c : slice) {
			if (kind.equals(c.parameterKind) && c.isEvaluable()) n++;
		}
		return n;
	}

	private void pushProfileNamePropertyOnly(String resourceId,
			String profileName) {
		long ts = System.currentTimeMillis();
		java.util.LinkedHashMap<String, String> props =
				new java.util.LinkedHashMap<>();
		props.put("VCF-CF Compliance|profile_name", profileName);
		stitcher.pushProperties(resourceId, props, ts);
		logInfo("Pushed profile_name='" + profileName + "' to resource="
				+ resourceId);
	}

	/**
	 * Publish first-class rollups + per-control raw onto a matched VMWARE
	 * resource. Key set and value semantics match v1 (the golden-comparison
	 * contract) for every resource that evaluated at least one control
	 * ({@code totalCount > 0}).
	 *
	 * <p><b>Build 48 score gate (deviation from byte-identical v1).</b> When
	 * {@code totalCount == 0} — every control unreadable, or a profile slice
	 * with zero evaluable controls — {@code score} / {@code pass_count} /
	 * {@code fail_count} are OMITTED rather than pushed as the zero-divisor
	 * sentinel {@code score=100}. Only {@code total_count=0} +
	 * {@code unreadable_count} are pushed, so the per-host compliance symptoms
	 * see "no data" rather than a flattering green sentinel (the cardinal
	 * "unreadable is NOT compliant" rule). This is intentionally NOT
	 * byte-identical to v1 for the {@code totalCount == 0} corner; v1 emitted
	 * the sentinel. No shipped profile produces a healthy host/VM with zero
	 * evaluable controls (every resource carries many advanced_setting + vim
	 * controls), so on real data this gate only ever fires for genuinely
	 * unreadable resources.
	 */
	private void pushComplianceViaClient(String resourceId,
			ControlEvaluator.ComplianceResult cr, String profileName) {
		long ts = System.currentTimeMillis();
		String prefix = "VCF-CF Compliance|" + profileName;

		java.util.LinkedHashMap<String, String> props =
				new java.util.LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			String ctrlPrefix = prefix + "|" + ctrl.scgId;
			props.put(ctrlPrefix + "|Actual", ctrl.actual);
			props.put(ctrlPrefix + "|Expected", ctrl.expected);
			props.put(ctrlPrefix + "|Description", ctrl.description);
		}
		props.put("VCF-CF Compliance|profile_name", profileName);

		java.util.LinkedHashMap<String, Double> stats =
				new java.util.LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			String ctrlPrefix = prefix + "|" + ctrl.scgId;
			stats.put(ctrlPrefix + "|Compliant", ctrl.compliant ? 1.0 : 0.0);
		}
		// Build 48 — no-sentinel per-resource push. A totalCount==0 result is
		// a host nothing could be scored on (every control unreadable); its
		// cr.score is the zero-divisor sentinel 100.0 from
		// evaluateControlsUnreadable. Pushing that sentinel as
		// VCF-CF Compliance|score lands a green "100" on the resource and the
		// per-host compliance symptoms (LT 95 / LT 80) read it as fully
		// compliant -> a blind host masquerades as perfect. Mirror the world
		// rollup's scored>0 discipline (line ~330): when totalCount==0, OMIT
		// score/pass_count/fail_count entirely and push only total_count=0 +
		// unreadable_count, so the symptoms see 'no data', not a sentinel.
		// Absent is the only honest per-resource value here (score=0 would
		// false-trip CRITICAL and is equally dishonest).
		if (cr.totalCount > 0) {
			stats.put("VCF-CF Compliance|score", cr.score);
			stats.put("VCF-CF Compliance|pass_count", (double) cr.passCount);
			stats.put("VCF-CF Compliance|fail_count", (double) cr.failCount);
		}
		stats.put("VCF-CF Compliance|total_count", (double) cr.totalCount);
		stats.put("VCF-CF Compliance|unreadable_count",
				(double) cr.unreadableCount);

		stitcher.pushProperties(resourceId, props, ts);
		stitcher.pushStats(resourceId, stats, ts);
	}

	// ----- per-kind stat holders ------------------------------------------

	private static final class HostStats {
		int total; int scored; double scoreSum; int belowThreshold;
		int unreadable;
		// Build 50 (review W1): count of hosts whose contribution to
		// avg_host_score came from lastKnownHostScore this cycle (i.e. the host
		// was channel-unreadable but folded its last-known score). 0 when every
		// scored host was read live this cycle. Subset of `scored`.
		int staleScored;
	}

	private static final class VmStats {
		int total; int scored; double scoreSum; int belowThreshold;
		int unreadable;
	}

	private static final class VCenterStats {
		boolean matched;
		int total; int scored; double scoreSum; int belowThreshold;
		int unreadable;
	}

	private static final class DvsStats { int total; int unreadable; }
	private static final class DvpgStats { int total; int unreadable; }
	private static final class ClusterStats { int total; int unreadable; }

	// -----------------------------------------------------------------------
	// onDiscard
	// -----------------------------------------------------------------------

	@Override
	public void onDiscard() {
		if (vcApi != null) vcApi.logout();
		if (vsphere != null) vsphere.disconnect();
		if (suiteStitcher != null) suiteStitcher.discard();
		super.onDiscard();
	}
}
