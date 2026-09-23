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

	// v3 (build 57): benchmark applied to each object in its previous cycle,
	// keyed "<Kind>|<moid>" -> profile_name. Drives orphaned-control cleanup
	// when an object's benchmark changes (see noteApplied). In-memory only:
	// a collector restart forgets history (first post-restart cycle cannot
	// detect a change). Replaces the build-era previousProfileName.
	private final java.util.concurrent.ConcurrentHashMap<String, String>
			appliedProfileByObject = new java.util.concurrent.ConcurrentHashMap<>();

	// Profiles in use this cycle, by name (all bundled in Auto mode, the one
	// fixed profile otherwise), plus previously applied bundled profiles
	// loaded on demand for orphan computation.
	private volatile java.util.Map<String, BenchmarkProfile> profilesByName;
	private final java.util.concurrent.ConcurrentHashMap<String, BenchmarkProfile>
			historyProfiles = new java.util.concurrent.ConcurrentHashMap<>();

	/**
	 * Per-control {@code Compliant} value domain (v3): 1 compliant, 0
	 * non-compliant, -1 not evaluated (unreadable this cycle, or no longer in
	 * the applied benchmark). The per-control compliance alerts fire on
	 * {@code Compliant == 0} only, so an unreadable setting never raises a
	 * "fix this" runbook; the object still counts as non-compliant through
	 * {@code unreadable_count} / {@code non_compliant}.
	 */
	static final double COMPLIANT_NOT_EVALUATED = -1.0;

	// Task #16 — last-known per-host compliance score, keyed by the stable host
	// MOID (hostInfo.moid), NOT the display name (a host can be renamed). Scott's
	// decision (v3: now applied to the per-vCenter Rollup|Host average, since
	// the world average is retired): use a host's LAST-KNOWN score
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
	 * resource. Walks vSphere inventory, selects a benchmark per object (v3),
	 * evaluates, pushes per-object compliance onto matched VMWARE resources,
	 * and pushes the per-vCenter rollup onto this instance's vCenter object.
	 *
	 * <p><b>v3 (build 57) world change.</b> ComplianceWorld is ONE resource
	 * shared by every adapter instance (identifier
	 * {@code world_id=compliance_world}), so any per-instance number pushed
	 * there is last-writer-wins across vCenters. It now carries only
	 * {@code Summary|last_scan_timestamp} (adapter liveness: the last scan by
	 * any instance). Fleet numbers live in the per-vCenter rollup
	 * ({@link ComplianceRollup}) on each {@code VMwareAdapter Instance}.
	 */
	private void collectWorld(ResourceConfig worldRc, List<MetricData> out)
			throws Exception {
		vsphere.ensureConnected();

		Path confDir = getAdapterDescribeFile(ADAPTER_KIND, "describe.xml")
				.getParent();   // <adaptersHome>/<kind>/conf
		BenchmarkSelector selector = buildSelector(confDir.toString());

		logInfo("stitcher=" + (stitcher != null));
		if (stitcher != null) {
			loadStitcherResources();
		}

		String vcVersion = null;
		try {
			vcVersion = vsphere.getVCenterVersion();
		} catch (Exception e) {
			logWarn("Could not read the vCenter version: " + e.getMessage());
		}
		if (selector.isAuto()) {
			logInfo("Auto (by version): vCenter version=" + vcVersion
					+ " governs vCenter / cluster / vDS / portgroup benchmark "
					+ "choice");
		}

		ComplianceRollup rollup = new ComplianceRollup();
		CycleStats cs = new CycleStats();
		java.util.Set<String> seen = new java.util.HashSet<>();

		java.util.Map<String, String> hostVersions =
				collectHosts(selector, rollup, cs, seen);
		collectVms(selector, hostVersions, rollup, cs, seen);
		ComplianceStitcher.HostEntry vcEntry =
				collectVCenter(selector, vcVersion, rollup, cs, seen);
		collectDvs(selector, vcVersion, rollup, cs, seen);
		collectDvpg(selector, vcVersion, rollup, cs, seen);
		collectClusters(selector, vcVersion, rollup, cs, seen);

		// Forget applied-profile history for objects no longer in inventory.
		appliedProfileByObject.keySet().retainAll(seen);

		pushRollup(vcEntry, rollup);

		if (cs.unreadable > 0) {
			logWarn(cs.unreadable + " control instance(s) could not be read "
					+ "this cycle (declared-but-unreadable). They are excluded "
					+ "from every compliance score, and each affected object "
					+ "counts as non-compliant (unreadable is not compliant).");
		}

		pushWorldProperty(out, "Summary|last_scan_timestamp",
				Instant.now().toString());

		logInfo("ComplianceAdapter collection complete: "
				+ cs.hosts + " hosts, "
				+ cs.vms + " VMs, "
				+ (vcEntry != null ? "1" : "0") + " vCenter pushed, "
				+ cs.dvs + " DVS, "
				+ cs.dvpg + " DVPG, "
				+ cs.clusters + " ClusterComputeResource, "
				+ cs.noBenchmark + " object(s) without a benchmark");
	}

	/**
	 * Build the per-cycle benchmark selector. {@code Auto (by version)}
	 * loads every bundled profile once (cached by the loader) and selects
	 * per object; any other value forces that profile for every object.
	 */
	private BenchmarkSelector buildSelector(String confDir) {
		if (config.isAuto()) {
			java.util.Map<String, BenchmarkProfile> all =
					benchmarkLoader.loadAll(confDir);
			profilesByName = all;
			logInfo("Benchmark mode: " + BenchmarkSelector.AUTO + " ("
					+ all.size() + " bundled profiles loaded; "
					+ benchmarkLoader.lastManualReviewApplied()
					+ " prose-expected controls set to manual review)");
			return BenchmarkSelector.auto(all);
		}
		BenchmarkProfile profile = benchmarkLoader.load(
				config.benchmarkProfile,
				config.customProfilePath,
				confDir);
		if (!profile.name.equals(config.benchmarkProfile)) {
			logWarn("Profile load divergence: requested='"
					+ config.benchmarkProfile + "' resolved='"
					+ profile.name + "': profile_name will use the resolved "
					+ "name");
		}
		java.util.Map<String, BenchmarkProfile> one = new java.util.HashMap<>();
		one.put(profile.name, profile);
		profilesByName = one;
		logInfo("Benchmark mode: fixed '" + profile.name + "' for every "
				+ "object (" + benchmarkLoader.lastManualReviewApplied()
				+ " prose-expected controls set to manual review)");
		return BenchmarkSelector.fixed(profile);
	}

	/** Push the per-vCenter rollup onto this instance's vCenter object. */
	private void pushRollup(ComplianceStitcher.HostEntry vcEntry,
			ComplianceRollup rollup) {
		if (stitcher == null) {
			return;
		}
		if (vcEntry == null) {
			logWarn("No VMwareAdapter Instance resolved for "
					+ config.vcenterHost + ": the per-vCenter compliance "
					+ "rollup (VCF-CF Compliance|Rollup|*) is NOT pushed this "
					+ "cycle");
			return;
		}
		java.util.Map<String, Double> stats = rollup.toStats();
		stitcher.pushStats(vcEntry.resourceId, stats,
				System.currentTimeMillis());
		logInfo("Pushed " + stats.size() + " rollup stat(s) to vCenter "
				+ vcEntry.hostName + " (resource=" + vcEntry.resourceId + ")");
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

	// ----- Applied-benchmark change detection (v3, replaces Fix #2) -------

	/**
	 * v3 (build 57) replacement for the build-era {@code detectProfileChange}.
	 *
	 * <p>With profile-free per-control keys
	 * ({@code VCF-CF Compliance|<control_id>|...}) a benchmark change no
	 * longer moves an object to a new key namespace. The lingering-key
	 * problem changes shape: a control that the OLD benchmark evaluated but
	 * the NEW one does not keeps its last {@code Compliant} value forever,
	 * and a stale {@code 0} would keep that control's compliance alert
	 * open. So on a per-object benchmark change (a host upgraded 8.0 to 9.0,
	 * a fixed profile switched, Auto enabled, a version going unmapped) the
	 * adapter pushes {@code Compliant=-1} and a "not in applied benchmark"
	 * Actual for each orphaned control, which cancels the alert and tells
	 * the operator why the value stopped.
	 *
	 * <p>The pre-v3 version also counted stitched resources for its log
	 * line and left ClusterComputeResource out of that count (its other kind
	 * names did match the stitcher's); the count is gone with the rewrite.
	 *
	 * <p>In-memory only: a collector restart forgets history, and the first
	 * post-restart cycle cannot see a change (same caveat as before).
	 */
	private void noteApplied(BenchmarkSelector.Kind kind, String moid,
			BenchmarkSelector.Selection sel, String resourceId) {
		if (moid == null) return;
		String key = kind.name() + "|" + moid;
		String prev = appliedProfileByObject.put(key, sel.profileName);
		if (prev == null || prev.equals(sel.profileName)) {
			return;
		}
		if (prev.startsWith("no benchmark")) {
			// Nothing was evaluated under a no-benchmark label: no orphans.
			logInfo(kind.rollupName + " " + moid + ": benchmark now '"
					+ sel.profileName + "' (was '" + prev + "')");
			return;
		}
		BenchmarkProfile old = profileForHistory(prev);
		if (old == null) {
			logInfo(kind.rollupName + " " + moid + ": benchmark changed '"
					+ prev + "' -> '" + sel.profileName + "'; the previous "
					+ "control set is not loadable, so its per-control keys "
					+ "are left as they are");
			return;
		}
		java.util.Set<String> keep = new java.util.HashSet<>();
		if (sel.profile != null) {
			for (BenchmarkProfile.Control c : sliceFor(sel.profile, kind)) {
				if (BenchmarkSelector.evaluatedFor(kind, c)) {
					keep.add(c.controlId);
				}
			}
		}
		java.util.LinkedHashMap<String, String> props =
				new java.util.LinkedHashMap<>();
		java.util.LinkedHashMap<String, Double> stats =
				new java.util.LinkedHashMap<>();
		for (BenchmarkProfile.Control c : sliceFor(old, kind)) {
			if (!BenchmarkSelector.evaluatedFor(kind, c)) continue;
			if (keep.contains(c.controlId)) continue;
			String base = "VCF-CF Compliance|" + c.controlId;
			props.put(base + "|Actual", "(not in applied benchmark: "
					+ sel.profileName + ")");
			stats.put(base + "|Compliant", COMPLIANT_NOT_EVALUATED);
		}
		logWarn(kind.rollupName + " " + moid + ": benchmark changed '" + prev
				+ "' -> '" + sel.profileName + "'; " + stats.size()
				+ " control(s) no longer apply"
				+ (stats.isEmpty() || stitcher == null || resourceId == null
						? "" : " and are marked Compliant=-1 (not evaluated)"));
		if (!stats.isEmpty() && stitcher != null && resourceId != null) {
			long ts = System.currentTimeMillis();
			stitcher.pushProperties(resourceId, props, ts);
			stitcher.pushStats(resourceId, stats, ts);
		}
	}

	/** A previously applied profile by name, for orphan computation. */
	private BenchmarkProfile profileForHistory(String name) {
		java.util.Map<String, BenchmarkProfile> current = profilesByName;
		if (current != null && current.containsKey(name)) {
			return current.get(name);
		}
		if (!BenchmarkLoader.BUNDLED_PROFILES.contains(name)) {
			// "Custom" (path may have changed) or a no-benchmark label.
			return null;
		}
		return historyProfiles.computeIfAbsent(name, n -> {
			try {
				return new BenchmarkLoader().load(n, null, adapterConfDir());
			} catch (RuntimeException e) {
				logWarn("Could not load previous profile '" + n + "': "
						+ e.getMessage());
				return null;
			}
		});
	}

	private String adapterConfDir() {
		return getAdapterDescribeFile(ADAPTER_KIND, "describe.xml")
				.getParent().toString();
	}

	private static java.util.List<BenchmarkProfile.Control> sliceFor(
			BenchmarkProfile p, BenchmarkSelector.Kind kind) {
		switch (kind) {
			case HOST: return p.hostControls();
			case VM: return p.vmControls();
			case VCENTER: return p.vCenterControls();
			case CLUSTER: return p.clusterControls();
			case VDS: return p.dvsControls();
			case PORTGROUP: return p.dvpgControls();
			default: return java.util.Collections.emptyList();
		}
	}

	// ----- Per-kind collectors --------------------------------------------

	/**
	 * Hosts. Returns host MOID -> ESXi version (null values allowed) so VMs
	 * can follow their host in Auto mode.
	 */
	private java.util.Map<String, String> collectHosts(
			BenchmarkSelector selector, ComplianceRollup rollup,
			CycleStats cs, java.util.Set<String> seen) throws Exception {
		java.util.Map<String, String> hostVersions = new java.util.HashMap<>();
		java.util.List<VSphereClient.HostInfo> hosts = vsphere.getHosts();
		if (hosts.isEmpty()) {
			logWarn("No hosts returned from vCenter SOAP");
			return hostVersions;
		}
		logInfo("vSphere SOAP: " + hosts.size() + " hosts");

		for (VSphereClient.HostInfo hostInfo : hosts) {
			String hostId = hostInfo.moid;
			String hostName = hostInfo.name;
			cs.hosts++;
			if (hostId != null) {
				seen.add(BenchmarkSelector.Kind.HOST.name() + "|" + hostId);
			}

			String version = null;
			if (selector.isAuto()) {
				try {
					version = vsphere.getHostProductVersion(hostInfo.moRef);
				} catch (Exception e) {
					logWarn("Host " + hostName + ": could not read the ESXi "
							+ "version (" + e.getMessage() + ")");
				}
			}
			if (hostId != null) hostVersions.put(hostId, version);

			ComplianceStitcher.HostEntry he = stitcher == null ? null
					: stitcher.matchHost(hostName, hostId);
			String resourceId = he == null ? null : he.resourceId;

			BenchmarkSelector.Selection sel =
					selector.select(BenchmarkSelector.Kind.HOST,
						BenchmarkSelector.governingVersion(
								BenchmarkSelector.Kind.HOST, null, version));
			if (sel.noBenchmark()) {
				recordNoBenchmark(BenchmarkSelector.Kind.HOST, hostName, hostId,
						sel, resourceId, rollup, cs);
				continue;
			}
			java.util.List<BenchmarkProfile.Control> hostControls =
					sel.profile.hostControls();

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

			ControlEvaluator.ComplianceResult cr;
			boolean wholeHostUnreadable = false;
			if (isDisconnectedState(connState)) {
				logWarn("Host " + hostName + ": connectionState='" + connState
						+ "' — host not fully connected to vCenter; ALL "
						+ "compliance controls marked UNREADABLE this cycle "
						+ "(no partial score emitted)");
				cr = wholeUnreadable(hostControls, hostName);
				wholeHostUnreadable = true;
			} else {
				java.util.Map<String, String> advSettings = null;
				boolean advUnreadable = false;
				try {
					advSettings = vsphere.getAdvancedSettings(hostInfo.moRef);
				} catch (VSphereClient.AdvancedSettingsUnreadableException e) {
					// Build 48: null OptionManager MoRef means the host
					// disconnected between the connectionState check and this
					// read (a flap). A half-connected host must never produce
					// a score: treat the WHOLE host as unreadable, identical to
					// the connection-state branch above.
					logWarn("Host " + hostName + ": advanced-settings channel "
							+ "UNREADABLE (" + e.getMessage() + "): host "
							+ "flapped between connection check and read; ALL "
							+ "compliance controls marked UNREADABLE this cycle "
							+ "(no partial score emitted)");
					wholeHostUnreadable = true;
				} catch (Exception e) {
					// Any other read failure (SOAP fault, transport) is likewise
					// a read failure, not an empty result: treat as unreadable.
					advUnreadable = true;
					logWarn("Host " + hostName + ": failed to read advanced "
							+ "settings (" + e.getMessage() + "): all "
							+ "advanced_setting controls marked UNREADABLE this "
							+ "cycle (not dropped from the denominator)");
				}
				if (wholeHostUnreadable) {
					cr = wholeUnreadable(hostControls, hostName);
				} else {
					ControlEvaluator.ComplianceResult advCr = advUnreadable
							? ControlEvaluator.evaluateControlsUnreadable(
									hostControls, hostName)
							: ControlEvaluator.evaluateControls(
									hostControls, advSettings, hostName);
					ControlEvaluator.ComplianceResult vimCr =
							evaluateVimForResource(hostInfo.moRef, hostControls,
									hostName);
					cr = mergeResults(advCr, vimCr);
				}
			}
			cs.unreadable += cr.unreadableCount;
			rollup.recordEvaluated(BenchmarkSelector.Kind.HOST, sel.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);

			if (cr.totalCount > 0) {
				// Task #16: remember this host's score so a future cycle in
				// which the host is unreadable can still contribute it to the
				// host average. Keyed by stable MOID (null-guarded: build 50).
				if (hostId != null) {
					lastKnownHostScore.put(hostId, cr.score);
				}
				logInfo("Host " + hostName + " [" + sel.profileName + "]: score="
						+ String.format("%.1f", cr.score) + "% ("
						+ cr.passCount + " pass, " + cr.failCount + " fail, "
						+ cr.unreadableCount + " unreadable, "
						+ cr.totalCount + " total)");
			} else if (wholeHostUnreadable) {
				applyLastKnownForUnreadableHost(hostId, hostName, rollup);
				logInfo("Host " + hostName + ": UNREADABLE (" + cr.unreadableCount
						+ " controls)");
			}

			if (resourceId != null) {
				pushComplianceViaClient(resourceId, cr, sel.profileName);
			}
			noteApplied(BenchmarkSelector.Kind.HOST, hostId, sel, resourceId);
		}
		// Build 50 (review N1): evict last-known-score entries for hosts no
		// longer in the current inventory (unreadable hosts are still
		// enumerated, so only genuinely removed hosts are pruned).
		evictAbsentHostScores(hosts);
		return hostVersions;
	}

	/** Every advanced_setting and vim/esxcli control folded to UNREADABLE. */
	private static ControlEvaluator.ComplianceResult wholeUnreadable(
			java.util.List<BenchmarkProfile.Control> controls, String name) {
		return mergeResults(
				ControlEvaluator.evaluateControlsUnreadable(controls, name),
				unreadableVimResult(controls, name));
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
	 * last-known score (if any) into the per-vCenter host rollup so the
	 * denominator stays full and an unreadable host does not silently flatter
	 * the average (counted in {@code Rollup|Host|scored_stale}). A host with no
	 * last-known score (never read since process start) stays excluded: we
	 * never invent a score we have not observed. The per-host push is
	 * unchanged: no score stat for a totalCount==0 host.
	 */
	private void applyLastKnownForUnreadableHost(String hostId, String hostName,
			ComplianceRollup rollup) {
		Double last = (hostId == null) ? null : lastKnownHostScore.get(hostId);
		if (last == null) {
			logInfo("Host " + hostName + ": unreadable and no last-known score "
					+ "(never read since collector start) — excluded from the "
					+ "host score rollup this cycle");
			return;
		}
		rollup.recordStaleScore(BenchmarkSelector.Kind.HOST, last);
		logInfo("Host " + hostName + ": unreadable this cycle — contributing "
				+ "last-known score " + String.format("%.1f", last)
				+ "% to the host score rollup (denominator kept full)");
	}

	private void collectVms(BenchmarkSelector selector,
			java.util.Map<String, String> hostVersions, ComplianceRollup rollup,
			CycleStats cs, java.util.Set<String> seen) {
		java.util.List<VSphereClient.VmInfo> vms;
		try {
			vms = vsphere.getVms();
		} catch (Exception e) {
			logWarn("Failed to enumerate VMs: " + e.getMessage());
			return;
		}
		if (vms.isEmpty()) {
			logInfo("No VMs returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + vms.size() + " VMs");

		for (VSphereClient.VmInfo vm : vms) {
			cs.vms++;
			if (vm.moid != null) {
				seen.add(BenchmarkSelector.Kind.VM.name() + "|" + vm.moid);
			}
			String hostVersion = selector.isAuto()
					? vmHostVersion(vm, hostVersions) : null;

			ComplianceStitcher.HostEntry he = stitcher == null ? null
					: stitcher.matchVm(vm.name, vm.moid);
			String resourceId = he == null ? null : he.resourceId;

			BenchmarkSelector.Selection sel =
					selector.select(BenchmarkSelector.Kind.VM,
						BenchmarkSelector.governingVersion(
								BenchmarkSelector.Kind.VM, null, hostVersion));
			if (sel.noBenchmark()) {
				recordNoBenchmark(BenchmarkSelector.Kind.VM, vm.name, vm.moid,
						sel, resourceId, rollup, cs);
				continue;
			}
			java.util.List<BenchmarkProfile.Control> vmControls =
					sel.profile.vmControls();

			ControlEvaluator.ComplianceResult advCr;
			try {
				java.util.Map<String, String> extra =
						vsphere.getVmExtraConfig(vm.moRef);
				advCr = ControlEvaluator.evaluateControls(vmControls, extra,
						vm.name);
			} catch (Exception e) {
				// v3 fix: a FAILED extraConfig read used to fall back to an
				// empty map, which scored every "X or Undefined" control as a
				// pass (absent key = platform default). A failed read is
				// unreadable, never compliant.
				logWarn("Failed to read extraConfig for " + vm.name + ": "
						+ e.getMessage() + ": advanced_setting controls "
						+ "marked UNREADABLE this cycle");
				advCr = ControlEvaluator.evaluateControlsUnreadable(vmControls,
						vm.name);
			}
			ControlEvaluator.ComplianceResult vimCr =
					evaluateVimForResource(vm.moRef, vmControls, vm.name);
			ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vimCr);
			cs.unreadable += cr.unreadableCount;
			rollup.recordEvaluated(BenchmarkSelector.Kind.VM, sel.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);

			if (resourceId != null) {
				pushComplianceViaClient(resourceId, cr, sel.profileName);
			}
			noteApplied(BenchmarkSelector.Kind.VM, vm.moid, sel, resourceId);
		}
		logInfo("VM compliance: " + cs.vms + " VMs seen");
	}

	/**
	 * The ESXi version of the host a VM runs on (Auto mode). Looks the host
	 * up in this cycle's host map; a host missing from the map is read
	 * directly and cached. Null (version unreadable) when the VM has no
	 * host or the read fails; never a default version.
	 */
	private String vmHostVersion(VSphereClient.VmInfo vm,
			java.util.Map<String, String> hostVersions) {
		String hostMoid;
		try {
			hostMoid = vsphere.getVmHostMoid(vm.moRef);
		} catch (Exception e) {
			logWarn("VM " + vm.name + ": could not read runtime.host ("
					+ e.getMessage() + ")");
			return null;
		}
		if (hostMoid == null) {
			return null;
		}
		if (hostVersions.containsKey(hostMoid)) {
			return hostVersions.get(hostMoid);
		}
		String v = null;
		try {
			v = vsphere.getHostProductVersion(
					new VSphereClient.MoRef("HostSystem", hostMoid));
		} catch (Exception e) {
			logWarn("VM " + vm.name + ": could not read the version of host "
					+ hostMoid + " (" + e.getMessage() + ")");
		}
		hostVersions.put(hostMoid, v);
		return v;
	}

	private ComplianceStitcher.HostEntry collectVCenter(
			BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) {
		String resourceName = config.vcenterHost;
		String moid = "vcenter";
		seen.add(BenchmarkSelector.Kind.VCENTER.name() + "|" + moid);

		ComplianceStitcher.HostEntry he = null;
		if (stitcher != null) {
			String vcInstanceUuid = null;
			try {
				vcInstanceUuid = vsphere.getVCenterInstanceUuid();
			} catch (Exception e) {
				logWarn("Could not read vCenter instance UUID for stitcher "
						+ "lookup: " + e.getMessage());
			}
			he = stitcher.matchVCenterAdapterInstance(resourceName,
					vcInstanceUuid);
			if (he == null) {
				logWarn("Could not resolve VMwareAdapter Instance for "
						+ resourceName + " (vcInstanceUuid=" + vcInstanceUuid
						+ "): vCenter compliance and the per-vCenter rollup "
						+ "will NOT appear");
			}
		}
		String resourceId = he == null ? null : he.resourceId;

		BenchmarkSelector.Selection sel =
				selector.select(BenchmarkSelector.Kind.VCENTER,
						BenchmarkSelector.governingVersion(
								BenchmarkSelector.Kind.VCENTER, vcVersion, null));
		if (sel.noBenchmark()) {
			recordNoBenchmark(BenchmarkSelector.Kind.VCENTER, resourceName, moid,
					sel, resourceId, rollup, cs);
			return he;
		}
		java.util.List<BenchmarkProfile.Control> vcControls =
				sel.profile.vCenterControls();

		ControlEvaluator.ComplianceResult advCr;
		try {
			java.util.Map<String, String> vcSettings =
					vsphere.getVCenterAdvancedSettings();
			logInfo("vCenter advanced settings: " + vcSettings.size()
					+ " entries");
			advCr = ControlEvaluator.evaluateControls(vcControls, vcSettings,
					resourceName);
		} catch (Exception e) {
			// v3: previously the whole vCenter was skipped (no push, not
			// counted). A failed read is unreadable, which the vCenter object
			// and the rollup must show.
			logWarn("Failed to read vCenter advanced settings: "
					+ e.getMessage() + ": advanced_setting controls marked "
					+ "UNREADABLE this cycle");
			advCr = ControlEvaluator.evaluateControlsUnreadable(vcControls,
					resourceName);
		}
		ControlEvaluator.ComplianceResult vamiCr =
				evaluateVamiForVCenter(vcControls, resourceName);
		ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vamiCr);
		logInfo("vCenter " + resourceName + " [" + sel.profileName + "]: score="
				+ String.format("%.1f", cr.score) + "% ("
				+ cr.passCount + " pass, " + cr.failCount + " fail, "
				+ cr.unreadableCount + " unreadable, "
				+ cr.totalCount + " total)");

		cs.unreadable += cr.unreadableCount;
		rollup.recordEvaluated(BenchmarkSelector.Kind.VCENTER, sel.bucket,
				cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);

		if (resourceId != null) {
			pushComplianceViaClient(resourceId, cr, sel.profileName);
			logInfo("Pushed vCenter compliance data to " + he.hostName
					+ " (resource=" + he.resourceId + ", VCURL=" + he.moid
					+ ")");
		}
		noteApplied(BenchmarkSelector.Kind.VCENTER, moid, sel, resourceId);
		return he;
	}

	private void collectDvs(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) {
		if (stitcher == null) return;   // nothing to push onto; skip the reads
		java.util.List<VSphereClient.DvsInfo> switches;
		try {
			switches = vsphere.getDvSwitches();
		} catch (Exception e) {
			logWarn("Failed to enumerate DVS: " + e.getMessage());
			return;
		}
		if (switches.isEmpty()) {
			logInfo("No DVS returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + switches.size() + " DVS");
		for (VSphereClient.DvsInfo dvs : switches) {
			cs.dvs++;
			ComplianceStitcher.HostEntry he = stitcher.matchDvs(dvs.name,
					dvs.moid);
			collectVimObject(BenchmarkSelector.Kind.VDS, dvs.moRef, dvs.name,
					dvs.moid, he, selector, vcVersion, rollup, cs, seen);
		}
	}

	private void collectDvpg(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) {
		if (stitcher == null) return;
		java.util.List<VSphereClient.DvpgInfo> pgs;
		try {
			pgs = vsphere.getDvPortgroups();
		} catch (Exception e) {
			logWarn("Failed to enumerate DVPG: " + e.getMessage());
			return;
		}
		if (pgs.isEmpty()) {
			logInfo("No DVPG returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + pgs.size() + " DVPG");
		for (VSphereClient.DvpgInfo pg : pgs) {
			cs.dvpg++;
			ComplianceStitcher.HostEntry he = stitcher.matchDvpg(pg.name,
					pg.moid);
			collectVimObject(BenchmarkSelector.Kind.PORTGROUP, pg.moRef,
					pg.name, pg.moid, he, selector, vcVersion, rollup, cs,
					seen);
		}
	}

	/**
	 * ClusterComputeResource (vSAN) collector. Non-vSAN clusters get
	 * profile_name only: vSAN controls are genuinely N/A, not a coverage
	 * gap. The bulk of SCG's cluster controls require the vSAN Management
	 * SDK (not on this classpath) and stay manual_audit: CLASSPATH GAP.
	 */
	private void collectClusters(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) {
		if (stitcher == null) return;
		java.util.List<VSphereClient.ClusterInfo> clusters;
		try {
			clusters = vsphere.getClusters();
		} catch (Exception e) {
			logWarn("Failed to enumerate ClusterComputeResource: "
					+ e.getMessage());
			return;
		}
		if (clusters.isEmpty()) {
			logInfo("No ClusterComputeResource returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + clusters.size()
				+ " ClusterComputeResource");
		for (VSphereClient.ClusterInfo cluster : clusters) {
			cs.clusters++;
			ComplianceStitcher.HostEntry he = stitcher.matchCluster(
					cluster.name, cluster.moid);
			collectVimObject(BenchmarkSelector.Kind.CLUSTER, cluster.moRef,
					cluster.name, cluster.moid, he, selector, vcVersion,
					rollup, cs, seen);
		}
	}

	/**
	 * Shared body for the vim-property-only kinds (vDS, portgroup, cluster),
	 * all governed by the vCenter version. Evaluated whether or not the
	 * VMWARE resource is matched this cycle, so the rollup counts every
	 * inventory object, not only the stitched ones.
	 *
	 * <p>v3 cardinal fix: a FAILED read (vim properties, or the cluster vSAN
	 * probe) used to push profile_name only, which is indistinguishable from
	 * "nothing to check". It now folds every evaluable control to
	 * UNREADABLE, so the object reports unreadable_count and counts as
	 * non-compliant.
	 */
	private void collectVimObject(BenchmarkSelector.Kind kind,
			VSphereClient.MoRef moRef, String name, String moid,
			ComplianceStitcher.HostEntry he, BenchmarkSelector selector,
			String vcVersion, ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) {
		if (moid != null) seen.add(kind.name() + "|" + moid);
		String resourceId = he == null ? null : he.resourceId;

		// The object's own version (e.g. a vDS at 9.0.0 under a 9.1.1
		// vCenter) is deliberately not read: vCenter governs these kinds.
		BenchmarkSelector.Selection sel = selector.select(kind,
				BenchmarkSelector.governingVersion(kind, vcVersion, null));
		if (sel.noBenchmark()) {
			recordNoBenchmark(kind, name, moid, sel, resourceId, rollup, cs);
			return;
		}
		java.util.List<BenchmarkProfile.Control> controls =
				sliceFor(sel.profile, kind);
		ControlEvaluator.ComplianceResult cr;
		if (countEvaluable(controls, "vim_property") == 0) {
			cr = emptyResult(name);
		} else if (kind == BenchmarkSelector.Kind.CLUSTER) {
			Boolean vsan = probeVsan(moRef, name);
			if (vsan == null) {
				cr = null;                    // probe failed: unreadable
			} else if (!vsan) {
				cr = emptyResult(name);       // non-vSAN: genuinely N/A
			} else {
				cr = readAndEvaluateVim(moRef, controls, name);
			}
		} else {
			cr = readAndEvaluateVim(moRef, controls, name);
		}
		if (cr == null) {
			cr = unreadableVimResult(controls, name);
		}
		cs.unreadable += cr.unreadableCount;
		rollup.recordEvaluated(kind, sel.bucket, cr.totalCount, cr.failCount,
				cr.unreadableCount, cr.score);
		if (resourceId != null) {
			pushOrProfileName(resourceId, cr, sel.profileName);
		}
		noteApplied(kind, moid, sel, resourceId);
	}

	/**
	 * vSAN presence for a cluster: TRUE when vSAN is configured, FALSE for a
	 * non-vSAN cluster (vSAN controls genuinely N/A), NULL when the probe
	 * itself failed (unreadable, never "not vSAN").
	 */
	private Boolean probeVsan(VSphereClient.MoRef moRef, String name) {
		try {
			boolean present = vsphere.hasVsanConfig(moRef);
			if (!present) {
				logInfo("Cluster " + name + " has no vsanConfigInfo (non-vSAN "
						+ "cluster), pushing profile_name only");
			}
			return present;
		} catch (Exception e) {
			logWarn("Failed to probe vSAN config for cluster " + name + ": "
					+ e.getMessage() + ": vSAN controls marked UNREADABLE");
			return null;
		}
	}

	/** Read + evaluate vim controls; null on a failed read (unreadable). */
	private ControlEvaluator.ComplianceResult readAndEvaluateVim(
			VSphereClient.MoRef moRef,
			java.util.List<BenchmarkProfile.Control> controls, String name) {
		java.util.Map<String, Object> values;
		try {
			values = vsphere.readVimProperties(moRef, controls);
		} catch (Exception e) {
			logWarn("Failed to read vim properties for " + name + ": "
					+ e.getMessage() + ": controls marked UNREADABLE");
			return null;
		}
		return ControlEvaluator.evaluateVimProperties(controls, values, name,
				VSphereClient.UNREADABLE);
	}

	/** Record + push an object whose version has no benchmark. */
	private void recordNoBenchmark(BenchmarkSelector.Kind kind, String name,
			String moid, BenchmarkSelector.Selection sel, String resourceId,
			ComplianceRollup rollup, CycleStats cs) {
		cs.noBenchmark++;
		rollup.recordNoBenchmark(kind);
		logInfo(kind.rollupName + " " + name + ": " + sel.profileName
				+ " (not scored)");
		if (resourceId != null) {
			pushNoBenchmark(resourceId, sel.profileName);
		}
		noteApplied(kind, moid, sel, resourceId);
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
			// v3 cardinal fix: a failed read is UNREADABLE (counted, object
			// non-compliant), not a silent skip that shrinks the denominator.
			logWarn("Failed to read vim properties for " + resourceName + ": "
					+ e.getMessage()
					+ ": vim_property / esxcli controls marked UNREADABLE this "
					+ "cycle (advanced_setting results preserved)");
			return unreadableVimResult(controls, resourceName);
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

	/**
	 * An object with a benchmark but nothing evaluable against it (non-vSAN
	 * cluster, a slice with zero evaluable controls): profile_name plus the
	 * two flags, no score. The flags are pushed so a view's summary row can
	 * count every object and a stale 1 from an earlier cycle is cleared.
	 */
	private void pushProfileNamePropertyOnly(String resourceId,
			String profileName) {
		long ts = System.currentTimeMillis();
		java.util.LinkedHashMap<String, String> props =
				new java.util.LinkedHashMap<>();
		props.put("VCF-CF Compliance|profile_name", profileName);
		java.util.LinkedHashMap<String, Double> stats =
				new java.util.LinkedHashMap<>();
		stats.put("VCF-CF Compliance|non_compliant", 0.0);
		stats.put("VCF-CF Compliance|no_benchmark", 0.0);
		stitcher.pushProperties(resourceId, props, ts);
		stitcher.pushStats(resourceId, stats, ts);
		logInfo("Pushed profile_name='" + profileName + "' to resource="
				+ resourceId);
	}

	/**
	 * v3: an object whose version has no SCG in this pak (Auto mode).
	 * profile_name = "no benchmark for <product> X.Y", no_benchmark = 1,
	 * non_compliant = 0 (not scored, so neither compliant nor not), and no
	 * score / counts / per-control results.
	 */
	private void pushNoBenchmark(String resourceId, String label) {
		long ts = System.currentTimeMillis();
		java.util.LinkedHashMap<String, String> props =
				new java.util.LinkedHashMap<>();
		props.put("VCF-CF Compliance|profile_name", label);
		java.util.LinkedHashMap<String, Double> stats =
				new java.util.LinkedHashMap<>();
		stats.put("VCF-CF Compliance|no_benchmark", 1.0);
		stats.put("VCF-CF Compliance|non_compliant", 0.0);
		stitcher.pushProperties(resourceId, props, ts);
		stitcher.pushStats(resourceId, stats, ts);
	}

	/**
	 * Publish rollups + per-control raw onto a matched VMWARE resource.
	 *
	 * <p><b>v3 (build 57) keys: profile-free.</b> Per-control keys are
	 * {@code VCF-CF Compliance|<control_id>|{Actual,Expected,Description}}
	 * (properties) and {@code ...|Compliant} (metric: 1 / 0 / -1, see
	 * {@link #COMPLIANT_NOT_EVALUATED}). The benchmark that applied is the
	 * {@code profile_name} property. Old profile-prefixed keys are not
	 * migrated (owner-approved break).
	 *
	 * <p>Aggregates: score / pass_count / fail_count only when
	 * {@code totalCount > 0} (build 48 no-sentinel gate), total_count and
	 * unreadable_count always, plus the v3 flags {@code non_compliant}
	 * (1 when fail_count &gt; 0 or unreadable_count &gt; 0: unreadable is not
	 * compliant) and {@code no_benchmark} (0 here).
	 */
	private void pushComplianceViaClient(String resourceId,
			ControlEvaluator.ComplianceResult cr, String profileName) {
		long ts = System.currentTimeMillis();

		java.util.LinkedHashMap<String, String> props =
				new java.util.LinkedHashMap<>();
		java.util.LinkedHashMap<String, Double> stats =
				new java.util.LinkedHashMap<>();
		for (ControlEvaluator.ControlResult ctrl : cr.controlResults) {
			String base = "VCF-CF Compliance|" + ctrl.scgId;
			props.put(base + "|Actual", ctrl.actual);
			props.put(base + "|Expected", ctrl.expected);
			props.put(base + "|Description", ctrl.description);
			stats.put(base + "|Compliant", ctrl.unreadable
					? COMPLIANT_NOT_EVALUATED
					: (ctrl.compliant ? 1.0 : 0.0));
		}
		props.put("VCF-CF Compliance|profile_name", profileName);

		// Build 48: no-sentinel per-resource push: when totalCount==0 the
		// score is the zero-divisor sentinel 100.0; pushing it would land a
		// green "100" on a blind object. Omit score/pass/fail instead.
		if (cr.totalCount > 0) {
			stats.put("VCF-CF Compliance|score", cr.score);
			stats.put("VCF-CF Compliance|pass_count", (double) cr.passCount);
			stats.put("VCF-CF Compliance|fail_count", (double) cr.failCount);
		}
		stats.put("VCF-CF Compliance|total_count", (double) cr.totalCount);
		stats.put("VCF-CF Compliance|unreadable_count",
				(double) cr.unreadableCount);
		stats.put("VCF-CF Compliance|non_compliant",
				ComplianceRollup.isNonCompliant(cr.failCount,
						cr.unreadableCount) ? 1.0 : 0.0);
		stats.put("VCF-CF Compliance|no_benchmark", 0.0);

		stitcher.pushProperties(resourceId, props, ts);
		stitcher.pushStats(resourceId, stats, ts);
	}

	/** Per-cycle counters for the completion log line. */
	private static final class CycleStats {
		int hosts; int vms; int dvs; int dvpg; int clusters;
		int noBenchmark; int unreadable;
	}

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
