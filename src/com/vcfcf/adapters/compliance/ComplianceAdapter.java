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
 * adapter failed to read never passes. Since build 63 (owner decision) it
 * counts against the score like a failure (ControlEvaluator.score), is
 * counted separately in unreadable_count, and raises the per-kind
 * "Compliance data not collected" alert; the zero-divisor placeholder of an
 * object with nothing attempted is never pushed or averaged.
 */
public final class ComplianceAdapter extends VcfCfAdapter<ComplianceConfig> {

	private static final String ADAPTER_KIND = "vcfcf_compliance";

	private volatile VSphereClient vsphere;
	private volatile BenchmarkLoader benchmarkLoader;
	private volatile SuiteApiStitcher suiteStitcher;
	private volatile ComplianceStitcher stitcher;

	// Build 59 (review N3): benchmark applied to each object last cycle,
	// used only for the B2 "version unreadable" fallback. Emptied only by a
	// collector restart or an instance edit. See LastBenchmarkMemory.
	private final LastBenchmarkMemory memory = new LastBenchmarkMemory();

	// Build 59 (review W1): objects pushed this cycle with a decided
	// benchmark; cleaned at the end of the cycle from live values.
	private final java.util.List<PendingCleanup> pendingCleanup =
			new java.util.ArrayList<>();

	// Profiles in use this cycle, by name (every bundled profile, plus the
	// overrides file's pins), and this cycle's conf dir.
	private volatile java.util.Map<String, BenchmarkProfile> profilesByName;
	private volatile String cycleConfDir;

	// Build 90: the overrides file (central configuration-file store). The
	// store keeps the last good parse across cycles and instance edits; a
	// changed file name starts from nothing (see OverridesStore).
	private final OverridesStore overridesStore = new OverridesStore();
	private volatile OverridesStore.Snapshot cycleOverridesSnap;
	private volatile ComplianceOverrides.Resolved cycleOverrides =
			ComplianceOverrides.Resolved.EMPTY;
	// Build 92: this cycle's profiles by name BEFORE the overrides file is
	// applied (empty when the file has nothing), so a skipped control in
	// force on an object can be found and pushed every cycle.
	private volatile java.util.Map<String, BenchmarkProfile> cycleUnadjusted =
			java.util.Collections.emptyMap();
	// Build 90 (review N1): Skip and Override entries in force for this
	// instance's own profile set this cycle (Summary|overrides_skipped and
	// overrides_overridden), not every entry accepted against any bundled
	// profile.
	private volatile int cycleSkippedInForce;
	// Build 92 (review N2): the account is stored as the removed Custom
	// profile; zero its retired rollup bucket on the next complete rollup.
	private volatile boolean zeroCustomBucket;
	private volatile int cycleOverriddenInForce;
	// Build 93 (review W1): this instance's vCenter object as resolved by
	// the last cycle that reached vCenter, for marking a later cycle that
	// cannot reach it. Cleared on configure (the host may have changed).
	private volatile String lastVcResourceId;

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
		// Build 93: the Compliance Profile setting is removed (every instance
		// runs Auto (by version)); a stored value is read only for the INFO
		// below and the retired Custom rollup bucket.
		String storedProfile = getIdentifier(resourceConfig,
				ComplianceConfig.RETIRED_PROFILE_KEY);
		// Build 93: Allow Insecure SSL is removed; read only for the WARN.
		String storedAllowInsecure = getIdentifier(resourceConfig,
				ComplianceConfig.RETIRED_ALLOW_INSECURE_KEY);
		String readAppliance = getIdentifier(resourceConfig,
				ComplianceConfig.READ_APPLIANCE_KEY);
		String overridesFile = getIdentifier(resourceConfig,
				ComplianceConfig.OVERRIDES_FILE_KEY);
		String username = getCredentialField(resourceConfig, "username");
		String password = getCredentialField(resourceConfig, "password");

		this.config = new ComplianceConfig(
				vcenterHost, username, password,
				readAppliance, overridesFile);
		this.lastVcResourceId = null;
		boolean storedAsCustom = ComplianceConfig.isCustomName(storedProfile);
		this.zeroCustomBucket = storedAsCustom;
		String profileNotice =
				ComplianceConfig.retiredProfileNotice(storedProfile);
		if (profileNotice != null) {
			// Build 93: one INFO per configure naming the stored value.
			logInfo(profileNotice);
		}
		String tlsNotice =
				ComplianceConfig.retiredAllowInsecureNotice(storedAllowInsecure);
		if (tlsNotice != null) {
			// Build 93: one WARN per configure; validation is strict.
			logWarn(tlsNotice);
		}

		// Build 95 (issue #23): an instance edit re-runs configure on the
		// same adapter object; the previous vCenter session is logged out
		// and the previous Suite API client closed, so an edit no longer
		// leaves a live session and HTTP pools behind in the collector JVM.
		// Review W4: the new clients are built first, swapped in, and only
		// then are the old ones released, so a cycle still running never
		// sees a null client; its calls already on the old client fail
		// (the closed client does not log in again). (Issue #28: the REST
		// client built here was never used by collection; it is gone. Test
		// Connection builds its own.)
		VSphereClient oldVsphere = this.vsphere;
		SuiteApiStitcher oldSuite = this.suiteStitcher;
		VSphereClient newVsphere = new VSphereClient(
				config.vcenterHost, config.username, config.password,
				sslSocketFactoryFor(config.vcenterHost),
				clientLog(componentLogger(VSphereClient.class)));

		this.benchmarkLoader = new BenchmarkLoader();
		// HOLD (owner decision pending): "Read vCenter appliance settings".
		// Off = the vami_api controls load as manual review for this
		// instance (no score, no per-control alert, not attempted).
		this.benchmarkLoader.setApplianceReads(config.readApplianceSettings);
		// An instance edit re-runs configure (and an upgrade from a build with
		// a fixed Compliance Profile lands here too): forget last cycle's
		// benchmarks so the B2 fallback never reuses a benchmark chosen under
		// the old settings.
		memory.clear();

		// Ambient Suite API stitching — reads maintenanceuser.properties,
		// decrypts via the platform SDK Crypt, targets https://localhost/
		// suite-api as maintenanceAdmin. If the credential file is absent
		// (e.g. a remote collector), create() throws; stitching is then
		// disabled for the cycle and the collect path logs the gap rather
		// than aborting.
		SuiteApiStitcher newSuite = null;
		ComplianceStitcher newStitcher = null;
		try {
			newSuite = SuiteApiStitcher.create(
					this, componentLogger(SuiteApiStitcher.class));
			newStitcher = new ComplianceStitcher(newSuite,
					componentLogger(ComplianceStitcher.class));
		} catch (RuntimeException e) {
			newSuite = null;
			newStitcher = null;
			logWarn("Ambient Suite API stitcher unavailable: compliance data "
					+ "will not be pushed onto VMWARE resources this instance: "
					+ e.getMessage());
		}
		// Review W4: swap, then release the previous clients.
		this.vsphere = newVsphere;
		this.suiteStitcher = newSuite;
		this.stitcher = newStitcher;
		releaseClients(oldVsphere, oldSuite);

		logInfo("ComplianceAdapter configured: vcenter=" + config.vcenterHost
				+ " profile=" + BenchmarkSelector.AUTO
				+ " readApplianceSettings=" + config.readApplianceSettings
				+ " overridesFile="
				+ (config.overridesFile.isEmpty() ? "(none)"
						: config.overridesFile)
				+ " stitcher=" + (stitcher != null));
	}

	/**
	 * The TLS context for every vCenter client (REST session and
	 * inventory, VAMI appliance API, Test Connection, and through
	 * {@link #sslSocketFactoryFor} the vim25 SOAP walk and esxcli): the
	 * PLATFORM trust manager, which trusts the VCF Operations trust store
	 * plus the certificates accepted on this instance through Validate
	 * Connection, wrapped by {@link VCenterCertificates#nameChecking} so the
	 * certificate must also carry the name vCenter is entered by (build 93,
	 * review B1: the platform trust manager checks the chain only). Null
	 * (JDK default trust, which checks the name itself) only when no
	 * platform trust manager is available, never trust-all.
	 *
	 * <p>Build 94: {@code dialledHost} is the host the client built on this
	 * context connects to (the account's vCenter Host / IP as the client
	 * uses it); the certificate is matched against it, not against the
	 * peer host the TLS provider reports (none under BouncyCastle JSSE on
	 * 9.1.1 collectors).
	 */
	private javax.net.ssl.SSLContext sslContextFor(String dialledHost) {
		try {
			return VCenterCertificates.nameChecking(getAdapterTrustManager(),
					getKeyManagers(), dialledHost);
		} catch (RuntimeException e) {
			logWarn("Platform trust manager unavailable for the vCenter "
					+ "clients; using the JDK default trust store: "
					+ e.getMessage());
			return null;
		}
	}

	/**
	 * The SSL socket factory for the raw-SOAP {@link VSphereClient}
	 * connection (and its per-cycle {@link EsxcliSoapClient}): the factory
	 * of {@link #sslContextFor}, so the vim25 walk validates the vCenter
	 * certificate, chain and name, exactly as the REST clients do. Both
	 * SOAP clients also set {@link VCenterCertificates#strictHostnameVerifier}
	 * through {@link VCenterCertificates#secure}. If no platform trust
	 * manager can be obtained the JDK default factory is used, never
	 * trust-all.
	 */
	private javax.net.ssl.SSLSocketFactory sslSocketFactoryFor(
			String dialledHost) {
		javax.net.ssl.SSLContext ctx = sslContextFor(dialledHost);
		if (ctx != null) {
			return ctx.getSocketFactory();
		}
		logWarn("Platform trust manager unavailable: using the JDK default "
				+ "trust store for the vCenter SOAP connection.");
		return (javax.net.ssl.SSLSocketFactory)
				javax.net.ssl.SSLSocketFactory.getDefault();
	}

	// -----------------------------------------------------------------------
	// certificateCheckUrls (framework hook, build 93)
	// -----------------------------------------------------------------------

	/**
	 * Build 93: the vCenter endpoint VCF Operations reviews on Validate
	 * Connection, so an untrusted certificate brings up the Review and
	 * Accept Certificate dialog instead of failing. Derived only from the
	 * passed (possibly unsaved) config, never from instance state; see
	 * {@link VCenterCertificates#checkUrls}. {@code @Override} on purpose:
	 * a buildkit older than 1.0.11 has no such hook and must fail to
	 * compile rather than build a pak that never offers the dialog.
	 */
	@Override
	protected List<String> certificateCheckUrls(ResourceConfig rc) {
		return VCenterCertificates.checkUrls(
				getIdentifier(rc, "vcenter_host"));
	}

	// -----------------------------------------------------------------------
	// getTester
	// -----------------------------------------------------------------------

	@Override
	protected VcfCfTester<ComplianceConfig> getTester() {
		// Build 46 onTest NPE fix: the controller invokes Test-connection on a
		// FRESH instance — onConfigure (configureAdapter) has NOT run, so the
		// instance fields (this.config and the clients) are still null. The base's
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
			String username = getCredentialField(rc, "username");
			String password = getCredentialField(rc, "password");

			ComplianceConfig testCfg = new ComplianceConfig(
					vcenterHost, username, password,
					null, null);

			VCenterApiClient testApi = new VCenterApiClient(
					testCfg.baseUrl(), testCfg.username, testCfg.password,
					sslContextFor(testCfg.vcenterHost));
			try {
				testApi.login();
			} catch (Exception e) {
				VCenterCertificates.Failure f = VCenterCertificates.classify(e);
				if (f == null) throw e;
				// Build 93: rethrow WITHOUT the cause. The framework's final
				// onTest replaces the text of any failure whose cause chain
				// shows a trust problem with its generic message, which offers
				// the removed Allow Insecure SSL setting. The original is
				// logged here instead.
				logWarn("Test Connection: vCenter certificate problem ("
						+ f + "): " + e, e);
				throw new Exception(VCenterCertificates.message(f,
						vcenterHost) + " (" + e.getClass().getSimpleName()
						+ ")");
			}
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

	/**
	 * Build 95: the platform logger as the SDK-free {@link VSphereClient.Log}
	 * (null stays null: the client then logs nothing).
	 */
	private static VSphereClient.Log clientLog(
			final com.integrien.alive.common.adapter3.Logger l) {
		if (l == null) return null;
		return new VSphereClient.Log() {
			@Override public void info(String m) { l.info(m); }
			@Override public void debug(String m) { l.debug(m); }
			@Override public void warn(String m) { l.warn(m); }
			@Override public boolean isDebugEnabled() {
				return l.isDebugEnabled();
			}
		};
	}

	/**
	 * Build 95 (bulk-collection design build B): the internal switch for the
	 * bulk-read shadow comparison. On: after each kind is scored the
	 * per-object way, the same objects are read in paged bulk calls,
	 * evaluated locally and compared, and the differences logged. Scores,
	 * pushes and alerts still come only from the per-object path. Not a
	 * user setting. Review W5: the one switch for shadow mode; off, no
	 * kind records per-object outcomes (no memory held) and no bulk read
	 * is made. Whether a release ships with it on is Scott's decision;
	 * the default stays on until then.
	 */
	static final boolean BULK_SHADOW = true;

	/**
	 * Build 95: objects per bulk page. Hosts small (each carries its whole
	 * config.option list, about a thousand settings), VMs larger, the
	 * low-count kinds in between. Review W5: VMs 50 (was 200): a VM page
	 * carries config.hardware and config.extraConfig, and the DOM is
	 * several times the bytes read, in the collector JVM every adapter
	 * shares; the shadow summary now logs the page bytes to size it.
	 */
	static int bulkPageSize(String type) {
		switch (type) {
			case "HostSystem": return 10;
			case "VirtualMachine": return 50;
			case "ClusterComputeResource": return 50;
			default: return 100;
		}
	}

	/**
	 * Build 95 (issue #16, first slice): checked before every object in
	 * every per-object loop, so Stop Collecting abandons the cycle within
	 * one object instead of waiting for the whole vCenter walk.
	 */
	private final StopCheck stop = StopCheck.orInterrupted(
			this::isAbortRequested);

	// Build 95 (issue #17): this cycle's measurement (phases and calls).
	private volatile CycleMetrics cycleMetrics;

	private CycleMetrics.Scope phase(CycleMetrics.Phase p) {
		return CycleMetrics.scope(cycleMetrics, p);
	}

	private void countSuiteCall() {
		CycleMetrics m = cycleMetrics;
		if (m != null) m.suiteCall();
	}

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
	 * there is last-writer-wins across vCenters. The only key this adapter
	 * pushes there is {@code Summary|last_scan_timestamp} (adapter liveness:
	 * the last scan by any instance). Fleet numbers live in the per-vCenter
	 * rollup ({@link ComplianceRollup}) on each {@code VMwareAdapter
	 * Instance}; the environment totals ({@code Rollup|Environment|*}, build
	 * 82) are ComputedMetrics the engine sums across those children.
	 *
	 * <p>Build 86: the cycle's duration is logged from a {@code finally}, so
	 * a cycle that ends in an exception (where the time usually goes) still
	 * reports it. Monotonic clock ({@code System.nanoTime}).
	 */
	private void collectWorld(ResourceConfig worldRc, List<MetricData> out)
			throws Exception {
		long cycleStartNs = System.nanoTime();
		boolean completed = false;
		String abandonedAt = null;
		// Build 95 (issue #17): per-phase time and call counts for the
		// summary line; measurement only.
		CycleMetrics metrics = new CycleMetrics();
		cycleMetrics = metrics;
		if (vsphere != null) vsphere.setMetrics(metrics);
		if (stitcher != null) stitcher.setMetrics(metrics);
		try {
			collectWorldCycle(worldRc, out);
			completed = true;
		} catch (InterruptedException e) {
			// Build 95 (issue #16): one line saying the cycle was abandoned,
			// where, and what that leaves behind; review N4: with the
			// timing summary, and no second "failed" line.
			abandonedAt = String.valueOf(e.getMessage());
			throw e;
		} finally {
			if (vsphere != null) vsphere.setMetrics(null);
			if (stitcher != null) stitcher.setMetrics(null);
			cycleMetrics = null;
			long ms = (System.nanoTime() - cycleStartNs) / 1_000_000L;
			String line = ComplianceDecisions.cycleEndLine(completed,
					abandonedAt, ms,
					abandonedAt != null ? metrics.summary() : null);
			if (completed) {
				logInfo(line);
			} else {
				logWarn(line);
			}
		}
	}

	/**
	 * Build 93: {@code vsphere.ensureConnected()}, with a certificate the
	 * instance does not trust (or one issued for another name) turned into
	 * the admin-facing instruction (open the account and Validate
	 * Connection; enter vCenter by the name on its certificate). The cause
	 * is kept for the log; any other failure is rethrown unchanged.
	 */
	private void ensureVCenterConnected() throws Exception {
		try {
			vsphere.ensureConnected();
		} catch (Exception e) {
			VCenterCertificates.Failure f = VCenterCertificates.classify(e);
			if (f == null) throw e;
			throw new Exception(VCenterCertificates.message(f,
					config.vcenterHost), e);
		}
	}

	/**
	 * Build 93 (review W1): the cycle could not reach vCenter (connect,
	 * login or certificate failure), so nothing was read. Push
	 * {@code Rollup|incomplete} = 1 on this instance's vCenter object, which
	 * raises "Compliance data not collected (vCenter)", instead of leaving
	 * the last scores showing as current with no signal. Best effort: any
	 * failure here is logged and the cycle's own exception is what the
	 * caller rethrows.
	 */
	private void markCycleNotCollected(Exception cause) {
		ComplianceStitcher st = stitcher;
		if (st == null) {
			logWarn("vCenter " + config.vcenterHost + " not reached this "
					+ "cycle and no Suite API stitcher: Rollup|incomplete "
					+ "cannot be pushed; the last scores stay in place");
			return;
		}
		try {
			String id = ComplianceDecisions.markNotCollected(lastVcResourceId,
					() -> {
						st.loadVCenterAdapterInstance();
						ComplianceStitcher.HostEntry he =
								st.matchVCenterAdapterInstance(
										config.vcenterHost, null);
						return he == null ? null : he.resourceId;
					},
					(rid, stats) -> st.pushStats(rid, stats,
							System.currentTimeMillis()));
			if (id == null) {
				logWarn("vCenter " + config.vcenterHost + " not reached this "
						+ "cycle (" + cause.getClass().getSimpleName() + "), "
						+ "and its VMwareAdapter Instance could not be "
						+ "resolved without vCenter (no VCURL equal to the "
						+ "entered host): Rollup|incomplete is NOT pushed; "
						+ "the last scores stay in place");
			} else {
				logWarn("vCenter " + config.vcenterHost + " not reached this "
						+ "cycle (" + cause.getClass().getSimpleName() + "): "
						+ ComplianceRollup.INCOMPLETE_KEY + " = 1 pushed to "
						+ "resource " + id + "; the compliance values shown "
						+ "are from the last completed cycle");
			}
		} catch (RuntimeException e) {
			logWarn("vCenter " + config.vcenterHost + " not reached this "
					+ "cycle, and pushing Rollup|incomplete failed: " + e);
		}
	}

	/** The cycle body; {@link #collectWorld} times it. */
	private void collectWorldCycle(ResourceConfig worldRc,
			List<MetricData> out) throws Exception {
		try {
			ensureVCenterConnected();
		} catch (InterruptedException e) {
			throw e;   // cancelled: no more network calls this cycle
		} catch (Exception e) {
			markCycleNotCollected(e);
			throw e;
		}
		// Build 85: fresh esxcli reads every cycle. The esxcli cache lived as
		// long as the vCenter session, so a stale result (pass or failure)
		// could be served cycle after cycle; a stale pass is a false pass.
		vsphere.beginCycle();

		Path confDir = getAdapterDescribeFile(ADAPTER_KIND, "describe.xml")
				.getParent();   // <adaptersHome>/<kind>/conf
		cycleConfDir = confDir.toString();
		cycleReasons = new UnreadableReasons();
		// Build 90: the overrides file, fetched once per cycle (no fetch when
		// the setting is empty), applied while the selector is built.
		cycleOverridesSnap = refreshOverrides();
		BenchmarkSelector selector = buildSelector(cycleConfDir,
				cycleOverridesSnap.parsed);
		pendingCleanup.clear();

		logInfo("stitcher=" + (stitcher != null));
		if (stitcher != null) {
			try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
				loadStitcherResources();
			}
		}

		String vcVersion = null;
		try {
			vcVersion = vsphere.getVCenterVersion();
		} catch (Exception e) {
			logWarn("Could not read the vCenter version: " + e.getMessage());
		}
		logInfo("Auto (by version): vCenter version=" + vcVersion
				+ " governs vCenter / cluster / vDS / portgroup benchmark "
				+ "choice");

		ComplianceRollup rollup = new ComplianceRollup();
		CycleStats cs = new CycleStats();
		java.util.Set<String> seen = new java.util.HashSet<>();

		java.util.Map<String, String> hostVersions;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.HOSTS)) {
			hostVersions = collectHosts(selector, rollup, cs, seen);
		}
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.VMS)) {
			collectVms(selector, hostVersions, rollup, cs, seen);
		}
		ComplianceStitcher.HostEntry vcEntry;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.VCENTER)) {
			vcEntry = collectVCenter(selector, vcVersion, rollup, cs, seen);
		}
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.NETWORK)) {
			collectDvs(selector, vcVersion, rollup, cs, seen);
			collectDvpg(selector, vcVersion, rollup, cs, seen);
			collectClusters(selector, vcVersion, rollup, cs, seen);
		}

		// Forget applied-profile history for objects no longer in inventory.
		memory.retain(seen);
		if (cs.skipPushedKeys > 0) {
			// Build 92: the skipped controls are pushed every cycle, so the
			// symptom on each key sees its cancel cycles.
			logInfo("Overrides file '" + config.overridesFile + "': "
					+ cs.skipPushedKeys + " skipped control key(s) set to -1 "
					+ "(not evaluated) on " + cs.skipPushedObjects
					+ " object(s) this cycle");
		}
		cleanStaleControls(cs);
		if (cycleReasons.total() > 0) {
			// Build 74: why controls were unreadable, once per cycle (the
			// per-control detail is at DEBUG).
			logInfo("Unreadable controls this cycle by reason: "
					+ cycleReasons.summary());
		}

		// Build 88: one INFO line per kind naming objects with no matching
		// VCF Ops resource (Rollup|<K>|unmatched; first 20 named).
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			String line = rollup.unmatchedLogLine(k);
			if (line != null) {
				logInfo(line);
			}
		}

		if (vcEntry != null) {
			lastVcResourceId = vcEntry.resourceId;
		}
		pushRollup(vcEntry, rollup);
		pushOverridesStatus(vcEntry, out);
		// Known limitation: this edge is added, never removed. A vCenter whose
		// compliance instance is deleted stays a ComplianceWorld child. See
		// knowledge/designs/sdk-adapters/compliance-environment-computed-metrics.md
		linkVCenterToWorld(vcEntry);

		if (cs.unreadable > 0) {
			logWarn(cs.unreadable + " control instance(s) could not be read "
					+ "this cycle (declared-but-unreadable). They count as "
					+ "failing in each object's score, each affected object "
					+ "is non-compliant, and its \"Compliance data not "
					+ "collected\" alert fires.");
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
				+ cs.noBenchmark + " object(s) without a benchmark, "
				+ cs.versionUnreadable + " with an unreadable version, "
				+ unmatchedTotal(rollup) + " with no VCF Ops resource (not "
				+ "scored), " + rollup.skippedPods() + " vSphere Pod VM(s) "
				+ "skipped, "
				+ cs.cleanedKeys + " stale per-control key(s) marked "
				+ "not evaluated on " + cs.cleanedObjects + " object(s)"
				+ (cycleMetrics != null ? "; " + cycleMetrics.summary() : ""));
	}

	private static int unmatchedTotal(ComplianceRollup rollup) {
		int n = 0;
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			n += rollup.unmatched(k);
		}
		return n;
	}

	/**
	 * Build the per-cycle benchmark selector: {@code Auto (by version)} over
	 * every bundled profile (loaded once, cached by the loader), selecting
	 * per object. Build 93: Auto is the only mode.
	 *
	 * <p>Build 90: the overrides file ({@code parsed}, null for none) is
	 * applied on top: skipped controls are removed from every loaded
	 * profile, overridden expected values replace the SCG values, and
	 * Profile pins replace Auto for the kinds they cover (a pin without
	 * kind covers every kind; a kind pin wins over it). The manual-review
	 * overlay keeps working underneath. The result is kept in
	 * {@link #cycleOverrides} for the push, the cleanup and the status keys.
	 */
	private BenchmarkSelector buildSelector(String confDir,
			ComplianceOverrides.Parsed parsed) {
		java.util.Map<String, BenchmarkProfile> baseProfiles =
				benchmarkLoader.loadAll(confDir);
		logInfo("Benchmark mode: " + BenchmarkSelector.AUTO + " ("
				+ baseProfiles.size() + " bundled profiles loaded; "
				+ benchmarkLoader.lastManualReviewApplied()
				+ " controls set to manual review (prose expected values, standard-switch controls))");
		BenchmarkSelector base = BenchmarkSelector.auto(baseProfiles);
		if (parsed == null || parsed.isEmpty()) {
			cycleUnadjusted = java.util.Collections.emptyMap();
			cycleOverrides = ComplianceOverrides.Resolved.EMPTY;
			cycleSkippedInForce = 0;
			cycleOverriddenInForce = 0;
			profilesByName = baseProfiles;
			return base;
		}

		// Every profile the file can name: all bundled ones (cached), which
		// since build 93 are also the instance's own.
		java.util.Map<String, BenchmarkProfile> bundled = baseProfiles;
		java.util.Map<String, BenchmarkProfile> known =
				new java.util.LinkedHashMap<>(bundled);
		ComplianceOverrides.Resolved r =
				ComplianceOverrides.resolve(parsed, known.values());
		cycleOverrides = r;
		cycleUnadjusted = java.util.Collections.unmodifiableMap(known);
		java.util.Map<BenchmarkSelector.Kind, BenchmarkProfile> rawPins =
				r.pins(bundled);
		cycleSkippedInForce =
				r.skippedIn(baseProfiles.values(), rawPins).size();
		cycleOverriddenInForce =
				r.overriddenIn(baseProfiles.values(), rawPins).size();

		java.util.Map<String, BenchmarkProfile> effBase = r.adjust(baseProfiles);
		java.util.Map<String, BenchmarkProfile> effBundled = r.adjust(bundled);
		BenchmarkSelector selector = BenchmarkSelector.auto(effBase);
		java.util.Map<BenchmarkSelector.Kind, BenchmarkProfile> pins =
				r.pins(effBundled);
		selector = selector.withPins(pins);

		// Profiles a decision may name this cycle (the B2 fallback looks the
		// previous benchmark up here): every bundled one, plus every pin.
		java.util.Map<String, BenchmarkProfile> byName =
				new java.util.LinkedHashMap<>(effBase);
		for (BenchmarkProfile p : pins.values()) byName.put(p.name, p);
		profilesByName = byName;
		return selector;
	}

	/**
	 * Build 90: fetch this cycle's overrides file through the Suite API
	 * channel (none when the setting is empty) and log what happened. Never
	 * throws: every failure is a status.
	 */
	private OverridesStore.Snapshot refreshOverrides() {
		final SuiteApiStitcher sas = suiteStitcher;
		OverridesStore.Fetcher fetcher = sas == null ? null : path -> {
			countSuiteCall();
			return sas.get(path);
		};
		OverridesStore.Snapshot snap = overridesStore.refresh(
				config.overridesFile, fetcher, Instant.now());
		switch (snap.status) {
			case ABSENT:
				logWarn("Overrides file '" + snap.fileName + "' not loaded: "
						+ snap.detail + ". Running with no overrides (the "
						+ "guide's values only). Copy "
						+ "compliance_overrides_template in Infrastructure "
						+ "Operations > Configurations > Management Packs "
						+ "Configuration and save the copy under this name "
						+ "plus .xml (it lands in User Defined), or correct the "
						+ "instance's Overrides file setting.");
				break;
			case PARSE_FAILED:
				logWarn("Overrides file '" + snap.fileName + "' could not be "
						+ "parsed: " + snap.detail + ". "
						+ (snap.parsed != null
								? "Keeping the copy read at "
										+ OverridesStore.formatTime(
												snap.lastGood,
												java.time.ZoneId.systemDefault())
								: "No earlier copy to keep: running with no "
										+ "overrides")
						+ ".");
				break;
			case FETCH_FAILED:
				logWarn("Overrides file '" + snap.fileName + "' could not be "
						+ "fetched this cycle (" + snap.fetchReason + ", "
						+ snap.fetchFailures + " cycle"
						+ (snap.fetchFailures == 1 ? "" : "s")
						+ " in a row): " + snap.detail + ". "
						+ (snap.parsed != null
								? "Keeping the copy read at "
										+ OverridesStore.formatTime(
												snap.lastGood,
												java.time.ZoneId.systemDefault())
								: "No earlier copy to keep: running with no "
										+ "overrides")
						+ (snap.notLoaded()
								? "; the overrides-not-loaded alert is raised"
								: "")
						+ ".");
				break;
			default:
				break;
		}
		return snap;
	}

	/**
	 * Build 90: report the overrides file. One INFO line listing the
	 * applied entries, one WARN per rejected entry, then the status keys on
	 * the Compliance World (shared by every instance, so it shows the last
	 * instance to collect) and on this instance's vCenter object. Pushed
	 * every cycle, "none" and zeros included.
	 */
	private void pushOverridesStatus(ComplianceStitcher.HostEntry vcEntry,
			List<MetricData> out) {
		OverridesStore.Snapshot snap = cycleOverridesSnap;
		if (snap == null) return;
		ComplianceOverrides.Resolved r = cycleOverrides;
		if (snap.parsed != null) {
			logInfo("Overrides file '" + snap.fileName + "': "
					+ (r.applied.isEmpty() ? "no entries applied"
							: r.applied.size() + " entr"
									+ (r.applied.size() == 1 ? "y" : "ies")
									+ " applied: "
									+ String.join("; ", r.applied))
					+ (r.changesProfiles()
							? " (in force for this instance's profiles: "
									+ cycleSkippedInForce + " skipped, "
									+ cycleOverriddenInForce + " overridden)"
							: "")
					+ (r.rejected.isEmpty() ? ""
							: " (" + r.rejected.size() + " rejected, see the "
									+ "WARN lines)"));
			for (String rej : r.rejected) {
				logWarn("Overrides file '" + snap.fileName + "': rejected "
						+ rej);
			}
		}
		String status = snap.statusText(r.rejected.size(),
				java.time.ZoneId.systemDefault());
		int skipped = cycleSkippedInForce;
		int overridden = cycleOverriddenInForce;
		boolean notLoaded = snap.notLoaded();

		long ts = System.currentTimeMillis();
		for (java.util.Map.Entry<String, String> e : ComplianceDecisions
				.overridesProps("", snap.fileName, status).entrySet()) {
			pushWorldProperty(out, e.getKey(), e.getValue());
		}
		for (java.util.Map.Entry<String, Double> e : ComplianceDecisions
				.overridesStats("", skipped, overridden, notLoaded).entrySet()) {
			out.add(new MetricData(new MetricKey(false, e.getKey()), ts,
					e.getValue()));
		}
		if (stitcher != null && vcEntry != null) {
			stitcher.pushProperties(vcEntry.resourceId,
					ComplianceDecisions.overridesProps(ComplianceDecisions.K,
							snap.fileName, status), ts);
			stitcher.pushStats(vcEntry.resourceId,
					ComplianceDecisions.overridesStats(ComplianceDecisions.K,
							skipped, overridden, notLoaded), ts);
		}
	}

	/** Build 90: control ids whose expected value is a site override. */
	private java.util.Set<String> siteOverriddenFor(String profileName) {
		java.util.Map<String, BenchmarkProfile> m = profilesByName;
		BenchmarkProfile p = m == null || profileName == null ? null
				: m.get(profileName);
		return p == null ? java.util.Collections.<String>emptySet()
				: p.siteOverriddenIds();
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
		boolean zeroedCustom = zeroCustomBucket
				&& ComplianceRollup.zeroRetiredCustom(stats);
		if (!rollup.incompleteKinds().isEmpty()) {
			logWarn("Inventory listing failed this cycle for "
					+ rollup.incompleteKinds() + " (the vCenter listing, or "
					+ "since build 88 the VCF Ops resource list for the kind; "
					+ "see the WARN above): their Rollup keys, and the "
					+ "cross-kind Rollup|All and Rollup|Benchmark keys, are NOT "
					+ "pushed this cycle (previous values kept rather than "
					+ "under-counted)");
		}
		stitcher.pushStats(vcEntry.resourceId, stats,
				System.currentTimeMillis());
		if (zeroedCustom) {
			zeroCustomBucket = false;
			logInfo("Account stored as Custom: "
					+ ComplianceRollup.RETIRED_CUSTOM_KEY + " set to 0 once");
		}
		logInfo("Pushed " + stats.size() + " rollup stat(s) to vCenter "
				+ vcEntry.hostName + " (resource=" + vcEntry.resourceId + ")");
	}

	/**
	 * Build 82: assert ComplianceWorld (parent) to this instance's own
	 * VMwareAdapter Instance (child), so the ComplianceWorld
	 * {@code Rollup|Environment} ComputedMetrics have children to walk.
	 * Additive Suite API POST through {@link SuiteApiStitcher#addChild},
	 * re-asserted every cycle; never the RelationshipBuilder /
	 * setRelationships route (a full set from one instance would replace
	 * the links every other instance added). Never fails the cycle.
	 *
	 * <p>Known limitation: nothing removes this edge. A vCenter whose
	 * compliance instance is deleted stays a ComplianceWorld child, and the
	 * environment totals keep summing its last Rollup|All values. See
	 * knowledge/designs/sdk-adapters/compliance-environment-computed-metrics.md
	 * (Vision item 2) in the factory repo.
	 */
	private void linkVCenterToWorld(ComplianceStitcher.HostEntry vcEntry) {
		SuiteApiStitcher sas = suiteStitcher;
		if (sas == null) {
			return;   // configureAdapter already logged the missing stitcher
		}
		// Build 83 (review of build 82, W2): the ComplianceWorld id is looked
		// up every cycle (one local GET) and never cached, because an
		// accepted add to a deleted world's id would never clear a cache.
		ComplianceDecisions.WorldLink link = ComplianceDecisions.linkWorld(
				vcEntry == null ? null : vcEntry.resourceId,
				() -> {
					countSuiteCall();
					return sas.findSingletonResourceId(ADAPTER_KIND,
							"ComplianceWorld");
				},
				(parent, child) -> {
					countSuiteCall();
					return sas.addChild(parent, child);
				});
		switch (link.outcome) {
			case ACCEPTED:
				// Asynchronous on the platform side: accepted, not proven.
				logInfo("Link of vCenter " + vcEntry.hostName + " (resource="
						+ vcEntry.resourceId + ") under ComplianceWorld "
						+ "(resource=" + link.worldId + ") requested and "
						+ "accepted by Suite API");
				break;
			case NO_VCENTER:
				// DEBUG: the unresolved vCenter is already reported at WARN
				// by the stitcher, collectVCenter and pushRollup this cycle.
				logDebug("vCenter " + config.vcenterHost + " is NOT linked "
						+ "under ComplianceWorld this cycle: its VMwareAdapter "
						+ "Instance was not resolved, so the environment "
						+ "totals do not include it");
				break;
			case NO_WORLD:
				// Build 85 (review of build 84, N1): the lookup returns null
				// for zero matches, several matches, a partial page and a
				// failed query alike, so this line cannot say which. The
				// framework logs the cause in the WARN just before it.
				logWarn("vCenter " + vcEntry.hostName + " is NOT linked under "
						+ "ComplianceWorld this cycle: no single "
						+ "ComplianceWorld resource was found or the lookup "
						+ "could not be queried (see the preceding "
						+ "SuiteApiStitchClient findSingletonResourceId WARN "
						+ "for the cause; zero matches is normal only on the "
						+ "first cycle); retried next cycle");
				break;
			default:   // ADD_FAILED
				// One line, no stack trace (the cause is in the stitcher's
				// own WARN just before this one).
				logWarn("vCenter " + vcEntry.hostName + " is NOT linked under "
						+ "ComplianceWorld this cycle: the relationship add "
						+ "to resource " + link.worldId + " was not accepted; "
						+ "retried next cycle");
				break;
		}
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

	// ----- Per-object decision plumbing (build 58) ------------------------

	/**
	 * Benchmark decision for one object: {@link ComplianceDecisions#decide}
	 * with the object's benchmark from last cycle, so an unreadable version
	 * reuses it instead of dropping the object (review B2).
	 */
	private ComplianceDecisions.Decision decide(BenchmarkSelector selector,
			BenchmarkSelector.Kind kind, String moid, String version) {
		String key = moid == null ? null
				: LastBenchmarkMemory.key(kind, moid);
		ComplianceDecisions.Decision d = ComplianceDecisions.decide(selector,
				kind, version, memory.previous(key), profilesByName);
		if (d.reusedPrevious) {
			logWarn(kind.rollupName + " " + moid + ": governing "
					+ kind.product + " version unreadable this cycle; scoring "
					+ "against last cycle's benchmark " + d.profileName);
		}
		return d;
	}

	/**
	 * Version unreadable and no previous benchmark (review B2; build 65 W1):
	 * nothing collected. Score 0 (build 63 rule), non-compliant,
	 * collection_failed = 1 (raises "Compliance data not collected"),
	 * counted as scored 0 in the rollup's unknown bucket, never
	 * no_benchmark, no alert cleanup, benchmark memory untouched.
	 */
	private void recordVersionUnreadable(BenchmarkSelector.Kind kind,
			String name, ComplianceDecisions.Decision d, String resourceId,
			ComplianceRollup rollup, CycleStats cs) {
		cs.versionUnreadable++;
		rollup.recordVersionUnreadable(kind);
		logWarn(kind.rollupName + " " + name + ": " + d.profileName
				+ " and no previous benchmark; nothing collected: score 0, "
				+ "non-compliant, collection_failed=1");
		if (resourceId != null) {
			long ts = System.currentTimeMillis();
			stitcher.pushProperties(resourceId,
					ComplianceDecisions.profileNameProps(d.profileName), ts);
			stitcher.pushStats(resourceId,
					ComplianceDecisions.versionUnreadableStats(), ts);
		}
	}

	/** Record + push an object whose READABLE version has no benchmark. */
	private void recordNoBenchmark(BenchmarkSelector.Kind kind, String name,
			String moid, ComplianceDecisions.Decision d, String resourceId,
			ComplianceRollup rollup, CycleStats cs) {
		cs.noBenchmark++;
		rollup.recordNoBenchmark(kind);
		logInfo(kind.rollupName + " " + name + ": " + d.profileName
				+ " (no benchmark, not scored)");
		if (resourceId != null) {
			pushNoBenchmark(resourceId, d.profileName);
		}
		afterPush(kind, moid, d, resourceId, cs,
				java.util.Collections.<String>emptySet(), null);
	}

	/**
	 * After an object with a decided benchmark (scored, or no benchmark):
	 * remember the benchmark for the B2 fallback, and queue the object for
	 * this cycle's stale-control cleanup when it was pushed.
	 *
	 * @param skip the skipped controls in force that went out in this
	 *             object's push ({@link #skipInForce}); null or empty: none.
	 *             They join the live set, so the cleanup leaves them alone.
	 */
	private void afterPush(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d, String resourceId, CycleStats cs,
			java.util.Set<String> pushed, ComplianceDecisions.SkipPush skip) {
		if (moid == null) return;
		String prev = memory.record(LastBenchmarkMemory.key(kind, moid),
				d.profileName);
		if (prev != null && !prev.equals(d.profileName)) {
			logInfo(kind.rollupName + " " + moid + ": benchmark changed '"
					+ prev + "' -> '" + d.profileName + "'");
		}
		if (resourceId != null && stitcher != null) {
			java.util.Set<String> live = pushed;
			if (skip != null && !skip.isEmpty()) {
				cs.skipPushedObjects++;
				cs.skipPushedKeys += skip.ids.size();
				live = new java.util.TreeSet<>(pushed);
				live.addAll(skip.ids);
			}
			pendingCleanup.add(new PendingCleanup(kind, resourceId, d.profile,
					d.profileName, live));
		}
	}

	/**
	 * Build 92 (adapter issue #41): Compliant = -1 and the skip Actual text
	 * for every skipped control in force on this object, sent EVERY cycle
	 * while the Skip is in the file ({@link ComplianceDecisions#skipPush}).
	 * One -1 sample was not enough: the per-control symptom needs its cancel
	 * cycles of fresh non-triggering samples before the alert cancels.
	 * Removing the Skip empties this and the control is scored again on the
	 * same cycle. Review W3: the result is merged into the object's own
	 * push ({@link ComplianceDecisions#pushObject}), never a separate call.
	 */
	private ComplianceDecisions.SkipPush skipInForce(
			BenchmarkSelector.Kind kind, ComplianceDecisions.Decision d) {
		ComplianceOverrides.Resolved r = cycleOverrides;
		if (d.profile == null || r == null || r.skipped.isEmpty()) {
			return null;
		}
		return ComplianceDecisions.skipPush(kind,
				cycleUnadjusted.get(d.profileName), r.skipped,
				config.overridesFile);
	}

	/** One object queued for end-of-cycle cleanup. */
	private static final class PendingCleanup {
		final BenchmarkSelector.Kind kind;
		final String resourceId;
		final BenchmarkProfile profile;   // null: no benchmark
		final String profileName;
		// Build 76: control ids whose Compliant value was pushed this cycle.
		final java.util.Set<String> pushed;

		PendingCleanup(BenchmarkSelector.Kind kind, String resourceId,
				BenchmarkProfile profile, String profileName,
				java.util.Set<String> pushed) {
			this.kind = kind;
			this.resourceId = resourceId;
			this.profile = profile;
			this.profileName = profileName;
			this.pushed = pushed;
		}
	}

	/**
	 * Build 59 (review W1 on build 58): per-control cleanup from LIVE values,
	 * every cycle. For each pushed object, the candidates are the bundled
	 * controls outside its current benchmark
	 * ({@link ComplianceDecisions#candidateControlIds}); their latest
	 * {@code Compliant} values are bulk-read from VCF Ops (requests sized by
	 * URL length, see ComplianceDecisions#latestCompliantPaths), and only a candidate whose latest value is 0 is set to -1
	 * ({@link ComplianceDecisions#staleZeroControls}). No key is ever
	 * created, a cleaned key is not touched again, and a missed or failed
	 * cleanup is retried next cycle. If a bulk read fails, that batch is
	 * skipped this cycle (logged), with no fallback.
	 */
	private void cleanStaleControls(CycleStats cs) throws InterruptedException {
		if (stitcher == null || pendingCleanup.isEmpty()) return;
		java.util.Map<String, BenchmarkProfile> bundled = bundledForCleanup();
		if (bundled == null) return;
		java.util.Map<BenchmarkSelector.Kind, java.util.List<PendingCleanup>>
				byKind = new java.util.EnumMap<>(BenchmarkSelector.Kind.class);
		for (PendingCleanup p : pendingCleanup) {
			byKind.computeIfAbsent(p.kind, k -> new java.util.ArrayList<>())
					.add(p);
		}
		for (java.util.Map.Entry<BenchmarkSelector.Kind,
				java.util.List<PendingCleanup>> e : byKind.entrySet()) {
			java.util.List<PendingCleanup> objs = e.getValue();
			for (int i = 0; i < objs.size(); i += CLEANUP_BATCH) {
				stop.check("per-control cleanup of " + e.getKey().rollupName
						+ " objects " + i + "+");
				cleanBatch(e.getKey(), objs.subList(i,
						Math.min(objs.size(), i + CLEANUP_BATCH)),
						bundled.values(), cs);
			}
		}
		pendingCleanup.clear();
		// Build 60 (review W1): one line per cycle with what the read
		// returned, so a read that silently returns nothing is visible and
		// not mistaken for "nothing stale".
		logInfo("Stale-control cleanup read: " + cs.cleanupQueried
				+ " object(s) with candidate controls queried in "
				+ cs.cleanupRequests + " request(s); " + cs.cleanupValues
				+ " Compliant value(s) returned; " + cs.cleanedKeys
				+ " stale 0(s) set to -1 on " + cs.cleanedObjects
				+ " object(s); " + cs.cleanupSkipped
				+ " object(s) skipped (read failed)");
		if (cs.cleanupSkipped > 0) {
			logWarn("Stale-control cleanup skipped for " + cs.cleanupSkipped
					+ " object(s) this cycle (latest-value read failed); "
					+ "retrying next cycle");
		}
	}

	// Objects per cleanup batch; requests within a batch are sized by URL
	// length, so this only bounds the candidate union and memory.
	private static final int CLEANUP_BATCH = 500;

	private void cleanBatch(BenchmarkSelector.Kind kind,
			java.util.List<PendingCleanup> batch,
			java.util.Collection<BenchmarkProfile> bundled, CycleStats cs) {
		// Build 76: the plan is per object and based on what was actually
		// pushed this cycle (ComplianceDecisions.cleanupPlan): a control in
		// the object's benchmark but not pushed (not applicable, e.g. vSAN
		// controls on a non-vSAN cluster) retires a lingering 0 OR 1; a
		// control outside the benchmark retires a lingering 0.
		java.util.Map<String, ComplianceDecisions.CleanupPlan> plans =
				new java.util.LinkedHashMap<>();
		java.util.Set<String> allCandidates = new java.util.TreeSet<>();
		for (PendingCleanup p : batch) {
			ComplianceDecisions.CleanupPlan plan =
					ComplianceDecisions.cleanupPlan(kind, p.profile, p.pushed,
							bundled, cycleOverrides.skipped);
			if (!plan.isEmpty()) {
				plans.put(p.resourceId, plan);
				allCandidates.addAll(plan.queryIds());
			}
		}
		if (plans.isEmpty()) return;
		java.util.Map<String, java.util.Set<String>> candidates =
				new java.util.LinkedHashMap<>();
		for (java.util.Map.Entry<String, ComplianceDecisions.CleanupPlan> e
				: plans.entrySet()) {
			candidates.put(e.getKey(), e.getValue().queryIds());
		}
		ComplianceStitcher.LatestRead read = stitcher.latestCompliant(
				new java.util.ArrayList<>(candidates.keySet()), allCandidates);
		cs.cleanupQueried += candidates.size();
		cs.cleanupRequests += read.requests;
		cs.cleanupValues += read.valuesReturned;
		if (read.failed()) {
			cs.cleanupSkipped += candidates.size();
			logWarn("Stale-control cleanup read failed for a batch of "
					+ candidates.size() + " " + kind.rollupName + " object(s) "
					+ "after " + read.requests + " request(s) and "
					+ read.valuesReturned + " value(s) returned: " + read.error
					+ "; batch skipped this cycle");
			return;
		}
		java.util.Map<String, java.util.Map<String, Double>> latest =
				read.values;
		long ts = System.currentTimeMillis();
		for (PendingCleanup p : batch) {
			ComplianceDecisions.CleanupPlan plan = plans.get(p.resourceId);
			if (plan == null) continue;
			java.util.Set<String> stale = ComplianceDecisions.staleControls(
					plan, latest.get(p.resourceId));
			if (stale.isEmpty()) continue;
			stitcher.pushProperties(p.resourceId,
					ComplianceDecisions.orphanProps(stale, p.profileName,
							cycleOverrides.skipped,
							config.overridesFile), ts);
			stitcher.pushStats(p.resourceId,
					ComplianceDecisions.orphanStats(stale), ts);
			cs.cleanedObjects++;
			cs.cleanedKeys += stale.size();
			logInfo(kind.rollupName + " resource " + p.resourceId + ": "
					+ stale.size() + " control(s) not evaluated this cycle under "
					+ p.profileName + " still held a 0 or 1; set to -1 (not "
					+ "evaluated)");
		}
	}

	/**
	 * Every bundled profile (cached by the loader), for cleanup in both
	 * modes. Null on a load failure: cleanup is skipped and retried, the
	 * collection itself is never failed over it.
	 */
	private java.util.Map<String, BenchmarkProfile> bundledForCleanup() {
		try {
			return benchmarkLoader.loadAll(cycleConfDir);
		} catch (RuntimeException e) {
			logWarn("Could not load the bundled profiles for per-control "
					+ "cleanup (retrying next cycle): " + e.getMessage());
			return null;
		}
	}

	// ----- Per-kind collectors --------------------------------------------

	/**
	 * Build 88: whether this cycle can push to objects of {@code kind}
	 * ({@link ComplianceDecisions#kindPushable}). When the VCF Ops resource
	 * list for the kind could not be read, every object would otherwise be
	 * reported as unmatched and the kind's counts would drop to 0; instead
	 * the kind is skipped and marked incomplete, so its Rollup keys (and
	 * All and Benchmark) keep their previous values and Rollup|incomplete is
	 * 1 for the cycle, as for a failed vCenter listing.
	 */
	private boolean kindPushable(BenchmarkSelector.Kind kind,
			String resourceKind, ComplianceRollup rollup) {
		boolean present = stitcher != null;
		boolean failed = present && stitcher.loadFailed(resourceKind);
		if (ComplianceDecisions.kindPushable(present, failed)) {
			return true;
		}
		rollup.markIncomplete(kind);
		if (failed) {
			logWarn(kind.rollupName + " objects not scored this cycle: the "
					+ "VCF Ops " + resourceKind + " resource list could not "
					+ "be read (see the ComplianceStitcher fetchResources WARN "
					+ "above), so no object can be matched or pushed; "
					+ "Rollup|" + kind.rollupName + " keys held back");
		}
		return false;
	}

	/**
	 * Hosts. Returns host MOID -> ESX version (null values allowed) so VMs
	 * can follow their host in Auto mode.
	 */
	private java.util.Map<String, String> collectHosts(
			BenchmarkSelector selector, ComplianceRollup rollup,
			CycleStats cs, java.util.Set<String> seen) throws Exception {
		java.util.Map<String, String> hostVersions = new java.util.HashMap<>();
		// Build 95 (issue #18): a failed host listing holds the Host kind
		// back like every other kind (Rollup|Host, All and Benchmark keys
		// keep their values, Rollup|incomplete = 1 raises "Compliance data
		// not collected (vCenter)") and the cycle goes on with the other
		// kinds. It used to escape and fail the whole cycle with no
		// incomplete signal. VMs then read their host's version on demand
		// (vmHostVersion). Review N5: the decision is the SDK-free
		// ComplianceDecisions.listOrHoldBack, so it is tested directly.
		java.util.List<VSphereClient.HostInfo> hosts =
				ComplianceDecisions.listOrHoldBack(() -> {
					try (CycleMetrics.Scope ph =
							phase(CycleMetrics.Phase.INVENTORY)) {
						return vsphere.getHosts();
					}
				}, rollup, BenchmarkSelector.Kind.HOST,
				e -> logWarn("Failed to enumerate hosts: " + e.getMessage()
						+ "; Host compliance not collected this cycle, "
						+ "Rollup|Host keys held back, other kinds still "
						+ "collected"));
		if (hosts == null) {
			return hostVersions;
		}
		if (hosts.isEmpty()) {
			logWarn("No hosts returned from vCenter SOAP");
			return hostVersions;
		}
		logInfo("vSphere SOAP: " + hosts.size() + " hosts");
		boolean pushable = kindPushable(BenchmarkSelector.Kind.HOST,
				"HostSystem", rollup);
		Shadow shadow = new Shadow("Host", "HostSystem");

		for (VSphereClient.HostInfo hostInfo : hosts) {
			stop.check("host " + hostInfo.name);
			String hostId = hostInfo.moid;
			String hostName = hostInfo.name;
			cs.hosts++;
			if (hostId != null) {
				seen.add(LastBenchmarkMemory.key(
						BenchmarkSelector.Kind.HOST, hostId));
			}
			if (!pushable) continue;

			// Build 88: match before any read. A host with no VCF Ops
			// resource is counted as unmatched only: not read, not scored,
			// not in the rollup. VMs on it read its version on demand.
			ComplianceStitcher.HostEntry he = stitcher.matchHost(hostName,
					hostId);
			if (he == null) {
				rollup.recordUnmatched(BenchmarkSelector.Kind.HOST, hostName,
						hostId);
				continue;
			}
			String resourceId = he.resourceId;

			String version = null;
			try {
				version = vsphere.getHostProductVersion(hostInfo.moRef);
			} catch (Exception e) {
				logWarn("Host " + hostName + ": could not read the ESX "
						+ "version (" + e.getMessage() + ")");
			}
			if (hostId != null) hostVersions.put(hostId, version);

			ComplianceDecisions.Decision d = decide(selector,
					BenchmarkSelector.Kind.HOST, hostId,
					BenchmarkSelector.governingVersion(
							BenchmarkSelector.Kind.HOST, null, version));
			if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
				recordVersionUnreadable(BenchmarkSelector.Kind.HOST, hostName,
						d, resourceId, rollup, cs);
				continue;
			}
			if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
				recordNoBenchmark(BenchmarkSelector.Kind.HOST, hostName, hostId,
						d, resourceId, rollup, cs);
				continue;
			}
			java.util.List<BenchmarkProfile.Control> hostControls =
					d.profile.hostControls();

			// Build 47: connection-state guard. A host whose vCenter link is
			// down at read time (disconnected / notResponding) cannot be read
			// honestly; scoring the subset that still resolves from vCenter's
			// cache yields a flattering partial score (the build-46 esx04
			// regression). Mark EVERY control UNREADABLE instead (build 63:
			// which scores the host 0, nothing was collected).
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
						+ "': host not fully connected to vCenter; ALL "
						+ "compliance controls marked UNREADABLE this cycle "
						+ "(no partial score emitted)");
				cr = wholeUnreadable(hostControls, hostName);
				wholeHostUnreadable = true;
				noteUnreadable(hostName, "host-not-connected: connectionState="
						+ connState, cr.unreadableCount);
			} else {
				java.util.Map<String, String> advSettings = null;
				boolean advUnreadable = false;
				String advReason = null;
				try {
					advSettings = vsphere.getAdvancedSettings(hostInfo.moRef);
				} catch (VSphereClient.AdvancedSettingsUnreadableException e) {
					// Build 48: null OptionManager MoRef means the host
					// disconnected between the connectionState check and this
					// read (a flap). Treat the WHOLE host as unreadable.
					logWarn("Host " + hostName + ": advanced-settings channel "
							+ "UNREADABLE (" + e.getMessage() + "); host "
							+ "flapped between connection check and read; ALL "
							+ "compliance controls marked UNREADABLE this cycle "
							+ "(no partial score emitted)");
					wholeHostUnreadable = true;
					advReason = "advanced-settings-unreadable: host flapped ("
							+ e.getMessage() + ")";
				} catch (Exception e) {
					// Any other read failure (SOAP fault, transport) is a read
					// failure, not an empty result: treat as unreadable.
					advUnreadable = true;
					advReason = "advanced-settings-unreadable: "
							+ e.getClass().getSimpleName() + ": " + e.getMessage();
					logWarn("Host " + hostName + ": failed to read advanced "
							+ "settings (" + e.getMessage() + "); all "
							+ "advanced_setting controls marked UNREADABLE this "
							+ "cycle (not dropped from the denominator)");
				}
				if (wholeHostUnreadable) {
					cr = wholeUnreadable(hostControls, hostName);
					noteUnreadable(hostName, advReason, cr.unreadableCount);
				} else {
					ControlEvaluator.ComplianceResult advCr = advUnreadable
							? ControlEvaluator.evaluateControlsUnreadable(
									hostControls, hostName)
							: ControlEvaluator.evaluateControls(
									hostControls, advSettings, hostName);
					if (advUnreadable) {
						noteUnreadable(hostName, advReason,
								advCr.unreadableCount);
					}
					ControlEvaluator.ComplianceResult vimCr =
							evaluateVimForResource(hostInfo.moRef, hostControls,
									hostName);
					cr = mergeResults(advCr, vimCr);
				}
			}
			cs.unreadable += cr.unreadableCount;
			rollup.recordEvaluated(BenchmarkSelector.Kind.HOST, d.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);
			if (!wholeHostUnreadable) {
				// Build 95: a wholly unreadable host is a known state, not
				// a comparison.
				shadow.record(hostId, hostName, hostControls, cr);
			}

			// Build 87: one WARN per host per cycle naming a host whose
			// esxcli reads were skipped (esxcli-host-unreachable).
			String esxcliUnreachable = vsphere.takeEsxcliUnreachable(hostId);
			if (esxcliUnreachable != null) {
				logWarn("Host " + hostName + ": esxcli request through vCenter "
						+ "failed (" + esxcliUnreachable + "); its remaining "
						+ "esxcli-backed controls are UNREADABLE "
						+ "(esxcli-host-unreachable) for the rest of this cycle. "
						+ "If every host shows this, check vCenter first.");
			}
			if (wholeHostUnreadable && cr.attempted() > 0) {
				// Build 63: nothing collected -> score 0 (owner decision),
				// counted in the host average like any other score.
				logInfo("Host " + hostName + ": UNREADABLE (" + cr.unreadableCount
						+ " controls), score 0");
			} else if (cr.attempted() > 0) {
				// Build 86: DEBUG for a fully read host (one line per host
				// per cycle is 12x the volume at 5 minutes); the per-cycle
				// INFO summary follows the loop. Build 87: INFO when any
				// control was unreadable, so a partly unreadable host is
				// named at INFO.
				String line = "Host " + hostName + " [" + d.profileName
						+ "]: score=" + String.format("%.1f", cr.score) + "% ("
						+ cr.passCount + " pass, " + cr.failCount + " fail, "
						+ cr.unreadableCount + " unreadable, "
						+ cr.totalCount + " total)";
				if (ComplianceDecisions.hostScoreLineAtInfo(
						cr.unreadableCount)) {
					logInfo(line);
				} else {
					logDebug(line);
				}
			}
			if (cr.attempted() > 0) {
				cs.hostsScored++;
				if (ComplianceRollup.isNonCompliant(cr.failCount,
						cr.unreadableCount)) {
					cs.hostsNonCompliant++;
				}
				if (wholeHostUnreadable) cs.hostsWhollyUnreadable++;
			}

			ComplianceDecisions.SkipPush skip =
					skipInForce(BenchmarkSelector.Kind.HOST, d);
			pushComplianceViaClient(resourceId, cr, d.profileName, skip);
			afterPush(BenchmarkSelector.Kind.HOST, hostId, d, resourceId, cs,
					ComplianceDecisions.pushedIds(cr), skip);
		}
		logInfo("Hosts scored this cycle: " + cs.hostsScored + " of "
				+ cs.hosts + " (" + cs.hostsNonCompliant + " non-compliant, "
				+ cs.hostsWhollyUnreadable + " wholly unreadable, "
				+ rollup.unmatched(BenchmarkSelector.Kind.HOST)
				+ " with no VCF Ops resource); per-host "
				+ "scores at DEBUG, at INFO for hosts with unreadable "
				+ "controls");
		runShadow(shadow);
		return hostVersions;
	}

	/**
	 * Build 95 (bulk-collection design build B): one kind's shadow
	 * comparison for this cycle: the per-object results recorded while the
	 * kind is scored, and the controls each object was scored against (its
	 * benchmark's slice), so the bulk result is evaluated against the same
	 * controls.
	 */
	private static final class Shadow {
		final ShadowComparator comparator;
		final java.util.Map<String, java.util.List<BenchmarkProfile.Control>>
				controls = new java.util.HashMap<>();
		String type;

		Shadow(String kind, String type) {
			this.comparator = new ShadowComparator(kind, BULK_SHADOW);
			this.type = type;
		}

		void record(String moid, String name,
				java.util.List<BenchmarkProfile.Control> slice,
				ControlEvaluator.ComplianceResult cr) {
			if (!comparator.isEnabled() || moid == null || cr == null) {
				return;   // review W5: shadow off records nothing
			}
			comparator.record(moid, name, cr.controlResults,
					VSphereClient.bulkComparable(type, slice));
			if (comparator.isRecorded(moid)) controls.put(moid, slice);
		}
	}

	/**
	 * Build 95: read the kind in paged bulk calls, evaluate each object
	 * locally and compare with what the per-object path recorded. One INFO
	 * summary, then one INFO line per disagreement (capped). Never changes
	 * a score or a push, never fails the cycle: a failed bulk read is
	 * reported in the summary. In this shadow build a failed page does not
	 * hold the kind back, because the kind's numbers come from the
	 * per-object path, which succeeded.
	 */
	private void runShadow(Shadow sh) throws InterruptedException {
		// Off (BULK_SHADOW false): nothing was recorded, so no bulk read.
		if (sh == null || !sh.comparator.hasRecords()) return;
		java.util.Set<String> paths = new java.util.LinkedHashSet<>();
		java.util.Set<java.util.List<BenchmarkProfile.Control>> slices =
				java.util.Collections.newSetFromMap(
						new java.util.IdentityHashMap<>());
		slices.addAll(sh.controls.values());
		for (java.util.List<BenchmarkProfile.Control> slice : slices) {
			paths.addAll(VSphereClient.bulkPaths(sh.type, slice));
		}
		final int[] pages = {0};
		final long[] bytes = {0, 0};   // total, largest page (review W5)
		long t0 = System.nanoTime();
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.SHADOW)) {
			VSphereClient.BulkStats st = vsphere.retrieveBulk(sh.type, paths,
					bulkPageSize(sh.type), rows -> {
						pages[0]++;
						for (VSphereClient.BulkRow row : rows) {
							stop.check("bulk shadow " + sh.type + " "
									+ row.ref.value);
							String moid = row.ref.value;
							java.util.List<BenchmarkProfile.Control> slice =
									sh.controls.get(moid);
							sh.comparator.compare(moid, slice == null ? null
									: vsphere.evaluateBulkRow(row, slice,
											moid));
						}
					});
			bytes[0] = st.bytes;
			bytes[1] = st.maxPageBytes;
			if (!st.droppedPaths.isEmpty() || st.pathFixes > 0) {
				logInfo("Bulk shadow " + sh.comparator.summaryKind()
						+ ": vCenter rejected " + st.pathFixes
						+ " path(s) as invalid for " + sh.type
						+ "; read with " + st.pathSet + (st.droppedPaths
						.isEmpty() ? "" : ", dropped " + st.droppedPaths));
			}
		} catch (InterruptedException e) {
			throw e;   // Stop Collecting: abandon the cycle
		} catch (Exception e) {
			sh.comparator.fail(e.getClass().getSimpleName() + ": "
					+ e.getMessage());
		}
		long ms = (System.nanoTime() - t0) / 1_000_000L;
		logInfo(sh.comparator.summary(pages[0], ms, bytes[0], bytes[1]));
		for (String line : sh.comparator.disagreementLines()) {
			logInfo("Bulk shadow disagreement: " + line);
		}
	}

	/** Every advanced_setting and vim/esxcli control folded to UNREADABLE. */
	private static ControlEvaluator.ComplianceResult wholeUnreadable(
			java.util.List<BenchmarkProfile.Control> controls, String name) {
		return mergeResults(
				ControlEvaluator.evaluateControlsUnreadable(controls, name),
				unreadableVimResult(controls, name));
	}

	private void collectVms(BenchmarkSelector selector,
			java.util.Map<String, String> hostVersions, ComplianceRollup rollup,
			CycleStats cs, java.util.Set<String> seen) throws InterruptedException {
		java.util.List<VSphereClient.VmInfo> vms;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			vms = vsphere.getVms();
		} catch (Exception e) {
			logWarn("Failed to enumerate VMs: " + e.getMessage());
			rollup.markIncomplete(BenchmarkSelector.Kind.VM);
			return;
		}
		if (vms.isEmpty()) {
			logInfo("No VMs returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + vms.size() + " VMs");
		boolean pushable = kindPushable(BenchmarkSelector.Kind.VM,
				"VirtualMachine", rollup);
		Shadow shadow = new Shadow("VM", "VirtualMachine");

		for (VSphereClient.VmInfo vm : vms) {
			stop.check("VM " + vm.name);
			// Build 88: vSphere Pod VMs (guest id crx*) are out of scope:
			// skipped before matching, scoring and the rollup, counted in
			// Rollup|VM|skipped_pods only. VCF Ops models them as kind Pod.
			if (ComplianceDecisions.isPodGuestId(vm.guestId)) {
				rollup.recordSkippedPod();
				logDebug("VM " + vm.name + " (" + vm.moid + "): vSphere Pod "
						+ "(guest id " + vm.guestId + "), out of scope, "
						+ "not scored");
				continue;
			}
			cs.vms++;
			if (vm.moid != null) {
				seen.add(LastBenchmarkMemory.key(
						BenchmarkSelector.Kind.VM, vm.moid));
			}
			if (!pushable) continue;

			// Build 88: match before any read; unmatched is counted only.
			ComplianceStitcher.HostEntry he = stitcher.matchVm(vm.name,
					vm.moid);
			if (he == null) {
				rollup.recordUnmatched(BenchmarkSelector.Kind.VM, vm.name,
						vm.moid);
				continue;
			}
			String resourceId = he.resourceId;
			String hostVersion = vmHostVersion(vm, hostVersions);

			ComplianceDecisions.Decision d = decide(selector,
					BenchmarkSelector.Kind.VM, vm.moid,
					BenchmarkSelector.governingVersion(
							BenchmarkSelector.Kind.VM, null, hostVersion));
			if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
				recordVersionUnreadable(BenchmarkSelector.Kind.VM, vm.name, d,
						resourceId, rollup, cs);
				continue;
			}
			if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
				recordNoBenchmark(BenchmarkSelector.Kind.VM, vm.name, vm.moid,
						d, resourceId, rollup, cs);
				continue;
			}
			java.util.List<BenchmarkProfile.Control> vmControls =
					d.profile.vmControls();

			ControlEvaluator.ComplianceResult advCr;
			try {
				java.util.Map<String, String> extra =
						vsphere.getVmExtraConfig(vm.moRef);
				advCr = ControlEvaluator.evaluateControls(vmControls, extra,
						vm.name);
			} catch (Exception e) {
				// v3 fix: a FAILED extraConfig read used to fall back to an
				// empty map, which scored every "X or Undefined" control as a
				// pass. A failed read is unreadable, never compliant.
				logWarn("Failed to read extraConfig for " + vm.name + ": "
						+ e.getMessage() + "; advanced_setting controls "
						+ "marked UNREADABLE this cycle");
				advCr = ControlEvaluator.evaluateControlsUnreadable(vmControls,
						vm.name);
				noteUnreadable(vm.name, "extraconfig-unreadable: "
						+ e.getClass().getSimpleName() + ": " + e.getMessage(),
						advCr.unreadableCount);
			}
			ControlEvaluator.ComplianceResult vimCr =
					evaluateVimForResource(vm.moRef, vmControls, vm.name);
			ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vimCr);
			cs.unreadable += cr.unreadableCount;
			rollup.recordEvaluated(BenchmarkSelector.Kind.VM, d.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);
			shadow.record(vm.moid, vm.name, vmControls, cr);

			ComplianceDecisions.SkipPush skip =
					skipInForce(BenchmarkSelector.Kind.VM, d);
			pushComplianceViaClient(resourceId, cr, d.profileName, skip);
			afterPush(BenchmarkSelector.Kind.VM, vm.moid, d, resourceId, cs,
					ComplianceDecisions.pushedIds(cr), skip);
		}
		logInfo("VM compliance: " + cs.vms + " VMs seen, "
				+ rollup.skippedPods() + " vSphere Pod VM(s) skipped (out "
				+ "of scope; named at DEBUG)");
		runShadow(shadow);
	}

	/**
	 * The ESX version of the host a VM runs on (Auto mode). The host MOID
	 * comes from the bulk VM enumeration (review N1); only when that was
	 * unavailable is runtime.host read per VM. The version itself is
	 * resolved by {@link ComplianceDecisions#resolveVmHostVersion}.
	 */
	private String vmHostVersion(VSphereClient.VmInfo vm,
			java.util.Map<String, String> hostVersions) {
		String hostMoid = vm.hostMoid;
		if (!vm.hostRead) {
			try {
				hostMoid = vsphere.getVmHostMoid(vm.moRef);
			} catch (Exception e) {
				logWarn("VM " + vm.name + ": could not read runtime.host ("
						+ e.getMessage() + ")");
				return null;
			}
		}
		return ComplianceDecisions.resolveVmHostVersion(hostMoid, hostVersions,
				moid -> {
					try {
						return vsphere.getHostProductVersion(
								new VSphereClient.MoRef("HostSystem", moid));
					} catch (Exception e) {
						logWarn("VM " + vm.name + ": could not read the version "
								+ "of host " + moid + " (" + e.getMessage() + ")");
						return null;
					}
				});
	}

	private ComplianceStitcher.HostEntry collectVCenter(
			BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) {
		String resourceName = config.vcenterHost;
		String moid = "vcenter";
		seen.add(LastBenchmarkMemory.key(BenchmarkSelector.Kind.VCENTER,
				moid));

		if (stitcher == null) {
			return null;   // nothing can be pushed; configureAdapter warned
		}
		String vcInstanceUuid = null;
		try {
			vcInstanceUuid = vsphere.getVCenterInstanceUuid();
		} catch (Exception e) {
			logWarn("Could not read vCenter instance UUID for stitcher "
					+ "lookup: " + e.getMessage());
		}
		ComplianceStitcher.HostEntry he = stitcher.matchVCenterAdapterInstance(
				resourceName, vcInstanceUuid);
		if (he == null) {
			logWarn("Could not resolve VMwareAdapter Instance for "
					+ resourceName + " (vcInstanceUuid=" + vcInstanceUuid
					+ "): vCenter compliance and the per-vCenter rollup "
					+ "will NOT be pushed");
			// Build 88: unmatched, counted only (the rollup itself lives on
			// this object, so it is not pushed this cycle either).
			rollup.recordUnmatched(BenchmarkSelector.Kind.VCENTER,
					resourceName, moid);
			return null;
		}
		String resourceId = he.resourceId;

		ComplianceDecisions.Decision d = decide(selector,
				BenchmarkSelector.Kind.VCENTER, moid,
				BenchmarkSelector.governingVersion(
						BenchmarkSelector.Kind.VCENTER, vcVersion, null));
		if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
			recordVersionUnreadable(BenchmarkSelector.Kind.VCENTER,
					resourceName, d, resourceId, rollup, cs);
			return he;
		}
		if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
			recordNoBenchmark(BenchmarkSelector.Kind.VCENTER, resourceName,
					moid, d, resourceId, rollup, cs);
			return he;
		}
		java.util.List<BenchmarkProfile.Control> vcControls =
				d.profile.vCenterControls();

		ControlEvaluator.ComplianceResult advCr;
		try {
			java.util.Map<String, String> vcSettings =
					vsphere.getVCenterAdvancedSettings();
			logInfo("vCenter advanced settings: " + vcSettings.size()
					+ " entries");
			advCr = ControlEvaluator.evaluateControls(vcControls, vcSettings,
					resourceName);
		} catch (Exception e) {
			// v3: a failed read is unreadable, which the vCenter object and
			// the rollup must show (previously the vCenter was skipped).
			logWarn("Failed to read vCenter advanced settings: "
					+ e.getMessage() + "; advanced_setting controls marked "
					+ "UNREADABLE this cycle");
			advCr = ControlEvaluator.evaluateControlsUnreadable(vcControls,
					resourceName);
			noteUnreadable(resourceName, "vcenter-settings-unreadable: "
					+ e.getClass().getSimpleName() + ": " + e.getMessage(),
					advCr.unreadableCount);
		}
		ControlEvaluator.ComplianceResult vamiCr =
				evaluateVamiForVCenter(vcControls, resourceName);
		ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vamiCr);
		logInfo("vCenter " + resourceName + " [" + d.profileName + "]: score="
				+ String.format("%.1f", cr.score) + "% ("
				+ cr.passCount + " pass, " + cr.failCount + " fail, "
				+ cr.unreadableCount + " unreadable, "
				+ cr.totalCount + " total)");

		cs.unreadable += cr.unreadableCount;
		rollup.recordEvaluated(BenchmarkSelector.Kind.VCENTER, d.bucket,
				cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);

		ComplianceDecisions.SkipPush skip =
				skipInForce(BenchmarkSelector.Kind.VCENTER, d);
		pushComplianceViaClient(resourceId, cr, d.profileName, skip);
		logInfo("Pushed vCenter compliance data to " + he.hostName
				+ " (resource=" + he.resourceId + ", VCURL=" + he.moid
				+ ")");
		afterPush(BenchmarkSelector.Kind.VCENTER, moid, d, resourceId, cs,
				ComplianceDecisions.pushedIds(cr), skip);
		return he;
	}

	private void collectDvs(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) throws InterruptedException {
		if (stitcher == null) return;   // nothing to push onto; skip the reads
		java.util.List<VSphereClient.DvsInfo> switches;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			switches = vsphere.getDvSwitches();
		} catch (Exception e) {
			logWarn("Failed to enumerate DVS: " + e.getMessage());
			rollup.markIncomplete(BenchmarkSelector.Kind.VDS);
			return;
		}
		if (switches.isEmpty()) {
			logInfo("No DVS returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + switches.size() + " DVS");
		if (!kindPushable(BenchmarkSelector.Kind.VDS,
				"VmwareDistributedVirtualSwitch", rollup)) {
			return;
		}
		Shadow shadow = new Shadow("vDS", switches.get(0).moRef.type);
		for (VSphereClient.DvsInfo dvs : switches) {
			stop.check("vDS " + dvs.name);
			cs.dvs++;
			ComplianceStitcher.HostEntry he = stitcher.matchDvs(dvs.name,
					dvs.moid);
			collectVimObject(BenchmarkSelector.Kind.VDS, dvs.moRef, dvs.name,
					dvs.moid, he, selector, vcVersion, rollup, cs, seen,
					shadow);
		}
		runShadow(shadow);
	}

	private void collectDvpg(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) throws InterruptedException {
		if (stitcher == null) return;
		java.util.List<VSphereClient.DvpgInfo> pgs;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			pgs = vsphere.getDvPortgroups();
		} catch (Exception e) {
			logWarn("Failed to enumerate DVPG: " + e.getMessage());
			rollup.markIncomplete(BenchmarkSelector.Kind.PORTGROUP);
			return;
		}
		if (pgs.isEmpty()) {
			logInfo("No DVPG returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + pgs.size() + " DVPG");
		if (!kindPushable(BenchmarkSelector.Kind.PORTGROUP,
				"DistributedVirtualPortgroup", rollup)) {
			return;
		}
		Shadow shadow = new Shadow("Portgroup", pgs.get(0).moRef.type);
		for (VSphereClient.DvpgInfo pg : pgs) {
			stop.check("portgroup " + pg.name);
			cs.dvpg++;
			ComplianceStitcher.HostEntry he = stitcher.matchDvpg(pg.name,
					pg.moid);
			collectVimObject(BenchmarkSelector.Kind.PORTGROUP, pg.moRef,
					pg.name, pg.moid, he, selector, vcVersion, rollup, cs,
					seen, shadow);
		}
		runShadow(shadow);
	}

	/**
	 * ClusterComputeResource (vSAN) collector. Non-vSAN clusters get
	 * profile_name only: vSAN controls are genuinely N/A, not a coverage
	 * gap. Most SCG cluster controls need the vSAN Management SDK (not on
	 * this classpath) and stay manual_audit (CLASSPATH GAP).
	 */
	private void collectClusters(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) throws InterruptedException {
		if (stitcher == null) return;
		java.util.List<VSphereClient.ClusterInfo> clusters;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			clusters = vsphere.getClusters();
		} catch (Exception e) {
			logWarn("Failed to enumerate ClusterComputeResource: "
					+ e.getMessage());
			rollup.markIncomplete(BenchmarkSelector.Kind.CLUSTER);
			return;
		}
		if (clusters.isEmpty()) {
			logInfo("No ClusterComputeResource returned from vCenter SOAP");
			return;
		}
		logInfo("vSphere SOAP: " + clusters.size()
				+ " ClusterComputeResource");
		if (!kindPushable(BenchmarkSelector.Kind.CLUSTER,
				"ClusterComputeResource", rollup)) {
			return;
		}
		Shadow shadow = new Shadow("Cluster", clusters.get(0).moRef.type);
		for (VSphereClient.ClusterInfo cluster : clusters) {
			stop.check("cluster " + cluster.name);
			cs.clusters++;
			ComplianceStitcher.HostEntry he = stitcher.matchCluster(
					cluster.name, cluster.moid);
			collectVimObject(BenchmarkSelector.Kind.CLUSTER, cluster.moRef,
					cluster.name, cluster.moid, he, selector, vcVersion,
					rollup, cs, seen, shadow);
		}
		runShadow(shadow);
	}

	/**
	 * Shared body for the vim-property kinds (vDS, portgroup, cluster), all
	 * governed by the vCenter version (the object's own version, e.g. a vDS
	 * at 9.0.0 under a 9.1.1 vCenter, is deliberately not read). Build 88:
	 * an object with no matching VMWARE resource is counted as unmatched
	 * only and not read (before 88 it was evaluated and counted, though
	 * nothing could be pushed to it). A FAILED read (vim properties, or the
	 * cluster vSAN probe) folds every evaluable control to UNREADABLE.
	 */
	private void collectVimObject(BenchmarkSelector.Kind kind,
			VSphereClient.MoRef moRef, String name, String moid,
			ComplianceStitcher.HostEntry he, BenchmarkSelector selector,
			String vcVersion, ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen, Shadow shadow) {
		if (moid != null) seen.add(LastBenchmarkMemory.key(kind, moid));
		if (he == null) {
			rollup.recordUnmatched(kind, name, moid);
			return;
		}
		String resourceId = he.resourceId;

		ComplianceDecisions.Decision d = decide(selector, kind, moid,
				BenchmarkSelector.governingVersion(kind, vcVersion, null));
		if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
			recordVersionUnreadable(kind, name, d, resourceId, rollup, cs);
			return;
		}
		if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
			recordNoBenchmark(kind, name, moid, d, resourceId, rollup, cs);
			return;
		}
		java.util.List<BenchmarkProfile.Control> controls =
				ComplianceDecisions.sliceFor(d.profile, kind);
		ControlEvaluator.ComplianceResult cr;
		// Review N4: gate on vim_property AND esxcli, the same kinds
		// BenchmarkSelector.evaluatedFor and the alert generator admit here.
		if (countEvaluable(controls, "vim_property")
				+ countEvaluable(controls, "esxcli") == 0) {
			cr = emptyResult(name);
		} else if (kind == BenchmarkSelector.Kind.CLUSTER) {
			Boolean vsan = probeVsan(moRef, name);
			if (vsan == null) {
				cr = null;                    // probe failed: unreadable
			} else if (!vsan) {
				cr = emptyResult(name);       // non-vSAN: genuinely N/A
			} else {
				cr = readAndEvaluateVim(moRef, controls, name);
				shadow.record(moid, name, controls, cr);
			}
		} else {
			cr = readAndEvaluateVim(moRef, controls, name);
			shadow.record(moid, name, controls, cr);
		}
		if (cr == null) {
			cr = unreadableVimResult(controls, name);
			noteUnreadable(name, lastObjectFailure, cr.unreadableCount);
		}
		cs.unreadable += cr.unreadableCount;
		rollup.recordEvaluated(kind, d.bucket, cr.totalCount, cr.failCount,
				cr.unreadableCount, cr.score);
		ComplianceDecisions.SkipPush skip = skipInForce(kind, d);
		pushOrProfileName(resourceId, cr, d.profileName, skip);
		afterPush(kind, moid, d, resourceId, cs,
				ComplianceDecisions.pushedIds(cr), skip);
	}

	/**
	 * vSAN presence for a cluster: TRUE when vSAN is configured, FALSE for a
	 * non-vSAN cluster (vSAN controls genuinely N/A), NULL when the probe
	 * itself failed (unreadable, never "not vSAN").
	 */
	private Boolean probeVsan(VSphereClient.MoRef moRef, String name) {
		try {
			boolean enabled = vsphere.hasVsanConfig(moRef);
			if (!enabled) {
				// Build 86: DEBUG, every non-vSAN cluster every cycle.
				logDebug("Cluster " + name + ": vSAN not enabled; vSAN "
						+ "controls not applicable (profile_name only)");
			}
			return enabled;
		} catch (Exception e) {
			logWarn("Failed to probe vSAN config for cluster " + name + ": "
					+ e.getMessage() + "; vSAN controls marked UNREADABLE");
			lastObjectFailure = "vsan-probe-failed: " + e.getMessage();
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
					+ e.getMessage() + "; controls marked UNREADABLE");
			lastObjectFailure = "exception: " + e.getClass().getSimpleName()
					+ ": " + e.getMessage();
			return null;
		}
		noteReadReasons(name, controls, values, vsphere.lastReadReasons());
		return ControlEvaluator.evaluateVimProperties(controls, values, name,
				VSphereClient.UNREADABLE);
	}

	// ----- shared push / evaluation helpers -------------------------------

	private void pushOrProfileName(String resourceId,
			ControlEvaluator.ComplianceResult cr, String profileName,
			ComplianceDecisions.SkipPush skip) {
		if (cr.totalCount > 0 || cr.unreadableCount > 0) {
			pushComplianceViaClient(resourceId, cr, profileName, skip);
		} else {
			pushProfileNamePropertyOnly(resourceId, profileName, skip);
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
			ControlEvaluator.ComplianceResult u =
					unreadableVimResult(controls, resourceName);
			noteUnreadable(resourceName, "exception: " + e.getClass()
					.getSimpleName() + ": " + e.getMessage(), u.unreadableCount);
			return u;
		}
		noteReadReasons(resourceName, controls, values,
				vsphere.lastReadReasons());
		return ControlEvaluator.evaluateVimProperties(
				controls, values, resourceName, VSphereClient.UNREADABLE);
	}

	// ----- unreadable diagnostics (build 74) ------------------------------

	/** This cycle's unreadable reasons; reset at the start of each cycle. */
	private volatile UnreadableReasons cycleReasons = new UnreadableReasons();

	/** Why the last whole-object vim read (or vSAN probe) failed. */
	private volatile String lastObjectFailure;

	private volatile com.integrien.alive.common.adapter3.Logger debugLog;

	private void logDebug(String message) {
		com.integrien.alive.common.adapter3.Logger l = debugLog;
		if (l == null) {
			l = componentLogger(ComplianceAdapter.class);
			debugLog = l;
		}
		if (l != null && l.isDebugEnabled()) {
			l.debug(message);
		}
	}

	/** Record {@code count} unreadable controls on one object for a reason. */
	private void noteUnreadable(String resourceName, String reason, int count) {
		if (count <= 0) return;
		cycleReasons.record(reason, count);
		logDebug("Unreadable on " + resourceName + ": " + count
				+ " control(s): " + reason);
	}

	/** Record the per-control reasons of one readVimProperties call. */
	private void noteReadReasons(String resourceName,
			java.util.List<BenchmarkProfile.Control> controls,
			java.util.Map<String, Object> values,
			java.util.Map<String, String> reasons) {
		for (BenchmarkProfile.Control c : controls) {
			if (values.get(c.parameter) != VSphereClient.UNREADABLE) continue;
			String why = reasons.get(c.parameter);
			if (why == null) why = "unknown: no reason recorded";
			cycleReasons.record(why, 1);
			logDebug("Unreadable " + c.controlId + " on " + resourceName
					+ " (" + c.readRecipe + "): " + why);
		}
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
				sslContextFor(config.vcenterHost), this::logWarn);
		try {
			java.util.Map<String, Object> values = new java.util.HashMap<>();
			for (BenchmarkProfile.Control c : controls) {
				if (!"vami_api".equals(c.parameterKind) || !c.isEvaluable()) {
					continue;
				}
				VamiRecipe r = VamiRecipe.parse(c.readRecipe);
				if (r == null) {
					values.put(c.configParameter, VSphereClient.UNREADABLE);
					noteUnreadableControl(resourceName, c,
							"recipe-malformed: " + c.readRecipe);
					continue;
				}
				Object read = client.readField(r);
				if (read == VamiApiClient.FAILED || read == null) {
					values.put(c.configParameter, VSphereClient.UNREADABLE);
					String why = client.failureReason(r.appliancePath, r.field);
					noteUnreadableControl(resourceName, c,
							why != null ? why : "vami-failed: " + c.readRecipe);
				} else {
					values.put(c.configParameter, read);
				}
			}
			return ControlEvaluator.evaluateVimProperties(
					controls, values, resourceName, VSphereClient.UNREADABLE);
		} finally {
			// Build 74: end the appliance session every cycle.
			client.close();
		}
	}

	private void noteUnreadableControl(String resourceName,
			BenchmarkProfile.Control c, String why) {
		cycleReasons.record(why, 1);
		logDebug("Unreadable " + c.controlId + " on " + resourceName + " ("
				+ c.readRecipe + "): " + why);
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
		return new ControlEvaluator.ComplianceResult(a.hostname, pass, fail,
				total, unreadable, ControlEvaluator.score(pass, fail, unreadable),
				merged);
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
	 * cluster, a slice with zero evaluable controls): profile_name, both
	 * flags 0, and zeroed counters (review W2) so a previous cycle's values
	 * never linger. No score (never a sentinel).
	 */
	private void pushProfileNamePropertyOnly(String resourceId,
			String profileName, ComplianceDecisions.SkipPush skip) {
		ComplianceDecisions.pushObject(stitcher, resourceId,
				ComplianceDecisions.profileNameProps(profileName),
				ComplianceDecisions.nothingEvaluatedStats(), skip,
				System.currentTimeMillis());
		logInfo("Pushed profile_name='" + profileName + "' to resource="
				+ resourceId);
	}

	/**
	 * A readable version with no SCG in this pak (Auto mode):
	 * profile_name = "no benchmark for <product> X.Y", no_benchmark = 1,
	 * non_compliant = 0, counters zeroed (review W2), no score and no
	 * per-control results.
	 */
	private void pushNoBenchmark(String resourceId, String label) {
		long ts = System.currentTimeMillis();
		stitcher.pushProperties(resourceId,
				ComplianceDecisions.profileNameProps(label), ts);
		stitcher.pushStats(resourceId, ComplianceDecisions.noBenchmarkStats(),
				ts);
	}

	/**
	 * Publish per-control results and aggregates onto a matched VMWARE
	 * resource. Keys are profile-free
	 * ({@code VCF-CF Compliance|<control_id>|...}); the payload is built by
	 * {@link ComplianceDecisions#complianceStats} /
	 * {@link ComplianceDecisions#complianceProps}: Compliant 1 / 0 for
	 * every control read (build 95: an unreadable control is not pushed),
	 * score whenever a control was attempted (build 63: unreadable counts
	 * as failing),
	 * counters always, non_compliant = fail or unreadable, no_benchmark = 0.
	 */
	private void pushComplianceViaClient(String resourceId,
			ControlEvaluator.ComplianceResult cr, String profileName,
			ComplianceDecisions.SkipPush skip) {
		ComplianceDecisions.pushObject(stitcher, resourceId,
				ComplianceDecisions.complianceProps(cr, profileName,
						siteOverriddenFor(profileName)),
				ComplianceDecisions.complianceStats(cr), skip,
				System.currentTimeMillis());
	}

	/** Per-cycle counters for the completion log line. */
	private static final class CycleStats {
		int hosts; int vms; int dvs; int dvpg; int clusters;
		int hostsScored; int hostsNonCompliant; int hostsWhollyUnreadable;
		int noBenchmark; int versionUnreadable; int unreadable;
		int cleanedObjects; int cleanedKeys; int cleanupSkipped;
		int cleanupQueried; int cleanupRequests; int cleanupValues;
		int skipPushedObjects; int skipPushedKeys;
	}

	// -----------------------------------------------------------------------
	// onDiscard
	// -----------------------------------------------------------------------

	@Override
	public void onDiscard() {
		// Review W4: the fields keep the (now closed) clients, so a cycle
		// still running fails its remaining reads instead of an NPE or a
		// fresh login.
		releaseClients(vsphere, suiteStitcher);
		super.onDiscard();
	}

	/**
	 * Build 95 (issue #23): log the vCenter session out and close the Suite
	 * API client. Used by configure (after the new clients are swapped in,
	 * review W4) and by discard. {@code disconnect()} marks the vCenter
	 * client closed first, so a cycle still using it fails its calls
	 * instead of logging in again, and bounds the Logout wait
	 * ({@code VSphereClient.LOGOUT_TIMEOUT_MS}). Never throws: a failed
	 * logout leaves only an idle session for vCenter to expire.
	 */
	private void releaseClients(VSphereClient oldVsphere,
			SuiteApiStitcher oldSuite) {
		if (oldVsphere != null) {
			try {
				oldVsphere.disconnect();
			} catch (RuntimeException e) {
				logWarn("Releasing the previous vCenter session failed: " + e);
			}
		}
		if (oldSuite != null) {
			try {
				oldSuite.discard();
			} catch (RuntimeException e) {
				logWarn("Releasing the previous Suite API client failed: " + e);
			}
		}
	}
}
