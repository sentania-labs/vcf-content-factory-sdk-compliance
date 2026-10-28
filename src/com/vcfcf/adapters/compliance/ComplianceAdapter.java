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
 * adapter failed to read never passes. Since build 95 (Scott 2026-10-14)
 * it is not pushed at all (its last value stays), is outside the score
 * (passed over evaluated, ControlEvaluator.score), is counted in
 * unreadable_count and flagged per object (has_unreadable, the reason, the
 * control ids), and the flag raises the per-kind "Compliance data not
 * collected" alert after two cycles; the zero-divisor placeholder of an
 * object with nothing read is never pushed or averaged.
 */
public final class ComplianceAdapter extends VcfCfAdapter<ComplianceConfig> {

	private static final String ADAPTER_KIND = "vcfcf_compliance";

	// Review N13 and W12: configureAdapter builds one Configured holder
	// (the account, every client, a fresh benchmark memory, the vCenter
	// resource-id slot, the Custom-bucket flag) and publishes it with the
	// one write to `configured`. Each cycle copies that reference once, at
	// its start, into `cycle`, and reads and writes only through it.
	// Nothing else holds the account or a client: the platform's
	// this.config is never set by this adapter. An instance edit during a
	// cycle therefore never switches that cycle to the new vCenter
	// part-way, and what the old cycle records (benchmarks, the vCenter
	// id) lands in the old holder, which no later cycle reads. See
	// Configured.
	private volatile Configured<SuiteApiStitcher, ComplianceStitcher>
			configured;
	private volatile Configured<SuiteApiStitcher, ComplianceStitcher> cycle;

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
	private volatile int cycleOverriddenInForce;

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

		// Review W12: the account goes only into the holder published
		// below, never into this.config.
		ComplianceConfig account = new ComplianceConfig(
				vcenterHost, username, password,
				readAppliance, overridesFile);
		// Build 92 (review N2): the account is stored as the removed Custom
		// profile; zero its retired rollup bucket on the next complete
		// rollup (the flag lives in the holder).
		boolean storedAsCustom = ComplianceConfig.isCustomName(storedProfile);
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
		// and the previous Suite API token released, so an edit no longer
		// leaves a live session behind in the collector JVM (review N14:
		// the Suite API client itself is not closed; see onDiscard).
		// Review W4: the new clients are built first, swapped in, and only
		// then are the old ones released, so a cycle still running never
		// sees a null client. Review N13 and W12: that cycle keeps the old
		// holder to its end (it copied it at its start), so its remaining
		// vCenter inventory calls fail (the closed vSphere client does not
		// log in again) instead of switching to the new vCenter part-way,
		// and the benchmarks and vCenter id it records go into the old
		// holder only. (Issue #28: the REST client built here was never
		// used by collection; it is gone. Test Connection builds its own.)
		Configured<SuiteApiStitcher, ComplianceStitcher> old = this.configured;
		VSphereClient newVsphere = new VSphereClient(
				account.vcenterHost, account.username, account.password,
				sslSocketFactoryFor(account.vcenterHost),
				clientLog(componentLogger(VSphereClient.class)));

		BenchmarkLoader newLoader = new BenchmarkLoader();
		// HOLD (owner decision pending): "Read vCenter appliance settings".
		// Off = the vami_api controls load as manual review for this
		// instance (no score, no per-control alert, not attempted).
		newLoader.setApplianceReads(account.readApplianceSettings);
		// An instance edit re-runs configure (and an upgrade from a build with
		// a fixed Compliance Profile lands here too): the new holder starts
		// with an empty benchmark memory, so the B2 fallback never reuses a
		// benchmark chosen under the old settings or on the old vCenter.

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
			newStitcher = new ComplianceStitcher(suiteApi(newSuite),
					clientLog(componentLogger(ComplianceStitcher.class)));
		} catch (RuntimeException e) {
			newSuite = null;
			newStitcher = null;
			logWarn("Ambient Suite API stitcher unavailable: compliance data "
					+ "will not be pushed onto VMWARE resources this instance: "
					+ e.getMessage());
		}
		// Review W4 and W12: publish the new holder with one volatile
		// write, then release the previous clients.
		this.configured = new Configured<>(account, newVsphere, newLoader,
				newSuite, newStitcher, storedAsCustom);
		if (old != null) {
			releaseClients(old.vsphere, old.suite);
		}

		logInfo("ComplianceAdapter configured: vcenter=" + account.vcenterHost
				+ " profile=" + BenchmarkSelector.AUTO
				+ " readApplianceSettings=" + account.readApplianceSettings
				+ " overridesFile="
				+ (account.overridesFile.isEmpty() ? "(none)"
						: account.overridesFile)
				+ " stitcher=" + (newStitcher != null));
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
			int count = 0;
			try {
				SimpleJson hosts = testApi.listHosts();
				if (!hosts.isNull() && hosts.isList()) {
					count = hosts.asList().size();
				}
			} finally {
				testApi.logout();
			}
			// Build 96 (issue #26): collection reads vCenter over vSphere
			// SOAP (vim25), not REST, so a REST login alone could pass the
			// test before a cycle that reads nothing. RetrieveServiceContent
			// and Login, then Logout.
			testSoapLogin(new VSphereClient(testCfg.vcenterHost,
					testCfg.username, testCfg.password,
					sslSocketFactoryFor(testCfg.vcenterHost),
					clientLog(componentLogger(VSphereClient.class))),
					testCfg.vcenterHost);
			// Build 96 (issue #26): the local Suite API the results are
			// pushed through. Reported, never failing the test: Test
			// Connection may run on a different node from collection.
			testSuiteApi();
			logInfo("Test OK: connected to " + testCfg.vcenterHost
					+ " (REST and vSphere SOAP), " + count
					+ " host(s) visible");
		};
	}

	/**
	 * Build 96 (issue #26): the vSphere SOAP login collection uses
	 * (RetrieveServiceContent, then Login), then Logout. A failure fails
	 * Test Connection with the certificate guidance when it is a
	 * certificate problem, else with the SOAP error.
	 */
	private void testSoapLogin(VSphereClient soap, String vcenterHost)
			throws Exception {
		try {
			soap.connect();
		} catch (Exception e) {
			VCenterCertificates.Failure f = VCenterCertificates.classify(e);
			if (f != null) {
				logWarn("Test Connection: vCenter certificate problem on the "
						+ "vSphere SOAP connection (" + f + "): " + e, e);
				throw new Exception(VCenterCertificates.message(f,
						vcenterHost) + " ("
						+ e.getClass().getSimpleName() + ")");
			}
			throw new Exception("The vCenter REST login worked, but the "
					+ "vSphere SOAP (vim25) login that collection uses failed: "
					+ e.getMessage());
		} finally {
			soap.disconnect();
		}
	}

	/**
	 * Build 96 (issue #26): whether the local VCF Operations Suite API (the
	 * ambient maintenance credential) answers from where Test Connection
	 * runs. Logged only: INFO when it answers, WARN when not.
	 */
	private void testSuiteApi() {
		SuiteApiStitcher sas = null;
		try {
			sas = SuiteApiStitcher.create(this,
					componentLogger(SuiteApiStitcher.class));
			sas.get("/api/versions/current");
			logInfo("Test Connection: the local VCF Operations Suite API "
					+ "answered (compliance values can be pushed from here)");
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (Exception e) {
			logWarn("Test Connection: the local VCF Operations Suite API did "
					+ "not answer from where this test ran ("
					+ e.getClass().getSimpleName() + ": " + e.getMessage()
					+ "). Compliance values are pushed through it; if "
					+ "collection logs the same, nothing will be pushed. The "
					+ "test still passes, because it can run on a different "
					+ "node from collection.");
		} finally {
			if (sas != null) {
				try {
					sas.discard();
				} catch (RuntimeException ignored) {
					// releasing the token is best effort
				}
			}
		}
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
	 * Build 96 (issue #27): the framework Suite API client as the SDK-free
	 * {@link ComplianceStitcher.SuiteApi}, so the stitcher compiles and is
	 * tested without the framework jar. Every call is passed through
	 * unchanged.
	 */
	private static ComplianceStitcher.SuiteApi suiteApi(
			final SuiteApiStitcher sas) {
		return new ComplianceStitcher.SuiteApi() {
			@Override
			public String get(String path)
					throws java.io.IOException, InterruptedException {
				return sas.get(path);
			}

			@Override
			public void pushProperties(String resourceId,
					java.util.Map<String, String> properties, long ts) {
				sas.pushProperties(resourceId, properties, ts);
			}

			@Override
			public void pushStats(String resourceId,
					java.util.Map<String, Double> stats, long ts) {
				sas.pushStats(resourceId, stats, ts);
			}
		};
	}

	/**
	 * Build 95: the platform logger as the SDK-free {@link VSphereClient.Log}
	 * (null stays null: the client then logs nothing). Build 96: also the
	 * stitcher's log.
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
	 * bulk-read shadow comparison. Build 103 (issue #17 build 2): the bulk
	 * read is primary, so the shadow runs the other way round: after each
	 * kind is scored from the bulk read, the objects scored from it are
	 * read again the per-object way and compared, and the differences
	 * logged. Scores, pushes and alerts come only from the primary path.
	 * Not a user setting. Review W5: the one switch for shadow mode; off, no
	 * kind records per-object outcomes (no memory held) and no bulk read
	 * is made. Decision 2026-10-14 (point 6): on in a dev-preview build
	 * (0.0.0.N), off in a tagged release, decided each cycle from the
	 * build's own version stamp ({@link ShadowMode}, conf/version.txt).
	 */
	private volatile boolean bulkShadow;

	/** The last shadow decision logged, so it is logged once per change. */
	private volatile String bulkShadowLogged;

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

	// Build 96 (issue #16): this cycle's time budget and consecutive-timeout
	// breaker (CycleBudget), why the cycle ended early (null: it did not),
	// and the last budget line logged (logged once per change). The clock
	// is a test seam.
	private volatile CycleBudget cycleBudget;
	private volatile String cycleEndedEarly;
	// Build 96 (review B1-r2): the kind this cycle ended early in (the next
	// cycle starts there), and whether it dropped an object.
	private volatile BenchmarkSelector.Kind cycleEndedIn;
	private volatile boolean cycleDropped;
	private volatile String budgetLogged;
	volatile java.util.function.LongSupplier budgetClock = System::nanoTime;

	/**
	 * Build 96 (issue #16): the platform's collection interval in seconds,
	 * or null when it cannot be read (the budget then falls back, see
	 * {@link CycleBudget#interval}).
	 */
	private Integer platformIntervalSec() {
		try {
			return getMonitoringIntervalInSec();
		} catch (RuntimeException e) {
			return null;
		}
	}

	private static Integer resourceIntervalSec(ResourceConfig rc) {
		try {
			return rc == null ? null : rc.getIntervalInSec();
		} catch (RuntimeException e) {
			return null;
		}
	}

	/**
	 * Build 96 (issue #16): true when this cycle's budget or breaker is
	 * reached. The kind being collected is then held back
	 * ({@code markIncomplete}: Rollup|incomplete = 1, its keys keep their
	 * values) and the caller stops; every later collector does the same
	 * for its own kind, so every kind not finished is held back. The first
	 * time, one WARN says where and why. Objects already pushed this cycle
	 * keep their fresh values.
	 */
	private boolean cycleOver(BenchmarkSelector.Kind kind,
			ComplianceRollup rollup, String where) {
		CycleBudget b = cycleBudget;
		String why = b == null ? null : b.exhausted();
		if (why == null) return false;
		rollup.markIncomplete(kind);
		if (cycleEndedEarly == null) {
			endedIn(kind, why);
			logWarn("Cycle ended early before " + where + ": " + why + ". "
					+ kind.rollupName + " and every kind not yet collected "
					+ "are held back this cycle (Rollup|incomplete = 1, their "
					+ "Rollup keys keep their values; objects already pushed "
					+ "keep this cycle's values; no more vCenter calls are "
					+ "made). The next cycle resumes here.");
		}
		return true;
	}

	/** Build 96 (review B1-r2): the first early end of this cycle. */
	private void endedIn(BenchmarkSelector.Kind kind, String why) {
		if (cycleEndedEarly == null) {
			cycleEndedEarly = why;
			cycleEndedIn = kind;
		}
	}

	/** Build 96 (issue #16): this cycle's budget or breaker is reached. */
	private boolean budgetExhausted() {
		CycleBudget b = cycleBudget;
		return b != null && b.exhausted() != null;
	}

	/**
	 * Build 96 (issue #16, review B1, W2, B1-r2, N2-r2): one kind's walk
	 * this cycle. {@link #order} starts after where the last early-ended
	 * cycle stopped in this kind (ResumeCursor). {@link #next}, at the top
	 * of each object, ends the walk when the budget or breaker is reached
	 * and records the last object finished. {@link #afterRead}, after an
	 * object is evaluated and before it is pushed or counted, decides what
	 * happens when a call was refused while that object was read (and only
	 * then: a deadline that passed after its last read does not count):
	 * <ul>
	 *   <li>{@link #DROP}: not pushed (its last values stay, no partial
	 *       score: a host at 64.58 never shows 100 from five passing
	 *       reads), the kind held back, the next cycle starts with it.</li>
	 *   <li>{@link #PUSH_THEN_STOP}: the second drop in a row of the same
	 *       object. Only its markers are pushed (Not Read = 1 and the
	 *       reason "cut by cycle budget twice", no score: peer review item
	 *       2), the kind held back, and the walk steps past it, so an
	 *       object that never fits costs at most two cycles and never pins
	 *       the walk.</li>
	 * </ul>
	 * {@link #finish} clears the cursor when the whole kind was read.
	 */
	private final class KindWalk {
		static final int CONTINUE = 0;
		static final int DROP = 1;
		static final int PUSH_THEN_STOP = 2;

		final BenchmarkSelector.Kind kind;
		final ComplianceRollup rollup;
		final java.util.Set<String> seen;
		private String inFlight;
		private String done;
		private boolean ended;
		private boolean resumed;
		private int refusalsAtStart;

		KindWalk(BenchmarkSelector.Kind kind, ComplianceRollup rollup,
				java.util.Set<String> seen) {
			this.kind = kind;
			this.rollup = rollup;
			this.seen = seen;
		}

		/**
		 * This cycle's objects of the kind, in MOID order: the whole list,
		 * or, resuming a pass (review B1-r2), only the tail after the last
		 * object an early-ended cycle finished. A walk that is not a
		 * resume drops any share carried from an earlier pass.
		 */
		<T> List<T> order(List<T> objects,
				java.util.function.Function<T, String> id) {
			resumed = cycle.resume.resumed(kind, objects, id);
			if (!resumed) cycle.resume.carry(kind, null);
			return cycle.resume.order(kind, objects, id);
		}

		/** False when the walk must stop before {@code moid}. */
		boolean next(String moid, String where) {
			done = inFlight;   // the previous object finished
			if (cycleOver(kind, rollup, where)) {
				cycle.resume.stoppedAfter(kind, done);
				ended = true;
				return false;
			}
			inFlight = moid;
			CycleBudget b = cycleBudget;
			refusalsAtStart = b == null ? 0 : b.refusals();
			return true;
		}

		/** What to do with the object just read (see the class comment). */
		int afterRead(String where) {
			CycleBudget b = cycleBudget;
			if (b == null || b.refusals() == refusalsAtStart) {
				return CONTINUE;
			}
			String why = b.exhausted();
			rollup.markIncomplete(kind);
			ended = true;
			endedIn(kind, why);
			String key = kind.name() + "|" + inFlight;
			if (key.equals(cycle.resume.dropped())) {
				cycle.resume.clearDropped();
				cycle.resume.stoppedAfter(kind, inFlight);
				logWarn("Cycle ended early while reading " + where + ": "
						+ why + ". It was cut the cycle before too, so only "
						+ "Not Read = 1 and the reason (\"cut by cycle budget "
						+ "twice\") are pushed, no score from the partial read, "
						+ "and the walk moves past it; " + kind.rollupName
						+ " and every kind not yet collected are held back "
						+ "(Rollup|incomplete = 1).");
				return PUSH_THEN_STOP;
			}
			cycle.resume.dropped(key);
			cycleDropped = true;
			cycle.resume.stoppedAfter(kind, done);
			logWarn("Cycle ended early while reading " + where + ": " + why
					+ ". It is not pushed this cycle (its last values stay, "
					+ "no partial score); " + kind.rollupName + " and every "
					+ "kind not yet collected are held back (Rollup|"
					+ "incomplete = 1). The next cycle starts with it; cut "
					+ "again, it is pushed flagged and the walk moves on.");
			return DROP;
		}

		/**
		 * Call after the loop, however it ended. Peer review item 3:
		 * <ul>
		 *   <li>Ended early: the kind is held back; what this cycle read of
		 *       it (its rollup share and the objects seen) is added to the
		 *       share carried for the pass.</li>
		 *   <li>Finished, resuming a pass: the carried share and seen
		 *       objects are added to this cycle's, so the kind's rollup
		 *       covers every object and is pushed (not held back), and the
		 *       benchmark memory is trimmed against all of them.</li>
		 *   <li>Finished from the top: nothing carried.</li>
		 * </ul>
		 */
		void finish() {
			ResumeCursor.Carry prior = cycle.resume.carry(kind);
			if (ended) {
				java.util.Set<String> s2 = new java.util.HashSet<>(
						prior == null ? java.util.Collections.<String>emptySet()
								: prior.seen);
				String prefix = kind.name() + "|";
				for (String k2 : seen) {
					if (k2.startsWith(prefix)) s2.add(k2);
				}
				ComplianceRollup.Part now = rollup.part(kind);
				cycle.resume.carry(kind, new ResumeCursor.Carry(
						prior == null ? now : prior.part.plus(now), s2));
				return;
			}
			cycle.resume.completed(kind);
			if (resumed && prior != null) {
				rollup.addPart(kind, prior.part);
				seen.addAll(prior.seen);
			}
			cycle.resume.carry(kind, null);
		}
	}

	/**
	 * Build 103 (issue #17 build 2): one kind's primary bulk read. The
	 * objects the walk will read (in its order, so the resume cursor and
	 * the budget cut work exactly as before) are fetched a page at a time,
	 * one {@code RetrieveProperties} per page ({@link
	 * VSphereClient#retrieveObjects}), with every path any benchmark the
	 * kind can be scored against needs ({@link VSphereClient#primaryPaths}).
	 * The page is fetched when the walk reaches its first object, so the
	 * call (and a refusal by the budget) belongs to that object, and is
	 * released when the next is fetched.
	 *
	 * <p>Fallback, per object: when a page's call fails (a fault, the
	 * response cap, a missing object), or the row lacks a value, that read
	 * is made per object exactly as in build 102 ({@link #row} returns
	 * null, or the reader falls back per control), so a bulk miss yields
	 * the per-object value or UNREADABLE with the per-object reason, never
	 * a pass.
	 */
	private final class BulkPager {
		final String label;
		final String type;
		final java.util.List<VSphereClient.MoRef> order;
		final java.util.Map<String, Integer> index = new java.util.HashMap<>();
		final java.util.Set<String> paths;
		final int pageSize;
		final VSphereClient.BulkStats stats = new VSphereClient.BulkStats();
		private java.util.Map<String, VSphereClient.BulkRow> page =
				java.util.Collections.emptyMap();
		private final java.util.Set<String> pageMoids = new java.util.HashSet<>();
		private final int fallbackAtStart;
		int failedPages;
		int refusedPages;
		int perObject;
		private boolean warned;

		/**
		 * @param order the objects to read in bulk, in walk order (only
		 *              the ones the walk will read: matched, not a Pod)
		 * @param slices every control slice an object of the kind can be
		 *               scored against ({@link BenchmarkSelector#profilesFor})
		 */
		BulkPager(String label, String type,
				java.util.List<VSphereClient.MoRef> order,
				java.util.Collection<java.util.List<BenchmarkProfile.Control>> slices) {
			this.label = label;
			this.type = type;
			this.order = order;
			for (int i = 0; i < order.size(); i++) {
				index.putIfAbsent(order.get(i).value, i);
			}
			this.paths = VSphereClient.primaryPaths(type, slices);
			this.pageSize = bulkPageSize(type);
			this.fallbackAtStart = cycle.vsphere.bulkFallbackReads();
		}

		/**
		 * The object's bulk row, fetching its page first when needed; null
		 * when the object is read per object (no path to read in bulk, not
		 * in the bulk order, its page failed, or vCenter did not return it).
		 */
		VSphereClient.BulkRow row(String moid) {
			if (paths.isEmpty() || moid == null || !index.containsKey(moid)) {
				return null;
			}
			if (!pageMoids.contains(moid)) load(index.get(moid));
			VSphereClient.BulkRow r = page.get(moid);
			if (r == null) perObject++;
			return r;
		}

		private void load(int at) {
			page = java.util.Collections.emptyMap();   // release the last page
			pageMoids.clear();
			java.util.List<VSphereClient.MoRef> refs = order.subList(at,
					Math.min(at + pageSize, order.size()));
			for (VSphereClient.MoRef r : refs) pageMoids.add(r.value);
			try {
				page = cycle.vsphere.retrieveObjects(type, refs, paths, stats);
			} catch (CycleBudget.Exhausted e) {
				// Refused by the cycle budget: the object being read is
				// cut (the walk sees the refusal); no WARN of its own.
				refusedPages++;
			} catch (Exception e) {
				failedPages++;
				if (!warned) {
					warned = true;
					logWarn("Bulk read of " + refs.size() + " " + label
							+ " object(s) failed (" + e.getClass().getSimpleName()
							+ ": " + e.getMessage() + "); they are read one at "
							+ "a time this cycle (the same values, more calls). "
							+ "Further failed " + label + " pages are counted "
							+ "in the bulk read summary.");
				}
			}
		}

		/** One INFO line per kind per cycle. */
		void logSummary() {
			if (paths.isEmpty() || order.isEmpty()) return;
			logInfo("Bulk read " + label + ": " + stats.objects + " of "
					+ order.size() + " object(s) in " + stats.pages
					+ " call(s), " + paths.size() + " path(s)"
					+ (stats.pathFixes > 0 || !stats.droppedPaths.isEmpty()
							? " (vCenter rejected " + stats.pathFixes
							+ " this cycle; dropped " + stats.droppedPaths + ")"
							: "")
					+ ", " + stats.bytes + " bytes (largest page "
					+ stats.maxPageBytes + "); " + perObject + " object(s) "
					+ "read one at a time (" + failedPages + " failed page(s), "
					+ refusedPages + " refused by the cycle budget), "
					+ (cycle.vsphere.bulkFallbackReads() - fallbackAtStart)
					+ " control(s) read one at a time (value not in the bulk "
					+ "read)");
		}
	}

	/**
	 * Build 103: every control slice an object of {@code kind} can be
	 * scored against this cycle (its pin, or every Auto profile).
	 */
	private static java.util.List<java.util.List<BenchmarkProfile.Control>>
			slicesFor(BenchmarkSelector selector, BenchmarkSelector.Kind kind) {
		java.util.List<java.util.List<BenchmarkProfile.Control>> out =
				new java.util.ArrayList<>();
		for (BenchmarkProfile p : selector.profilesFor(kind)) {
			out.add(ComplianceDecisions.sliceFor(p, kind));
		}
		return out;
	}

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
		// Review N13 and W12: one holder (account, clients, the state for
		// the next cycle) for the whole cycle (see the field comment).
		Configured<SuiteApiStitcher, ComplianceStitcher> c = configured;
		if (c == null) {
			throw new IllegalStateException(
					"ComplianceAdapter is not configured");
		}
		cycle = c;
		// Build 95 (issue #17): per-phase time and call counts for the
		// summary line; measurement only.
		CycleMetrics metrics = new CycleMetrics();
		cycleMetrics = metrics;
		if (c.vsphere != null) c.vsphere.setMetrics(metrics);
		if (c.stitcher != null) c.stitcher.setMetrics(metrics);
		// Build 96 (issue #16): the cycle's time budget and breaker.
		CycleBudget.Interval iv = CycleBudget.interval(platformIntervalSec(),
				resourceIntervalSec(worldRc));
		CycleBudget budget = new CycleBudget(CycleBudget.budgetMs(iv.seconds),
				CycleBudget.BREAKER_TIMEOUTS, budgetClock);
		cycleBudget = budget;
		cycleEndedEarly = null;
		cycleEndedIn = null;
		cycleDropped = false;
		String budgetLine = "Cycle limits: time budget "
				+ (budget.budgetMs() / 1000) + " s ("
				+ Math.round(CycleBudget.FRACTION * 100) + "% of the "
				+ iv.seconds + " s interval, " + iv.source + "); a cycle "
				+ "also ends after " + CycleBudget.BREAKER_TIMEOUTS
				+ " vCenter calls in a row time out";
		if (!budgetLine.equals(budgetLogged)) {
			budgetLogged = budgetLine;
			logInfo(budgetLine);
		}
		if (c.vsphere != null) c.vsphere.setCycleBudget(budget);
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
			if (c.vsphere != null) c.vsphere.setMetrics(null);
			if (c.stitcher != null) c.stitcher.setMetrics(null);
			if (c.vsphere != null) c.vsphere.setCycleBudget(null);
			cycleBudget = null;
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
			cycle.vsphere.ensureConnected();
		} catch (Exception e) {
			VCenterCertificates.Failure f = VCenterCertificates.classify(e);
			if (f == null) throw e;
			throw new Exception(VCenterCertificates.message(f,
					cycle.account.vcenterHost), e);
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
		ComplianceStitcher st = cycle.stitcher;
		if (st == null) {
			logWarn("vCenter " + cycle.account.vcenterHost + " not reached this "
					+ "cycle and no Suite API stitcher: Rollup|incomplete "
					+ "cannot be pushed; the last scores stay in place");
			return;
		}
		try {
			String id = ComplianceDecisions.markNotCollected(cycle.lastVcResourceId(),
					() -> {
						st.loadVCenterAdapterInstance();
						ComplianceStitcher.HostEntry he =
								st.matchVCenterAdapterInstance(
										cycle.account.vcenterHost, null);
						return he == null ? null : he.resourceId;
					},
					(rid, stats) -> st.pushStats(rid, stats,
							System.currentTimeMillis()));
			if (id == null) {
				logWarn("vCenter " + cycle.account.vcenterHost + " not reached this "
						+ "cycle (" + cause.getClass().getSimpleName() + "), "
						+ "and its VMwareAdapter Instance could not be "
						+ "resolved without vCenter (no VCURL equal to the "
						+ "entered host): Rollup|incomplete is NOT pushed; "
						+ "the last scores stay in place");
			} else {
				logWarn("vCenter " + cycle.account.vcenterHost + " not reached this "
						+ "cycle (" + cause.getClass().getSimpleName() + "): "
						+ ComplianceRollup.INCOMPLETE_KEY + " = 1 pushed to "
						+ "resource " + id + "; the compliance values shown "
						+ "are from the last completed cycle");
			}
		} catch (RuntimeException e) {
			logWarn("vCenter " + cycle.account.vcenterHost + " not reached this "
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
		cycle.vsphere.beginCycle();

		Path confDir = getAdapterDescribeFile(ADAPTER_KIND, "describe.xml")
				.getParent();   // <adaptersHome>/<kind>/conf
		cycleConfDir = confDir.toString();
		cycleReasons = new UnreadableReasons();
		// Build 95 (point 6): shadow mode from this build's version stamp.
		ShadowMode.Decision shadowMode = ShadowMode.decide(confDir);
		bulkShadow = shadowMode.enabled;
		if (!shadowMode.why.equals(bulkShadowLogged)) {
			bulkShadowLogged = shadowMode.why;
			logInfo("Bulk shadow mode: " + shadowMode.why);
		}
		// Build 90: the overrides file, fetched once per cycle (no fetch when
		// the setting is empty), applied while the selector is built.
		cycleOverridesSnap = refreshOverrides();
		BenchmarkSelector selector = buildSelector(cycleConfDir,
				cycleOverridesSnap.parsed);
		pendingCleanup.clear();

		logInfo("stitcher=" + (cycle.stitcher != null));
		if (cycle.stitcher != null) {
			try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
				loadStitcherResources();
			}
		}

		String vcVersion = null;
		try {
			vcVersion = cycle.vsphere.getVCenterVersion();
		} catch (Exception e) {
			logWarn("Could not read the vCenter version: " + e.getMessage());
		}
		logInfo("Auto (by version): vCenter version=" + vcVersion
				+ " governs vCenter / cluster / vDS / portgroup benchmark "
				+ "choice");

		ComplianceRollup rollup = new ComplianceRollup();
		CycleStats cs = new CycleStats();
		java.util.Set<String> seen = new java.util.HashSet<>();

		// Build 96 (issue #16, review B1): the small kinds first (the
		// vCenter object, switches, portgroups, clusters), then hosts and
		// VMs, so a cycle that ends early on its budget never starves them;
		// hosts and VMs resume where an early-ended cycle stopped
		// (ResumeCursor). VMs still follow hosts (they use the host
		// versions). No kind's score depends on the order.
		// Review B1-r2: one resume point across kinds. The round is fixed
		// (ResumeCursor.ROUND: vCenter object, switches, portgroups,
		// clusters, hosts, VMs); a cycle starts at the kind the last
		// early-ended cycle stopped in and wraps round, so VMs are never
		// skipped for good behind a host walk that overruns. When VMs come
		// before hosts in a cycle they read their host's version on demand
		// (vmHostVersion), the same value. collectVCenter runs every cycle
		// (it resolves the vCenter object the rollup goes to, with no
		// vCenter call once the limit is reached).
		cycle.retiredRepeats.beginCycle();
		// Peer review item 4, round 4 nit 2: the carried cleanup of the kind
		// this cycle resumes, first.
		runCarriedForStartKind(cs);
		ComplianceStitcher.HostEntry vcEntry = null;
		java.util.Map<String, String> hostVersions =
				new java.util.HashMap<>();
		for (BenchmarkSelector.Kind k : cycle.resume.round()) {
			switch (k) {
				case VCENTER:
					try (CycleMetrics.Scope ph = phase(
							CycleMetrics.Phase.VCENTER)) {
						vcEntry = collectVCenter(selector, vcVersion, rollup,
								cs, seen);
					}
					break;
				case VDS:
					try (CycleMetrics.Scope ph = phase(
							CycleMetrics.Phase.NETWORK)) {
						collectDvs(selector, vcVersion, rollup, cs, seen);
					}
					break;
				case PORTGROUP:
					try (CycleMetrics.Scope ph = phase(
							CycleMetrics.Phase.NETWORK)) {
						collectDvpg(selector, vcVersion, rollup, cs, seen);
					}
					break;
				case CLUSTER:
					try (CycleMetrics.Scope ph = phase(
							CycleMetrics.Phase.NETWORK)) {
						collectClusters(selector, vcVersion, rollup, cs, seen);
					}
					break;
				case HOST:
					try (CycleMetrics.Scope ph = phase(
							CycleMetrics.Phase.HOSTS)) {
						hostVersions = collectHosts(selector, rollup, cs, seen);
					}
					break;
				default:
					try (CycleMetrics.Scope ph = phase(
							CycleMetrics.Phase.VMS)) {
						collectVms(selector, hostVersions, rollup, cs, seen);
					}
					break;
			}
			// Build 96 (round 4 nit 2): the kind's cleanup right after its
			// walk, inside the budget.
			cleanKind(k, cs);
		}
		cycle.resume.startAt(cycleEndedIn);
		if (!cycleDropped) cycle.resume.clearDropped();

		// Forget applied-profile history for objects no longer in inventory,
		// only for kinds listed this cycle: a held-back kind (listing or VCF
		// Ops resource list failed) added no keys to seen, and trimming it
		// would drop every remembered benchmark of that kind.
		cycle.memory.retain(seen, rollup.incompleteKinds());
		// Build 96 (review N1-r2): the capped -1 counts, trimmed the same way.
		cycle.retiredRepeats.retain(seen, rollup.incompleteKinds());
		if (cs.skipPushedKeys > 0) {
			// Build 92: the skipped controls are pushed every cycle, so the
			// symptom on each key sees its cancel cycles.
			logInfo("Overrides file '" + cycle.account.overridesFile + "': "
					+ cs.skipPushedKeys + " skipped control key(s) set to -1 "
					+ "(not evaluated) on " + cs.skipPushedObjects
					+ " object(s) this cycle");
		}
		logCleanupSummary(cs);
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
			cycle.rememberVcResourceId(vcEntry.resourceId);
		}
		pushRollup(vcEntry, rollup);
		pushOverridesStatus(vcEntry, out);
		// Known limitation: this edge is added, never removed. A vCenter whose
		// compliance instance is deleted stays a ComplianceWorld child. See
		// knowledge/designs/sdk-adapters/compliance-environment-computed-metrics.md
		linkVCenterToWorld(vcEntry);

		if (cs.unreadable > 0) {
			logWarn(cs.unreadable + " control instance(s) could not be read "
					+ "this cycle (declared-but-unreadable). They were not "
					+ "pushed (their last values stay), they are outside "
					+ "each object's score and the pass rates, each affected "
					+ "object has has_unreadable = 1 with its reason, and its "
					+ "\"Compliance data not collected\" alert fires after "
					+ "two cycles.");
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
				+ (cycleEndedEarly != null ? "; ENDED EARLY: " + cycleEndedEarly
						+ " (" + rollup.incompleteKinds() + " held back)" : "")
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
				cycle.loader.loadAll(confDir);
		logInfo("Benchmark mode: " + BenchmarkSelector.AUTO + " ("
				+ baseProfiles.size() + " bundled profiles loaded; "
				+ cycle.loader.lastManualReviewApplied()
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
		final SuiteApiStitcher sas = cycle.suite;
		OverridesStore.Fetcher fetcher = sas == null ? null : path -> {
			countSuiteCall();
			return sas.get(path);
		};
		OverridesStore.Snapshot snap = overridesStore.refresh(
				cycle.account.overridesFile, fetcher, Instant.now());
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
		if (cycle.stitcher != null && vcEntry != null) {
			cycle.stitcher.pushProperties(vcEntry.resourceId,
					ComplianceDecisions.overridesProps(ComplianceDecisions.K,
							snap.fileName, status), ts);
			cycle.stitcher.pushStats(vcEntry.resourceId,
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
		if (cycle.stitcher == null) {
			return;
		}
		if (vcEntry == null) {
			logWarn("No VMwareAdapter Instance resolved for "
					+ cycle.account.vcenterHost + ": the per-vCenter compliance "
					+ "rollup (VCF-CF Compliance|Rollup|*) is NOT pushed this "
					+ "cycle");
			return;
		}
		java.util.Map<String, Double> stats = rollup.toStats();
		boolean zeroedCustom = cycle.zeroCustomBucketPending()
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
		cycle.stitcher.pushStats(vcEntry.resourceId, stats,
				System.currentTimeMillis());
		if (zeroedCustom) {
			cycle.customBucketZeroed();
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
		SuiteApiStitcher sas = cycle.suite;
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
				logDebug("vCenter " + cycle.account.vcenterHost + " is NOT linked "
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
		// Build 102 (issue #20): objects match on MOID plus this vCenter's
		// UUID only, so a failed read holds every vim25-backed kind back
		// (Rollup|incomplete = 1) instead of matching bare MOIDs.
		try {
			cycle.stitcher.setOwningVcUuid(cycle.vsphere.getVCenterInstanceUuid());
		} catch (Exception e) {
			cycle.stitcher.setOwningVcUuid(null);
			logWarn("Stitcher owning-vCenter UUID unavailable; objects are "
					+ "matched on MOID plus vCenter UUID only, so hosts, VMs, "
					+ "clusters, switches and port groups are held back this "
					+ "cycle: " + e.getMessage());
		}
		safeLoad(() -> cycle.stitcher.loadHostResources(),
				() -> "Stitcher loaded: " + cycle.stitcher.size() + " hosts",
				"loadHostResources");
		safeLoad(() -> cycle.stitcher.loadVmResources(),
				() -> "Stitcher loaded: "
						+ cycle.stitcher.countOfKind("VirtualMachine") + " VMs",
				"loadVmResources");
		safeLoad(() -> cycle.stitcher.loadVCenterAdapterInstance(),
				() -> "Stitcher loaded: "
						+ cycle.stitcher.countOfKind("VMwareAdapter Instance")
						+ " VMwareAdapter Instance(s)",
				"loadVCenterAdapterInstance");
		safeLoad(() -> cycle.stitcher.loadDvsResources(),
				() -> "Stitcher loaded: "
						+ cycle.stitcher.countOfKind(
								"VmwareDistributedVirtualSwitch") + " DVS",
				"loadDvsResources");
		safeLoad(() -> cycle.stitcher.loadDvpgResources(),
				() -> "Stitcher loaded: "
						+ cycle.stitcher.countOfKind("DistributedVirtualPortgroup")
						+ " DVPG",
				"loadDvpgResources");
		safeLoad(() -> cycle.stitcher.loadClusterResources(),
				() -> "Stitcher loaded: "
						+ cycle.stitcher.countOfKind("ClusterComputeResource")
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
	 * with the benchmark the object was last scored against (it can be
	 * several cycles old: a version that stays unreadable, or a kind held
	 * back in between; review N17), so an unreadable version
	 * reuses it instead of dropping the object (review B2).
	 */
	private ComplianceDecisions.Decision decide(BenchmarkSelector selector,
			BenchmarkSelector.Kind kind, String moid, String version) {
		String key = moid == null ? null
				: LastBenchmarkMemory.key(kind, moid);
		ComplianceDecisions.Decision d = ComplianceDecisions.decide(selector,
				kind, version, cycle.memory.previous(key), profilesByName);
		if (d.reusedPrevious) {
			logWarn(kind.rollupName + " " + moid + ": governing "
					+ kind.product + " version unreadable this cycle; scoring "
					+ "against the benchmark it was last scored against, "
					+ d.profileName + " (that can be more than one cycle "
					+ "ago)");
		}
		return d;
	}

	/**
	 * Version unreadable and no previous benchmark (review B2; build 65 W1):
	 * nothing collected. Build 95: only has_unreadable = 1 (raises
	 * "Compliance data not collected" after two cycles), collection_failed
	 * = 1 and the reason are pushed (no score, no counters); counted in the
	 * rollup's unknown bucket only, never no_benchmark, no alert cleanup,
	 * benchmark memory untouched.
	 */
	private void recordVersionUnreadable(BenchmarkSelector.Kind kind,
			String name, ComplianceDecisions.Decision d, String resourceId,
			ComplianceRollup rollup, CycleStats cs) {
		cs.versionUnreadable++;
		rollup.recordVersionUnreadable(kind);
		logWarn(kind.rollupName + " " + name + ": " + d.profileName
				+ " and no previous benchmark; nothing collected: only "
				+ "has_unreadable=1 and the reason are pushed");
		if (resourceId != null) {
			long ts = System.currentTimeMillis();
			// Build 95: nothing readable pushes the flag and the reason
			// only; the last read values stay.
			cycle.stitcher.pushProperties(resourceId,
					ComplianceDecisions.withObjectKind(
							ComplianceDecisions.versionUnreadableProps(
									d.profileName), kind), ts);
			cycle.stitcher.pushStats(resourceId,
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
		String prev = cycle.memory.record(LastBenchmarkMemory.key(kind, moid),
				d.profileName);
		if (prev != null && !prev.equals(d.profileName)) {
			logInfo(kind.rollupName + " " + moid + ": benchmark changed '"
					+ prev + "' -> '" + d.profileName + "'");
		}
		if (resourceId != null && cycle.stitcher != null) {
			java.util.Set<String> live = pushed;
			if (skip != null && !skip.isEmpty()) {
				cs.skipPushedObjects++;
				cs.skipPushedKeys += skip.ids.size();
				live = new java.util.TreeSet<>(pushed);
				live.addAll(skip.ids);
			}
			PendingCleanup pc = new PendingCleanup(kind, resourceId,
					d.profile, d.profileName, live);
			pc.objectKey = LastBenchmarkMemory.key(kind, moid);
			pendingCleanup.add(pc);
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
				cycle.account.overridesFile);
	}

	/**
	 * Build 96 (issue #42, peer review item 4): {@code skip} plus -1 for the
	 * object's retired keys still owed a repeat ({@link RetiredKeyRepeats},
	 * at most 4 -1 pushes per key in all), so the repeats ride the object's
	 * own push, inside the cycle budget, like a Skip. A key pushed with a
	 * value or skipped this cycle is never among them.
	 */
	private ComplianceDecisions.SkipPush withRetiredRepeats(
			ComplianceDecisions.SkipPush skip, BenchmarkSelector.Kind kind,
			String moid, ComplianceDecisions.Decision d,
			ControlEvaluator.ComplianceResult cr) {
		if (moid == null) return skip;
		java.util.Set<String> live = new java.util.HashSet<>(
				ComplianceDecisions.pushedIds(cr));
		if (skip != null) live.addAll(skip.ids);
		// Codex P2 on PR #57: recorded as pending at this time, which the
		// object's push then carries exactly, and counted only when a
		// read-back returns a sample with it.
		long ts = System.currentTimeMillis();
		java.util.Set<String> due = cycle.retiredRepeats.fold(
				LastBenchmarkMemory.key(kind, moid), live, ts);
		return ComplianceDecisions.SkipPush.withRetired(skip, due,
				d.profileName, ts);
	}

	/**
	 * Build 96 (issue #16, peer review item 2): an object cut by the cycle
	 * budget two cycles in a row. Only Not Read = 1 (has_unreadable) and
	 * the reason "cut by cycle budget twice" are pushed, no score, no
	 * counters, no per-control value, so nothing from the partial read is
	 * shown; its last values stay. Counted in the rollup like an object
	 * with nothing read (its benchmark bucket only); the kind is already
	 * held back.
	 */
	private void pushCutTwice(BenchmarkSelector.Kind kind,
			ComplianceDecisions.Decision d, String resourceId,
			ComplianceRollup rollup) {
		rollup.recordEvaluated(kind, d.bucket, 0, 0, 0, 0.0);
		if (resourceId == null || cycle.stitcher == null) return;
		long ts = System.currentTimeMillis();
		cycle.stitcher.pushProperties(resourceId,
				ComplianceDecisions.withObjectKind(
						ComplianceDecisions.cutTwiceProps(), kind), ts);
		cycle.stitcher.pushStats(resourceId,
				ComplianceDecisions.cutTwiceStats(), ts);
	}

	/** One object queued for end-of-cycle cleanup. */
	private static final class PendingCleanup {
		final BenchmarkSelector.Kind kind;
		final String resourceId;
		final BenchmarkProfile profile;   // null: no benchmark
		final String profileName;
		// Build 76: control ids whose Compliant value was pushed this cycle.
		final java.util.Set<String> pushed;
		// Build 96 (review N1-r2): the object's memory key (kind and MOID),
		// which the capped -1 repeat is kept under.
		String objectKey;

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
	 * created, and a missed or failed cleanup is retried next cycle. If a
	 * bulk read fails, that batch is skipped this cycle (logged), with no
	 * fallback. Build 96 (issue #42): a cleaned key, read back at -1, is
	 * pushed -1 again on later cycles while the control stays retired
	 * ({@link ComplianceDecisions#heldNotEvaluatedControls}), up to 4 -1
	 * pushes per key in all (review W1, {@link RetiredKeyRepeats}), so an
	 * alert open on it sees its 3 cancel cycles (before, it got one -1 and
	 * stayed open). The budget is checked before every batch.
	 */
	private void cleanStaleControls(java.util.List<PendingCleanup> entries,
			CycleStats cs) throws InterruptedException {
		if (cycle.stitcher == null || entries.isEmpty()) return;
		cs.cleanupRan = true;
		if (budgetExhausted()) {
			// Build 96 (issue #16, peer review item 4): over budget; the
			// cleanup (VCF Ops reads and pushes only) is carried over.
			carryCleanup(entries, 0, cs);
			return;
		}
		java.util.Map<String, BenchmarkProfile> bundled = bundledForCleanup();
		if (bundled == null) return;
		java.util.Map<BenchmarkSelector.Kind, java.util.List<PendingCleanup>>
				byKind = new java.util.EnumMap<>(BenchmarkSelector.Kind.class);
		for (PendingCleanup p : entries) {
			byKind.computeIfAbsent(p.kind, k -> new java.util.ArrayList<>())
					.add(p);
		}
		java.util.List<PendingCleanup> ordered = new java.util.ArrayList<>();
		for (java.util.List<PendingCleanup> l : byKind.values()) {
			ordered.addAll(l);
		}
		int done = 0;
		for (java.util.Map.Entry<BenchmarkSelector.Kind,
				java.util.List<PendingCleanup>> e : byKind.entrySet()) {
			java.util.List<PendingCleanup> objs = e.getValue();
			for (int i = 0; i < objs.size(); i += CLEANUP_BATCH) {
				stop.check("per-control cleanup of " + e.getKey().rollupName
						+ " objects " + i + "+");
				if (budgetExhausted()) {
					// Build 96 (review W1, peer review item 4): the
					// cleanup's reads and pushes count against the budget;
					// the rest is carried over.
					carryCleanup(ordered, done, cs);
					return;
				}
				done += Math.min(CLEANUP_BATCH, objs.size() - i);
				cleanBatch(e.getKey(), objs.subList(i,
						Math.min(objs.size(), i + CLEANUP_BATCH)),
						bundled.values(), cs);
			}
		}
	}

	/**
	 * Build 60 (review W1): one line per cycle with what the cleanup read
	 * returned, so a read that silently returns nothing is visible and not
	 * mistaken for "nothing stale". Build 96: the cleanup now runs per kind
	 * (after each kind's walk) and for carried entries, so the line sums
	 * them all.
	 */
	private void logCleanupSummary(CycleStats cs) {
		if (!cs.cleanupRan) return;
		logInfo("Stale-control cleanup read: " + cs.cleanupQueried
				+ " object(s) with candidate controls queried in "
				+ cs.cleanupRequests + " request(s); " + cs.cleanupValues
				+ " Compliant value(s) returned; " + cs.cleanedKeys
				+ " stale 0(s) set to -1 on " + cs.cleanedObjects
				+ " object(s); " + cs.heldKeys + " retired key(s) already at "
				+ "-1 pushed -1 again on " + cs.heldObjects + " object(s); "
				+ cs.cleanupSkipped + " object(s) skipped (read failed); "
				+ cs.cleanupCarried + " object(s) carried to the next cycle "
				+ "(budget); " + cs.carriedSuperseded + " carried object(s) "
				+ "superseded by this cycle's visit");
		if (cs.cleanupSkipped > 0) {
			logWarn("Stale-control cleanup skipped for " + cs.cleanupSkipped
					+ " object(s) this cycle (latest-value read failed); "
					+ "retrying next cycle");
		}
	}

	// Objects per cleanup batch; requests within a batch are sized by URL
	// length, so this only bounds the candidate union and memory.
	private static final int CLEANUP_BATCH = 500;

	/**
	 * Build 96 (peer review item 4): keep the cleanup entries from
	 * {@code from} on for a later cycle (in the configured holder). The
	 * retirements they find (a lingering 0 or 1 set to -1) still happen
	 * when every cycle ends early; the repeats ride the objects' own
	 * pushes.
	 */
	private void carryCleanup(java.util.List<PendingCleanup> all, int from,
			CycleStats cs) {
		java.util.List<PendingCleanup> rest = all.subList(from, all.size());
		cycle.deferredCleanup.addAll(rest);
		cs.cleanupCarried += rest.size();
		if (!cs.cleanupSkipLogged) {
			cs.cleanupSkipLogged = true;
			logInfo("Stale-control cleanup skipped this cycle for the rest: "
					+ "the cycle time budget was reached; carried to the "
					+ "next cycle");
		}
	}

	/** Build 96: take the carried entries of {@code kind} (null: none). */
	private java.util.List<PendingCleanup> takeCarried(
			BenchmarkSelector.Kind kind) {
		java.util.List<PendingCleanup> out = new java.util.ArrayList<>();
		synchronized (cycle.deferredCleanup) {
			java.util.Iterator<Object> it = cycle.deferredCleanup.iterator();
			while (it.hasNext()) {
				PendingCleanup p = (PendingCleanup) it.next();
				if (p.kind == kind) {
					out.add(p);
					it.remove();
				}
			}
		}
		return out;
	}

	/**
	 * Build 96 (peer review item 4, round 4 nit 2): at the start of a cycle
	 * that resumes a kind, the carried cleanup of that kind runs before the
	 * walk. Those objects lie before the resume point, so this cycle does
	 * not visit them again and their plan (last cycle's benchmark) still
	 * holds. Carried entries of the other kinds wait for their kind's walk
	 * ({@link #cleanKind}).
	 */
	private void runCarriedForStartKind(CycleStats cs)
			throws InterruptedException {
		BenchmarkSelector.Kind k = cycle.resume.startKind();
		if (k == null) return;
		java.util.List<PendingCleanup> carried = takeCarried(k);
		if (carried.isEmpty()) return;
		logInfo("Stale-control cleanup carried from the last cycle: "
				+ carried.size() + " " + k.rollupName + " object(s)");
		cleanStaleControls(carried, cs);
	}

	/**
	 * Build 96 (round 4 nit 2): after a kind's walk, its cleanup: this
	 * cycle's entries of the kind, plus the entries carried from an earlier
	 * cycle for objects this cycle did NOT visit. A carried entry whose
	 * object was queued again this cycle is dropped: the fresh entry (with
	 * this cycle's benchmark) replaces it, so a key that became live under
	 * a new benchmark never gets a -1 from the old plan.
	 */
	private void cleanKind(BenchmarkSelector.Kind kind, CycleStats cs)
			throws InterruptedException {
		java.util.List<PendingCleanup> mine = new java.util.ArrayList<>();
		java.util.Set<String> queued = new java.util.HashSet<>();
		java.util.Iterator<PendingCleanup> it = pendingCleanup.iterator();
		while (it.hasNext()) {
			PendingCleanup p = it.next();
			if (p.kind == kind) {
				mine.add(p);
				queued.add(p.resourceId);
				it.remove();
			}
		}
		for (PendingCleanup c : takeCarried(kind)) {
			if (queued.contains(c.resourceId)) {
				cs.carriedSuperseded++;
			} else {
				mine.add(c);
			}
		}
		cleanStaleControls(mine, cs);
	}

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
		ComplianceStitcher.LatestRead read = cycle.stitcher.latestCompliant(
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
			java.util.Map<String, Double> objLatest = latest.get(p.resourceId);
			java.util.Set<String> stale = ComplianceDecisions.staleControls(
					plan, objLatest);
			// Build 96 (issue #42, DEF-025): a key already retired to -1
			// gets -1 again on later cycles while the control stays retired
			// (guide version change, or no longer applicable), so its
			// symptom sees the cancel cycles an open alert needs. Same
			// properties and stats call as the retirement itself.
			// Review W1: capped at RetiredKeyRepeats.MAX_PUSHES (4) -1
			// pushes per key, the retirement included; the alert needs 3.
			java.util.Set<String> heldAll =
					ComplianceDecisions.heldNotEvaluatedControls(plan,
							objLatest);
			java.util.Set<String> ids = cycle.retiredRepeats.toPush(
					p.objectKey, stale, heldAll,
					objLatest == null || objLatest.isEmpty(),
					read.times == null ? null : read.times.get(p.resourceId),
					ts);
			java.util.Set<String> held = new java.util.TreeSet<>(ids);
			held.removeAll(stale);
			if (ids.isEmpty()) continue;
			cycle.stitcher.pushProperties(p.resourceId,
					ComplianceDecisions.orphanProps(ids, p.profileName,
							cycleOverrides.skipped,
							cycle.account.overridesFile), ts);
			cycle.stitcher.pushStats(p.resourceId,
					ComplianceDecisions.orphanStats(ids), ts);
			if (!held.isEmpty()) {
				cs.heldObjects++;
				cs.heldKeys += held.size();
			}
			if (stale.isEmpty()) continue;
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
			return cycle.loader.loadAll(cycleConfDir);
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
		boolean present = cycle.stitcher != null;
		boolean failed = present && cycle.stitcher.loadFailed(resourceKind);
		if (ComplianceDecisions.kindPushable(present, failed)) {
			return true;
		}
		rollup.markIncomplete(kind);
		if (failed) {
			logWarn(kind.rollupName + " objects not scored this cycle: the "
					+ "VCF Ops " + resourceKind + " resource list could not "
					+ "be read or scoped to this vCenter (see the "
					+ "ComplianceStitcher WARN above), so no object can be "
					+ "matched or pushed; "
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
		if (cycleOver(BenchmarkSelector.Kind.HOST, rollup, "the host listing")) {
			return hostVersions;   // build 96 (issue #16)
		}
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
						return cycle.vsphere.getHosts();
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
		Shadow shadow = new Shadow("Host", "HostSystem", bulkShadow);
		KindWalk walk = new KindWalk(BenchmarkSelector.Kind.HOST, rollup, seen);
		hosts = walk.order(hosts, h -> h.moid);   // build 96 (review B1)
		// Build 103 (issue #17): the hosts the walk will read, in its
		// order, read in bulk a page at a time.
		java.util.List<VSphereClient.MoRef> bulkOrder =
				new java.util.ArrayList<>();
		if (pushable) {
			for (VSphereClient.HostInfo h : hosts) {
				if (cycle.stitcher.matchHost(h.name, h.moid) != null) {
					bulkOrder.add(h.moRef);
				}
			}
		}
		BulkPager bulk = new BulkPager("Host", "HostSystem", bulkOrder,
				slicesFor(selector, BenchmarkSelector.Kind.HOST));

		for (VSphereClient.HostInfo hostInfo : hosts) {
			stop.check("host " + hostInfo.name);
			if (!walk.next(hostInfo.moid, "host " + hostInfo.name)) {
				break;   // build 96 (issue #16)
			}
			beginObject(BenchmarkSelector.Kind.HOST);
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
			ComplianceStitcher.HostEntry he = cycle.stitcher.matchHost(hostName,
					hostId);
			if (he == null) {
				rollup.recordUnmatched(BenchmarkSelector.Kind.HOST, hostName,
						hostId);
				continue;
			}
			String resourceId = he.resourceId;
			// Build 103: the host's bulk row (null: read per object).
			VSphereClient.BulkRow row = bulk.row(hostId);

			String version = VSphereClient.hostVersionOf(row);
			if (version == null) {
				try {
					version = cycle.vsphere.getHostProductVersion(
							hostInfo.moRef);
				} catch (Exception e) {
					logWarn("Host " + hostName + ": could not read the ESX "
							+ "version (" + e.getMessage() + ")");
				}
			}
			if (hostId != null) hostVersions.put(hostId, version);

			ComplianceDecisions.Decision d = decide(selector,
					BenchmarkSelector.Kind.HOST, hostId,
					BenchmarkSelector.governingVersion(
							BenchmarkSelector.Kind.HOST, null, version));
			if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
				// Round 4 nit 3: a version read refused by the budget is a
				// cut, not "version unreadable".
				int cut = walk.afterRead("host " + hostName);
				if (cut == KindWalk.DROP) break;
				if (cut == KindWalk.PUSH_THEN_STOP) {
					pushCutTwice(BenchmarkSelector.Kind.HOST, d, resourceId,
							rollup);
					break;
				}
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
			// regression). Mark EVERY control UNREADABLE instead (build 95:
			// nothing is pushed per control and no score; the host is
			// flagged has_unreadable with the reason "host not responding"
			// or "host disconnected").
			String connState = VSphereClient.textOf(row,
					"runtime.connectionState");
			if (connState == null) {
				try {
					connState = cycle.vsphere.getHostConnectionState(
							hostInfo.moRef);
				} catch (Exception e) {
					connState = null;  // unknown -> proceed with normal evaluation
				}
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
				// Build 103: config.option from the bulk row (the same
				// list QueryOptions returns, proven on devel); per object
				// when the row does not carry it.
				java.util.Map<String, String> advSettings =
						VSphereClient.advancedOf(row);
				boolean advUnreadable = false;
				String advReason = null;
				if (advSettings == null) {
					try {
						advSettings = cycle.vsphere.getAdvancedSettings(hostInfo.moRef);
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
									hostName, row);
					cr = mergeResults(advCr, vimCr);
				}
			}
			int verdict = walk.afterRead("host " + hostName);
			if (verdict == KindWalk.DROP) {
				break;   // build 96 (review W2): no partial score
			}
			if (verdict == KindWalk.PUSH_THEN_STOP) {
				// Peer review item 2: markers only, never a partial score.
				pushCutTwice(BenchmarkSelector.Kind.HOST, d, resourceId,
						rollup);
				break;
			}
			cs.unreadable += cr.unreadableCount;
			rollup.recordEvaluated(BenchmarkSelector.Kind.HOST, d.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);
			if (!wholeHostUnreadable && row != null) {
				// Build 95: a wholly unreadable host is a known state, not
				// a comparison. Build 103: only a host scored from the bulk
				// read is compared.
				shadow.record(hostId, hostName, hostControls, cr);
			}

			// Build 87: one WARN per host per cycle naming a host whose
			// esxcli reads were skipped (esxcli-host-unreachable).
			String esxcliUnreachable = cycle.vsphere.takeEsxcliUnreachable(hostId);
			if (esxcliUnreachable != null) {
				logWarn("Host " + hostName + ": esxcli request through vCenter "
						+ "failed (" + esxcliUnreachable + "); its remaining "
						+ "esxcli-backed controls are UNREADABLE "
						+ "(esxcli-host-unreachable) for the rest of this cycle. "
						+ "If every host shows this, check vCenter first.");
			}
			if (ComplianceDecisions.nothingReadable(cr)) {
				// Build 95: nothing read -> no score pushed and not in the
				// host counts; flagged (has_unreadable = 1) with its reason.
				logInfo("Host " + hostName + ": UNREADABLE (" + cr.unreadableCount
						+ " controls), no score this cycle: "
						+ objectUnreadable.reasonText(cr.unreadableCount));
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
			if (cr.totalCount > 0) {
				cs.hostsScored++;
				if (ComplianceRollup.isNonCompliant(cr.failCount)) {
					cs.hostsNonCompliant++;
				}
			} else if (ComplianceDecisions.nothingReadable(cr)) {
				cs.hostsWhollyUnreadable++;
			}

			ComplianceDecisions.SkipPush skip =
					skipInForce(BenchmarkSelector.Kind.HOST, d);
			pushComplianceViaClient(resourceId, cr, d.profileName,
					withRetiredRepeats(skip, BenchmarkSelector.Kind.HOST,
							hostId, d, cr));
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
		if (pushable) walk.finish();
		bulk.logSummary();
		runShadow(shadow);
		return hostVersions;
	}

	/**
	 * Build 95 (bulk-collection design build B): one kind's shadow
	 * comparison for this cycle: the results recorded while the kind is
	 * scored, and the controls each object was scored against (its
	 * benchmark's slice), so the other path is evaluated against the same
	 * controls. Build 103: the bulk read is primary, so the recorded side
	 * is the bulk result (only objects scored from a bulk row are
	 * recorded) and the per-object re-read is compared
	 * ({@link ShadowComparator#perObjectCheck}).
	 */
	private static final class Shadow {
		final ShadowComparator comparator;
		final java.util.Map<String, java.util.List<BenchmarkProfile.Control>>
				controls = new java.util.LinkedHashMap<>();
		final java.util.Map<String, String> names = new java.util.HashMap<>();
		String type;

		Shadow(String kind, String type, boolean enabled) {
			this.comparator = ShadowComparator.perObjectCheck(kind, enabled);
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
			if (comparator.isRecorded(moid)) {
				controls.put(moid, slice);
				names.put(moid, name);
			}
		}
	}

	/**
	 * Build 95, reversed in build 103 (issue #17 build 2): in a dev-preview
	 * build, after the kind is scored from the bulk read, each object
	 * scored from it is read again the per-object way (advanced settings
	 * and vim properties, never esxcli) and compared. One INFO summary,
	 * then one INFO line per disagreement (capped). Never changes a score
	 * or a push, never fails the cycle; skipped once the cycle's budget is
	 * used up, and stops early if it runs out during the re-read (the
	 * summary says so). Off in a release build: nothing is recorded and
	 * nothing is read.
	 */
	private void runShadow(Shadow sh) throws InterruptedException {
		// Off (a release build): nothing was recorded, so no re-read.
		if (sh == null || !sh.comparator.hasRecords()) return;
		if (budgetExhausted()) {
			// Build 96 (issue #16): no comparison on a cycle that ended
			// early (its vCenter calls would be refused anyway).
			logInfo("Bulk shadow " + sh.comparator.summaryKind()
					+ ": skipped, the cycle ended early");
			return;
		}
		long t0 = System.nanoTime();
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.SHADOW)) {
			for (java.util.Map.Entry<String,
					java.util.List<BenchmarkProfile.Control>> e
					: sh.controls.entrySet()) {
				String moid = e.getKey();
				stop.check("bulk shadow " + sh.type + " " + moid);
				if (budgetExhausted()) {
					sh.comparator.fail("the cycle time budget ran out "
							+ "during the per-object re-read");
					break;
				}
				sh.comparator.compare(moid, cycle.vsphere.evaluatePerObject(
						new VSphereClient.MoRef(sh.type, moid), e.getValue(),
						sh.names.get(moid)));
			}
		}
		long ms = (System.nanoTime() - t0) / 1_000_000L;
		logInfo(sh.comparator.summary(-1, ms));
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
		if (cycleOver(BenchmarkSelector.Kind.VM, rollup, "the VM listing")) {
			return;   // build 96 (issue #16)
		}
		java.util.List<VSphereClient.VmInfo> vms;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			vms = cycle.vsphere.getVms();
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
		Shadow shadow = new Shadow("VM", "VirtualMachine", bulkShadow);
		KindWalk walk = new KindWalk(BenchmarkSelector.Kind.VM, rollup, seen);
		vms = walk.order(vms, v -> v.moid);   // build 96 (review B1)
		// Build 103 (issue #17): the VMs the walk will read (matched, not
		// a vSphere Pod), in its order, read in bulk a page at a time.
		java.util.List<VSphereClient.MoRef> bulkOrder =
				new java.util.ArrayList<>();
		if (pushable) {
			for (VSphereClient.VmInfo v : vms) {
				if (!ComplianceDecisions.isPodGuestId(v.guestId)
						&& cycle.stitcher.matchVm(v.name, v.moid) != null) {
					bulkOrder.add(v.moRef);
				}
			}
		}
		BulkPager bulk = new BulkPager("VM", "VirtualMachine", bulkOrder,
				slicesFor(selector, BenchmarkSelector.Kind.VM));

		for (VSphereClient.VmInfo vm : vms) {
			stop.check("VM " + vm.name);
			if (!walk.next(vm.moid, "VM " + vm.name)) {
				break;   // build 96 (issue #16)
			}
			beginObject(BenchmarkSelector.Kind.VM);
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
			ComplianceStitcher.HostEntry he = cycle.stitcher.matchVm(vm.name,
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
				// Round 4 nit 3: a version read refused by the budget is a
				// cut, not "version unreadable".
				int cut = walk.afterRead("VM " + vm.name);
				if (cut == KindWalk.DROP) break;
				if (cut == KindWalk.PUSH_THEN_STOP) {
					pushCutTwice(BenchmarkSelector.Kind.VM, d, resourceId,
							rollup);
					break;
				}
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

			// Build 103: the VM's bulk row (null: read per object).
			VSphereClient.BulkRow row = bulk.row(vm.moid);
			ControlEvaluator.ComplianceResult advCr;
			try {
				java.util.Map<String, String> extra =
						VSphereClient.advancedOf(row);
				if (extra == null) {
					extra = cycle.vsphere.getVmExtraConfig(vm.moRef);
				}
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
					evaluateVimForResource(vm.moRef, vmControls, vm.name, row);
			ControlEvaluator.ComplianceResult cr = mergeResults(advCr, vimCr);
			int verdict = walk.afterRead("VM " + vm.name);
			if (verdict == KindWalk.DROP) {
				break;   // build 96 (review W2): no partial score
			}
			if (verdict == KindWalk.PUSH_THEN_STOP) {
				// Peer review item 2: markers only, never a partial score.
				pushCutTwice(BenchmarkSelector.Kind.VM, d, resourceId, rollup);
				break;
			}
			cs.unreadable += cr.unreadableCount;
			rollup.recordEvaluated(BenchmarkSelector.Kind.VM, d.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);
			if (row != null) shadow.record(vm.moid, vm.name, vmControls, cr);

			ComplianceDecisions.SkipPush skip =
					skipInForce(BenchmarkSelector.Kind.VM, d);
			pushComplianceViaClient(resourceId, cr, d.profileName,
					withRetiredRepeats(skip, BenchmarkSelector.Kind.VM,
							vm.moid, d, cr));
			afterPush(BenchmarkSelector.Kind.VM, vm.moid, d, resourceId, cs,
					ComplianceDecisions.pushedIds(cr), skip);
		}
		logInfo("VM compliance: " + cs.vms + " VMs seen, "
				+ rollup.skippedPods() + " vSphere Pod VM(s) skipped (out "
				+ "of scope; named at DEBUG)");
		if (pushable) walk.finish();
		bulk.logSummary();
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
				hostMoid = cycle.vsphere.getVmHostMoid(vm.moRef);
			} catch (Exception e) {
				logWarn("VM " + vm.name + ": could not read runtime.host ("
						+ e.getMessage() + ")");
				return null;
			}
		}
		return ComplianceDecisions.resolveVmHostVersion(hostMoid, hostVersions,
				moid -> {
					try {
						return cycle.vsphere.getHostProductVersion(
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
		String resourceName = cycle.account.vcenterHost;
		String moid = "vcenter";
		beginObject(BenchmarkSelector.Kind.VCENTER);
		seen.add(LastBenchmarkMemory.key(BenchmarkSelector.Kind.VCENTER,
				moid));

		if (cycle.stitcher == null) {
			return null;   // nothing can be pushed; configureAdapter warned
		}
		String vcInstanceUuid = null;
		try {
			vcInstanceUuid = cycle.vsphere.getVCenterInstanceUuid();
		} catch (Exception e) {
			logWarn("Could not read vCenter instance UUID for stitcher "
					+ "lookup: " + e.getMessage());
		}
		ComplianceStitcher.HostEntry he = cycle.stitcher.matchVCenterAdapterInstance(
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
		KindWalk walk = new KindWalk(BenchmarkSelector.Kind.VCENTER, rollup, seen);
		if (!walk.next(moid, "the vCenter object")) {
			// Build 96 (issue #16): not read this cycle, but its object is
			// resolved, so the rollup (incomplete = 1) is still pushed.
			return he;
		}
		String resourceId = he.resourceId;

		ComplianceDecisions.Decision d = decide(selector,
				BenchmarkSelector.Kind.VCENTER, moid,
				BenchmarkSelector.governingVersion(
						BenchmarkSelector.Kind.VCENTER, vcVersion, null));
		if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
			// Round 4 nit 3: a version read refused by the budget is a cut.
			int cut = walk.afterRead("the vCenter object");
			if (cut == KindWalk.PUSH_THEN_STOP) {
				pushCutTwice(BenchmarkSelector.Kind.VCENTER, d, resourceId,
						rollup);
			}
			if (cut != KindWalk.CONTINUE) return he;
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
					cycle.vsphere.getVCenterAdvancedSettings();
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
		// Build 96 (review W2, B1-r2): a call refused while the vCenter was
		// read drops it this cycle (no partial score); cut two cycles in a
		// row, it is pushed flagged.
		int verdict = walk.afterRead("the vCenter object");
		if (verdict == KindWalk.DROP) {
			return he;
		}
		if (verdict == KindWalk.PUSH_THEN_STOP) {
			// Peer review item 2: markers only, never a partial score.
			pushCutTwice(BenchmarkSelector.Kind.VCENTER, d, resourceId, rollup);
			return he;
		}

		cs.unreadable += cr.unreadableCount;
		rollup.recordEvaluated(BenchmarkSelector.Kind.VCENTER, d.bucket,
				cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);

		ComplianceDecisions.SkipPush skip =
				skipInForce(BenchmarkSelector.Kind.VCENTER, d);
		pushComplianceViaClient(resourceId, cr, d.profileName,
				withRetiredRepeats(skip, BenchmarkSelector.Kind.VCENTER, moid,
						d, cr));
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
		if (cycle.stitcher == null) return;   // nothing to push onto; skip the reads
		if (cycleOver(BenchmarkSelector.Kind.VDS, rollup,
				"the distributed switch listing")) {
			return;   // build 96 (issue #16)
		}
		java.util.List<VSphereClient.DvsInfo> switches;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			switches = cycle.vsphere.getDvSwitches();
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
		Shadow shadow = new Shadow("vDS", switches.get(0).moRef.type,
				bulkShadow);
		KindWalk walk = new KindWalk(BenchmarkSelector.Kind.VDS, rollup, seen);
		switches = walk.order(switches, o -> o.moid);   // build 96 (review B1)
		java.util.List<VSphereClient.MoRef> bulkOrder =
				new java.util.ArrayList<>();
		for (VSphereClient.DvsInfo o : switches) {
			if (cycle.stitcher.matchDvs(o.name, o.moid) != null) {
				bulkOrder.add(o.moRef);
			}
		}
		BulkPager bulk = new BulkPager("vDS", switches.get(0).moRef.type,
				bulkOrder, slicesFor(selector, BenchmarkSelector.Kind.VDS));
		for (VSphereClient.DvsInfo dvs : switches) {
			stop.check("vDS " + dvs.name);
			if (!walk.next(dvs.moid, "vDS " + dvs.name)) {
				break;   // build 96 (issue #16)
			}
			cs.dvs++;
			ComplianceStitcher.HostEntry he = cycle.stitcher.matchDvs(dvs.name,
					dvs.moid);
			if (collectVimObject(BenchmarkSelector.Kind.VDS, dvs.moRef,
					dvs.name, dvs.moid, he, selector, vcVersion, rollup, cs,
					seen, shadow, walk, bulk) != KindWalk.CONTINUE) {
				break;   // build 96 (review W2, B1-r2)
			}
		}
		walk.finish();
		bulk.logSummary();
		runShadow(shadow);
	}

	private void collectDvpg(BenchmarkSelector selector, String vcVersion,
			ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen) throws InterruptedException {
		if (cycle.stitcher == null) return;
		if (cycleOver(BenchmarkSelector.Kind.PORTGROUP, rollup,
				"the portgroup listing")) {
			return;   // build 96 (issue #16)
		}
		java.util.List<VSphereClient.DvpgInfo> pgs;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			pgs = cycle.vsphere.getDvPortgroups();
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
		Shadow shadow = new Shadow("Portgroup", pgs.get(0).moRef.type,
				bulkShadow);
		KindWalk walk = new KindWalk(BenchmarkSelector.Kind.PORTGROUP, rollup, seen);
		pgs = walk.order(pgs, o -> o.moid);   // build 96 (review B1)
		java.util.List<VSphereClient.MoRef> bulkOrder =
				new java.util.ArrayList<>();
		for (VSphereClient.DvpgInfo o : pgs) {
			if (cycle.stitcher.matchDvpg(o.name, o.moid) != null) {
				bulkOrder.add(o.moRef);
			}
		}
		BulkPager bulk = new BulkPager("Portgroup", pgs.get(0).moRef.type,
				bulkOrder, slicesFor(selector, BenchmarkSelector.Kind.PORTGROUP));
		for (VSphereClient.DvpgInfo pg : pgs) {
			stop.check("portgroup " + pg.name);
			if (!walk.next(pg.moid, "portgroup " + pg.name)) {
				break;   // build 96 (issue #16)
			}
			cs.dvpg++;
			ComplianceStitcher.HostEntry he = cycle.stitcher.matchDvpg(pg.name,
					pg.moid);
			if (collectVimObject(BenchmarkSelector.Kind.PORTGROUP, pg.moRef,
					pg.name, pg.moid, he, selector, vcVersion, rollup, cs,
					seen, shadow, walk, bulk) != KindWalk.CONTINUE) {
				break;   // build 96 (review W2, B1-r2)
			}
		}
		walk.finish();
		bulk.logSummary();
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
		if (cycle.stitcher == null) return;
		if (cycleOver(BenchmarkSelector.Kind.CLUSTER, rollup,
				"the cluster listing")) {
			return;   // build 96 (issue #16)
		}
		java.util.List<VSphereClient.ClusterInfo> clusters;
		try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase.INVENTORY)) {
			clusters = cycle.vsphere.getClusters();
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
		Shadow shadow = new Shadow("Cluster", clusters.get(0).moRef.type,
				bulkShadow);
		KindWalk walk = new KindWalk(BenchmarkSelector.Kind.CLUSTER, rollup, seen);
		clusters = walk.order(clusters, o -> o.moid);   // build 96 (review B1)
		java.util.List<VSphereClient.MoRef> bulkOrder =
				new java.util.ArrayList<>();
		for (VSphereClient.ClusterInfo o : clusters) {
			if (cycle.stitcher.matchCluster(o.name, o.moid) != null) {
				bulkOrder.add(o.moRef);
			}
		}
		BulkPager bulk = new BulkPager("Cluster", clusters.get(0).moRef.type,
				bulkOrder, slicesFor(selector, BenchmarkSelector.Kind.CLUSTER));
		for (VSphereClient.ClusterInfo cluster : clusters) {
			stop.check("cluster " + cluster.name);
			if (!walk.next(cluster.moid, "cluster " + cluster.name)) {
				break;   // build 96 (issue #16)
			}
			cs.clusters++;
			ComplianceStitcher.HostEntry he = cycle.stitcher.matchCluster(
					cluster.name, cluster.moid);
			if (collectVimObject(BenchmarkSelector.Kind.CLUSTER,
					cluster.moRef, cluster.name, cluster.moid, he, selector,
					vcVersion, rollup, cs, seen, shadow, walk, bulk)
					!= KindWalk.CONTINUE) {
				break;   // build 96 (review W2, B1-r2)
			}
		}
		walk.finish();
		bulk.logSummary();
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
	private int collectVimObject(BenchmarkSelector.Kind kind,
			VSphereClient.MoRef moRef, String name, String moid,
			ComplianceStitcher.HostEntry he, BenchmarkSelector selector,
			String vcVersion, ComplianceRollup rollup, CycleStats cs,
			java.util.Set<String> seen, Shadow shadow, KindWalk walk,
			BulkPager bulk) {
		beginObject(kind);
		if (moid != null) seen.add(LastBenchmarkMemory.key(kind, moid));
		if (he == null) {
			rollup.recordUnmatched(kind, name, moid);
			return KindWalk.CONTINUE;
		}
		String resourceId = he.resourceId;

		ComplianceDecisions.Decision d = decide(selector, kind, moid,
				BenchmarkSelector.governingVersion(kind, vcVersion, null));
		if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
			// Round 4 nit 3: a version read refused by the budget is a cut.
			int cut = walk.afterRead(kind.rollupName + " " + name);
			if (cut == KindWalk.PUSH_THEN_STOP) {
				pushCutTwice(kind, d, resourceId, rollup);
			}
			if (cut != KindWalk.CONTINUE) return cut;
			recordVersionUnreadable(kind, name, d, resourceId, rollup, cs);
			return KindWalk.CONTINUE;
		}
		if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
			recordNoBenchmark(kind, name, moid, d, resourceId, rollup, cs);
			return KindWalk.CONTINUE;
		}
		java.util.List<BenchmarkProfile.Control> controls =
				ComplianceDecisions.sliceFor(d.profile, kind);
		ControlEvaluator.ComplianceResult cr;
		// Build 103: the object's bulk row (null: read per object).
		VSphereClient.BulkRow row = null;
		// Review N4: gate on vim_property AND esxcli, the same kinds
		// BenchmarkSelector.evaluatedFor and the alert generator admit here.
		if (countEvaluable(controls, "vim_property")
				+ countEvaluable(controls, "esxcli") == 0) {
			cr = emptyResult(name);
		} else if (kind == BenchmarkSelector.Kind.CLUSTER) {
			row = bulk.row(moid);
			Boolean vsan = VSphereClient.vsanOf(row);
			if (vsan == null) {
				vsan = probeVsan(moRef, name);   // per object
			} else if (!vsan) {
				logDebug("Cluster " + name + ": vSAN not enabled; vSAN "
						+ "controls not applicable (profile_name only)");
			}
			if (vsan == null) {
				cr = null;                    // probe failed: unreadable
			} else if (!vsan) {
				cr = emptyResult(name);       // non-vSAN: genuinely N/A
			} else {
				cr = readAndEvaluateVim(moRef, controls, name, row);
				if (cr != null && row != null) {
					shadow.record(moid, name, controls, cr);
				}
			}
		} else {
			row = bulk.row(moid);
			cr = readAndEvaluateVim(moRef, controls, name, row);
			if (cr != null && row != null) {
				shadow.record(moid, name, controls, cr);
			}
		}
		if (cr == null) {
			cr = unreadableVimResult(controls, name);
			noteUnreadable(name, lastObjectFailure, cr.unreadableCount);
		}
		int verdict = walk.afterRead(kind.rollupName + " " + name);
		if (verdict == KindWalk.DROP) {
			return verdict;   // build 96 (review W2): no partial score
		}
		if (verdict == KindWalk.PUSH_THEN_STOP) {
			// Peer review item 2: markers only, never a partial score.
			pushCutTwice(kind, d, resourceId, rollup);
			return verdict;
		}
		cs.unreadable += cr.unreadableCount;
		rollup.recordEvaluated(kind, d.bucket, cr.totalCount, cr.failCount,
				cr.unreadableCount, cr.score);
		ComplianceDecisions.SkipPush skip = skipInForce(kind, d);
		pushOrProfileName(resourceId, cr, d.profileName,
				withRetiredRepeats(skip, kind, moid, d, cr));
		afterPush(kind, moid, d, resourceId, cs,
				ComplianceDecisions.pushedIds(cr), skip);
		return verdict;
	}

	/**
	 * vSAN presence for a cluster: TRUE when vSAN is configured, FALSE for a
	 * non-vSAN cluster (vSAN controls genuinely N/A), NULL when the probe
	 * itself failed (unreadable, never "not vSAN").
	 */
	private Boolean probeVsan(VSphereClient.MoRef moRef, String name) {
		try {
			boolean enabled = cycle.vsphere.hasVsanConfig(moRef);
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
			java.util.List<BenchmarkProfile.Control> controls, String name,
			VSphereClient.BulkRow row) {
		java.util.Map<String, Object> values;
		try {
			values = cycle.vsphere.readVimProperties(moRef, controls, row);
		} catch (Exception e) {
			logWarn("Failed to read vim properties for " + name + ": "
					+ e.getMessage() + "; controls marked UNREADABLE");
			lastObjectFailure = "exception: " + e.getClass().getSimpleName()
					+ ": " + e.getMessage();
			return null;
		}
		noteReadReasons(name, controls, values, cycle.vsphere.lastReadReasons());
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
			String resourceName, VSphereClient.BulkRow row) {
		int evaluableCount = countEvaluable(controls, "vim_property")
				+ countEvaluable(controls, "esxcli");
		if (evaluableCount == 0) {
			return emptyResult(resourceName);
		}
		java.util.Map<String, Object> values;
		try {
			values = cycle.vsphere.readVimProperties(moRef, controls, row);
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
				cycle.vsphere.lastReadReasons());
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

	/**
	 * Build 95: the unreadable reasons of the object being read now,
	 * published on it as unreadable_reason. Reset by {@link #beginObject}
	 * before each object (one collect thread per instance).
	 */
	private ObjectUnreadable objectUnreadable = new ObjectUnreadable();

	/** Build 95: the kind of the object being read now (object_kind). */
	private BenchmarkSelector.Kind objectKind;

	/** Build 95: start recording the next object's unreadable reasons. */
	private void beginObject(BenchmarkSelector.Kind kind) {
		objectUnreadable = new ObjectUnreadable();
		objectKind = kind;
	}

	/** Record {@code count} unreadable controls on one object for a reason. */
	private void noteUnreadable(String resourceName, String reason, int count) {
		if (count <= 0) return;
		cycleReasons.record(reason, count);
		objectUnreadable.record(reason, count);
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
			objectUnreadable.record(why, 1);
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
				cycle.account.baseUrl(), cycle.account.username,
				cycle.account.password, sslContextFor(cycle.account.vcenterHost),
				this::logWarn);
		client.setCycleBudget(cycleBudget);   // build 96 (review N10)
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
		objectUnreadable.record(why, 1);
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
				total, unreadable, ControlEvaluator.score(pass, fail),
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
		java.util.Map<String, String> props = new java.util.LinkedHashMap<>(
				ComplianceDecisions.profileNameProps(profileName));
		props.putAll(ComplianceDecisions.unreadableProps("", ""));
		props = ComplianceDecisions.withObjectKind(props, objectKind);
		ComplianceDecisions.pushObject(cycle.stitcher, resourceId, props,
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
		java.util.Map<String, String> props = new java.util.LinkedHashMap<>(
				ComplianceDecisions.profileNameProps(label));
		props.putAll(ComplianceDecisions.unreadableProps("", ""));
		props = ComplianceDecisions.withObjectKind(props, objectKind);
		cycle.stitcher.pushProperties(resourceId, props, ts);
		cycle.stitcher.pushStats(resourceId, ComplianceDecisions.noBenchmarkStats(),
				ts);
	}

	/**
	 * Publish per-control results and aggregates onto a matched VMWARE
	 * resource. Keys are profile-free
	 * ({@code VCF-CF Compliance|<control_id>|...}); the payload is built by
	 * {@link ComplianceDecisions#complianceStats} /
	 * {@link ComplianceDecisions#complianceProps}: Compliant 1 / 0 for
	 * every control read (build 95: an unreadable control is not pushed),
	 * score = passed over evaluated whenever a control was read (build 95:
	 * unreadable is in neither count), counters, non_compliant = a failing
	 * control, has_unreadable and the reason, no_benchmark = 0; with
	 * nothing read, the unreadable signals only.
	 */
	private void pushComplianceViaClient(String resourceId,
			ControlEvaluator.ComplianceResult cr, String profileName,
			ComplianceDecisions.SkipPush skip) {
		ComplianceDecisions.pushObject(cycle.stitcher, resourceId,
				ComplianceDecisions.withObjectKind(
						ComplianceDecisions.complianceProps(cr, profileName,
								siteOverriddenFor(profileName),
								objectUnreadable.reasonText(cr.unreadableCount)),
						objectKind),
				ComplianceDecisions.complianceStats(cr), skip,
				System.currentTimeMillis());
	}

	/** Per-cycle counters for the completion log line. */
	private static final class CycleStats {
		int hosts; int vms; int dvs; int dvpg; int clusters;
		int hostsScored; int hostsNonCompliant; int hostsWhollyUnreadable;
		int noBenchmark; int versionUnreadable; int unreadable;
		int cleanedObjects; int cleanedKeys; int cleanupSkipped;
		int heldObjects; int heldKeys;
		int cleanupCarried; int carriedSuperseded;
		boolean cleanupRan; boolean cleanupSkipLogged;
		int cleanupQueried; int cleanupRequests; int cleanupValues;
		int skipPushedObjects; int skipPushedKeys;
	}

	// -----------------------------------------------------------------------
	// onDiscard
	// -----------------------------------------------------------------------

	@Override
	public void onDiscard() {
		// Review W4: the holder keeps the released clients, so a cycle
		// still running never meets a null client. Review N14: only the
		// vSphere client is closed; that cycle's remaining vCenter
		// inventory reads fail instead of logging in again. The Suite API
		// client is not closed (discard only releases its token, and its
		// next call acquires a new one), so a cycle spanning an edit or a
		// discard logs in to the local VCF Ops again, keeps pushing to its
		// own objects, and leaves that one token unreleased until it
		// expires. A closed state in the Suite API client is framework
		// code.
		Configured<SuiteApiStitcher, ComplianceStitcher> c = configured;
		if (c != null) {
			releaseClients(c.vsphere, c.suite);
		}
		super.onDiscard();
	}

	/**
	 * Build 95 (issue #23): log the vCenter session out and release the
	 * Suite API token. Used by configure (after the new holder is
	 * published, review W4) and by discard. {@code disconnect()} marks the
	 * vCenter client closed first, so a cycle still using it fails its
	 * calls instead of logging in again, and bounds the Logout wait
	 * ({@code VSphereClient.LOGOUT_TIMEOUT_MS}). Never throws: a failed
	 * logout leaves only an idle session for vCenter to expire. Review
	 * N14: the Suite API client is not closed and acquires a new token if
	 * a cycle still running calls it again (see onDiscard).
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
