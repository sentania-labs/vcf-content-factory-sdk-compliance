package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.VcfCfAdapter;
import com.vcfcf.adapter.http.ManagedHttpClient;
import com.vcfcf.adapter.json.SimpleJson;
import com.vcfcf.adapter.spi.VcfCfCollector;
import com.vcfcf.adapter.spi.VcfCfDiscoverer;
import com.vcfcf.adapter.spi.VcfCfTester;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import com.integrien.alive.common.adapter3.AdapterBase;
import com.integrien.alive.common.adapter3.Logger;
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

	public ComplianceAdapter() {
		super();
	}

	public ComplianceAdapter(String adapterDir, Integer adapterInstanceId) {
		super(adapterDir, adapterInstanceId);
	}

	@Override
	public boolean isDynamicMetricsAllowed() {
		return true;
	}

	// -----------------------------------------------------------------------
	// onDescribe — provided by the framework base (VcfCfAdapter, commit
	// 750e0ee). The default resolves getAdapterDescribeFile(getAdapterKind(),
	// "describe.xml") and AdapterDescribe.make(is) — byte-for-byte the behavior
	// this adapter used to override, so the explicit override was removed in
	// build 44 (less code to maintain; getAdapterKind() == "vcfcf_compliance").
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
				adapterLogger());

		this.benchmarkLoader = new BenchmarkLoader();

		// Ambient Suite API stitching — reads maintenanceuser.properties,
		// decrypts via the platform SDK Crypt, targets https://localhost/
		// suite-api as maintenanceAdmin. If the credential file is absent
		// (e.g. a remote collector), create() throws; stitching is then
		// disabled for the cycle and the collect path logs the gap rather
		// than aborting.
		try {
			this.suiteStitcher = SuiteApiStitcher.create(this, adapterLogger());
			this.stitcher = new ComplianceStitcher(
					this.suiteStitcher, adapterLogger());
		} catch (RuntimeException e) {
			this.suiteStitcher = null;
			this.stitcher = null;
			logWarn("Ambient Suite API stitcher unavailable — compliance data "
					+ "will not be pushed onto VMWARE resources this instance: "
					+ e.getMessage());
		}

		logInfo("ComplianceAdapter configured: vcenter=" + config.vcenterHost
				+ " profile=" + config.benchmarkProfile
				+ " stitcher=" + (stitcher != null));
	}

	/**
	 * Expose the v2 base's instance logger to the adapter's helper classes
	 * (the stitcher and SuiteApiStitcher take a {@link Logger}). The base's
	 * private {@code adapterLogger()} builds the same instance from the same
	 * factory; this thin accessor reuses that factory.
	 */
	private Logger adapterLogger() {
		return getAdapterLoggerFactory().getLogger(getClass());
	}

	// -----------------------------------------------------------------------
	// getTester
	// -----------------------------------------------------------------------

	@Override
	protected VcfCfTester<ComplianceConfig> getTester() {
		return (cfg, http, param) -> {
			vcApi.login();
			SimpleJson hosts = vcApi.listHosts();
			int count = 0;
			if (!hosts.isNull() && hosts.isList()) {
				count = hosts.asList().size();
			}
			logInfo("Test OK: connected to " + cfg.vcenterHost
					+ ", " + count + " host(s) visible");
		};
	}

	// -----------------------------------------------------------------------
	// getDiscoverer — the single synthetic ComplianceWorld resource
	// -----------------------------------------------------------------------

	@Override
	protected VcfCfDiscoverer<ComplianceConfig> getDiscoverer() {
		return (cfg, http, param, dr) -> {
			logInfo("ComplianceAdapter discover: creating ComplianceWorld");
			dr.addResource(worldResourceConfig());
		};
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

			java.util.Map<String, String> advSettings;
			try {
				advSettings = vsphere.getAdvancedSettings(hostInfo.moRef);
			} catch (Exception e) {
				logWarn("Failed to read settings for " + hostName + ": "
						+ e.getMessage());
				advSettings = new java.util.HashMap<>();
			}

			ControlEvaluator.ComplianceResult advCr =
					ControlEvaluator.evaluateControls(
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
		return stats;
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
	 * resource. Key set and value semantics are byte-identical to v1 (the
	 * golden-comparison contract).
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
		stats.put("VCF-CF Compliance|score", cr.score);
		stats.put("VCF-CF Compliance|pass_count", (double) cr.passCount);
		stats.put("VCF-CF Compliance|fail_count", (double) cr.failCount);
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
