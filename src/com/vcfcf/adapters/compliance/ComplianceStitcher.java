package com.vcfcf.adapters.compliance;

import com.integrien.alive.common.adapter3.Logger;
import com.vcfcf.adapter.json.SimpleJson;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * v2 compliance stitcher — resolves foreign VMWARE resource UUIDs via the
 * framework {@link SuiteApiStitcher} facade and pushes per-control / rollup
 * data onto them.
 *
 * <p><b>v1 → v2 change.</b> v1 held an aria-ops-core {@code SuiteAPIClient}
 * (injected on {@code UnlicensedAdapter}) and used the
 * {@code com.vmware.ops.api.model.resource.ResourceDto} model + heavy
 * reflection to resolve resources and invoke {@code addProperties}/{@code
 * addStats}. v2 has no aria-ops-core and no {@code com.vmware.ops.*} on the
 * classpath: all transport goes through the ambient {@link SuiteApiStitcher},
 * which acquires/releases a Suite API token per call as {@code
 * maintenanceAdmin}. Resource resolution is now a plain authenticated
 * {@code GET /api/resources?...} parsed with {@link SimpleJson}; pushes go
 * through {@link SuiteApiStitcher#pushProperties}/{@link
 * SuiteApiStitcher#pushStats}.
 *
 * <p>The identity rules are preserved from v1 (the MOID trap): all vim25-backed
 * VMWARE kinds resolve by {@code VMEntityName} (name) +
 * {@code VMEntityObjectID} (moid); the non-vim25 {@code VMwareAdapter Instance}
 * resolves by {@code VMEntityVCID} (vCenter Instance UUID), or an exact
 * {@code VCURL} (vCenter FQDN) only when the UUID is unreadable. moid is tried
 * first (most authoritative), then exact name, then dot-prefix fuzzy match
 * (FQDN/shortname tolerance).
 *
 * <p><b>Cross-vCenter MOID scoping (the MOID trap — fix, build 51).</b> A bare
 * MOID like {@code host-12} / {@code vm-42} is <b>NOT unique across
 * vCenters</b> — in a multi-vCenter VCF Ops (e.g. the devel mgmt + wld01
 * instances) the {@code /api/resources} load returns every vCenter's
 * {@code host-12}, and the by-moid index keeps only the last writer, so a push
 * can land on the wrong vCenter's host. v1 inherited the unscoped matcher;
 * this build restores per-vCenter scoping: {@link #setOwningVcUuid} pins the
 * vCenter Instance UUID this adapter instance monitors (from
 * {@code VSphereClient.getVCenterInstanceUuid()}, called once per cycle before
 * the {@code load*} calls), and every loaded vim25-backed foreign resource is
 * filtered to that UUID by its {@code VMEntityVCID}. A resource belonging to a
 * different vCenter is skipped; a row whose {@code VMEntityVCID} is unknown, or
 * when the owning UUID itself is unknown, degrades to the unscoped behaviour
 * (logged) rather than dropping the resource. Single-vCenter deployments are
 * unaffected either way. (sdk-adapter-reviewer, vcommunity build 1 —
 * MOID-trap WARNING; same defect confirmed corpus-wide.)
 *
 * <p>The Suite API {@code /api/resources} response shape consumed here:
 * <pre>
 * { "resourceList": [
 *     { "identifier": "&lt;uuid&gt;",
 *       "resourceKey": {
 *         "name": "&lt;display name&gt;",
 *         "resourceIdentifiers": [
 *           { "identifierType": { "name": "VMEntityName" }, "value": "esx1..." },
 *           { "identifierType": { "name": "VMEntityObjectID" }, "value": "host-12" }
 *         ] } } ] }
 * </pre>
 */
public final class ComplianceStitcher {

	private final SuiteApiStitcher stitcher;
	private final Logger logger;

	// Per-VMWARE-resource-kind name/moid lookup tables.
	private final Map<String, Map<String, HostEntry>> resourcesByName =
			new HashMap<>();
	private final Map<String, Map<String, HostEntry>> resourcesByMoid =
			new HashMap<>();

	// VMwareAdapter Instance-only indexes — keyed by VCURL (FQDN) and
	// VMEntityVCID (vCenter Instance UUID).
	private final Map<String, HostEntry> vcByHost = new HashMap<>();
	private final Map<String, HostEntry> vcByVcUuid = new HashMap<>();

	// The vCenter Instance UUID this adapter instance monitors. When set, the
	// vim25-backed loaders keep only foreign resources whose VMEntityVCID
	// matches it, so a bare MOID can never resolve to a same-MOID resource in
	// another vCenter (the MOID trap). Null disables scoping (degrades to the
	// unscoped matcher — single-vCenter safe).
	private volatile String owningVcUuid;

	public ComplianceStitcher(SuiteApiStitcher stitcher, Logger logger) {
		this.stitcher = stitcher;
		this.logger = logger;
	}

	/**
	 * Pin the owning vCenter Instance UUID (from
	 * {@code VSphereClient.getVCenterInstanceUuid()}). Call once per cycle
	 * BEFORE the {@code load*} calls. A null/blank value disables scoping
	 * (degrades to the unscoped matcher — single-vCenter safe).
	 */
	public void setOwningVcUuid(String vcUuid) {
		this.owningVcUuid = (vcUuid != null && !vcUuid.isEmpty()) ? vcUuid : null;
	}

	public void loadHostResources() {
		loadResourcesForKind("HostSystem");
	}

	public void loadVmResources() {
		loadResourcesForKind("VirtualMachine");
	}

	public void loadVCenterAdapterInstance() {
		loadVCenterAdapterInstanceByIdentity();
	}

	public void loadDvsResources() {
		loadResourcesForKind("VmwareDistributedVirtualSwitch");
	}

	public void loadDvpgResources() {
		loadResourcesForKind("DistributedVirtualPortgroup");
	}

	public void loadClusterResources() {
		loadResourcesForKind("ClusterComputeResource");
	}

	/**
	 * VMwareAdapter Instance has no MoRef-style identity tuple — the
	 * {@code VMEntityName}/{@code VMEntityObjectID} pair comes back null on
	 * these resources. We extract the two platform-stable identity fields
	 * that DO exist ({@code VCURL} = vCenter FQDN, {@code VMEntityVCID} =
	 * vCenter Instance UUID), plus the resource key's display name as a
	 * third index.
	 */
	private void loadVCenterAdapterInstanceByIdentity() {
		String resourceKind = "VMwareAdapter Instance";
		Map<String, HostEntry> byName = new HashMap<>();
		Map<String, HostEntry> byMoid = new HashMap<>();
		resourcesByName.put(resourceKind, byName);
		resourcesByMoid.put(resourceKind, byMoid);
		vcByHost.clear();
		vcByVcUuid.clear();

		List<SimpleJson> resources = fetchResources(resourceKind);
		if (resources.isEmpty()) {
			logger.warn("ComplianceStitcher: /api/resources(" + resourceKind
					+ ") returned 0 results — adapter has no vCenter adapter "
					+ "instances in inventory");
			return;
		}

		logger.info("ComplianceStitcher: " + resourceKind
				+ " — processing " + resources.size() + " resource(s)");

		for (SimpleJson r : resources) {
			String uuid = findUuid(r);
			if (uuid == null) continue;
			SimpleJson key = r.get("resourceKey");
			String displayName = key.get("name").asString(null);
			String vcurl = getIdValue(key, "VCURL");
			String vcUuid = getIdValue(key, "VMEntityVCID");

			HostEntry entry = new HostEntry(uuid, displayName, vcurl);

			if (displayName != null && !displayName.isEmpty()) {
				byName.put(displayName, entry);
			}
			if (vcurl != null && !vcurl.isEmpty()) {
				vcByHost.put(vcurl, entry);
			}
			if (vcUuid != null && !vcUuid.isEmpty()) {
				vcByVcUuid.put(vcUuid, entry);
			}
			logger.info("ComplianceStitcher: " + resourceKind
					+ " indexed: name=" + displayName
					+ " VCURL=" + vcurl
					+ " VMEntityVCID=" + vcUuid
					+ " -> resourceId=" + entry.resourceId);
		}

		logger.info("ComplianceStitcher: loaded "
				+ byName.size() + " " + resourceKind + " by displayName, "
				+ vcByHost.size() + " by VCURL, "
				+ vcByVcUuid.size() + " by VMEntityVCID");
	}

	/**
	 * Shared loader for any vim25-backed VMWARE resource kind. All such
	 * kinds share the {@code VMEntityName} + {@code VMEntityObjectID}
	 * identity tuple.
	 */
	private void loadResourcesForKind(String resourceKind) {
		Map<String, HostEntry> byName = new HashMap<>();
		Map<String, HostEntry> byMoid = new HashMap<>();
		resourcesByName.put(resourceKind, byName);
		resourcesByMoid.put(resourceKind, byMoid);

		List<SimpleJson> resources = fetchResources(resourceKind);
		if (resources.isEmpty()) {
			logger.warn("ComplianceStitcher: /api/resources(" + resourceKind
					+ ") returned 0 results — this resource kind may not be "
					+ "present in inventory");
			return;
		}

		logger.info("ComplianceStitcher: " + resourceKind
				+ " — processing " + resources.size() + " resource(s)");

		int skippedForeignVc = 0;
		for (SimpleJson r : resources) {
			String uuid = findUuid(r);
			SimpleJson key = r.get("resourceKey");
			String name = getIdValue(key, "VMEntityName");
			String moid = getIdValue(key, "VMEntityObjectID");
			String vcUuid = getIdValue(key, "VMEntityVCID");

			// vCenter scoping (the MOID-trap fix): when this instance's owning
			// vCenter UUID is known AND the resource carries a VMEntityVCID that
			// does NOT match it, the resource belongs to a DIFFERENT vCenter —
			// skip it so a bare MOID cannot resolve across vCenters. A resource
			// with no VMEntityVCID is kept (degrade to unscoped — never drop a
			// resource we cannot disambiguate).
			if (owningVcUuid != null && vcUuid != null && !vcUuid.isEmpty()
					&& !owningVcUuid.equals(vcUuid)) {
				skippedForeignVc++;
				continue;
			}

			// resourceId prefers the platform UUID; fall back to name only
			// so a malformed row never produces a null push target.
			String resourceId = uuid != null ? uuid : name;
			if (resourceId == null) continue;

			HostEntry entry = new HostEntry(resourceId, name, moid);

			if (name != null && !name.isEmpty()) {
				byName.put(name, entry);
			}
			if (moid != null && !moid.isEmpty()) {
				byMoid.put(moid, entry);
			}
		}

		logger.info("ComplianceStitcher: loaded "
				+ byName.size() + " " + resourceKind + " by name, "
				+ byMoid.size() + " by MOID"
				+ (owningVcUuid != null
						? " (scoped to vCenter " + owningVcUuid + "; skipped "
						  + skippedForeignVc + " from other vCenters)"
						: " (unscoped — owning vCenter UUID unknown)"));
	}

	/**
	 * Fetch all VMWARE resources of {@code resourceKind} via the Suite API,
	 * returning the {@code resourceList} entries as a list of
	 * {@link SimpleJson} objects. Returns an empty list on any failure (a
	 * stitching read failure must not abort the collect cycle).
	 *
	 * <p>{@code pageSize=10000} is requested so a single page covers the
	 * inventory (the v1 client returned the full set; the Suite API default
	 * page size is 1000). If the inventory ever exceeds one page the missing
	 * resources simply do not stitch this cycle — never a wrong match.
	 */
	private List<SimpleJson> fetchResources(String resourceKind) {
		java.util.List<SimpleJson> out = new java.util.ArrayList<>();
		try {
			String enc = java.net.URLEncoder.encode(resourceKind, "UTF-8");
			String body = stitcher.get(
					"/api/resources?adapterKind=VMWARE&resourceKind=" + enc
					+ "&pageSize=10000");
			SimpleJson parsed = SimpleJson.parse(body);
			if (parsed == null || parsed.isNull()) return out;
			SimpleJson list = parsed.get("resourceList");
			if (list == null || !list.isList()) return out;
			for (SimpleJson r : list.asList()) {
				if (r != null && !r.isNull()) out.add(r);
			}
		} catch (Exception e) {
			logger.warn("ComplianceStitcher: fetchResources(" + resourceKind
					+ ") failed: " + e.getClass().getName()
					+ ": " + e.getMessage());
		}
		return out;
	}

	public HostEntry matchHost(String hostname, String moid) {
		return matchResource("HostSystem", hostname, moid);
	}

	public HostEntry matchVm(String name, String moid) {
		return matchResource("VirtualMachine", name, moid);
	}

	/**
	 * Resolve the {@code VMwareAdapter Instance} resource for this instance's
	 * vCenter. Build 58 (review B1): the decision is
	 * {@link ComplianceDecisions#matchVCenter}. A known vCenter Instance UUID
	 * resolves ONLY through {@code VMEntityVCID}; an unreadable UUID falls
	 * back to an exact {@code VCURL} match only. The pre-58 prefix,
	 * display-name and single-vCenter fallbacks are gone: each could push
	 * this vCenter's compliance data and rollup onto another vCenter's
	 * object. Null means "do not push" and is logged.
	 */
	public HostEntry matchVCenterAdapterInstance(String hostname,
			String vcInstanceUuid) {
		HostEntry m = ComplianceDecisions.matchVCenter(vcInstanceUuid,
				vcByVcUuid, vcByHost, hostname);
		if (m == null) {
			if (vcInstanceUuid != null && !vcInstanceUuid.isEmpty()) {
				logger.warn("ComplianceStitcher: no VMwareAdapter Instance "
						+ "carries VMEntityVCID=" + vcInstanceUuid + " (vCenter "
						+ hostname + "); not pushing vCenter data. Is this "
						+ "vCenter monitored by the VMWARE adapter in this VCF "
						+ "Ops?");
			} else {
				logger.warn("ComplianceStitcher: vCenter instance UUID "
						+ "unreadable and no VMwareAdapter Instance has "
						+ "VCURL exactly '" + hostname + "'; not pushing "
						+ "vCenter data");
			}
		}
		return m;
	}

	public HostEntry matchDvs(String name, String moid) {
		return matchResource("VmwareDistributedVirtualSwitch", name, moid);
	}

	public HostEntry matchDvpg(String name, String moid) {
		return matchResource("DistributedVirtualPortgroup", name, moid);
	}

	public HostEntry matchCluster(String name, String moid) {
		return matchResource("ClusterComputeResource", name, moid);
	}

	/**
	 * Generic resource matcher: moid first (most authoritative), then exact
	 * name, then dot-prefix fuzzy match (FQDN vs shortname tolerance).
	 */
	private HostEntry matchResource(String resourceKind, String name,
			String moid) {
		Map<String, HostEntry> byMoid = resourcesByMoid.get(resourceKind);
		Map<String, HostEntry> byName = resourcesByName.get(resourceKind);

		if (moid != null && byMoid != null) {
			HostEntry m = byMoid.get(moid);
			if (m != null) return m;
		}

		if (name != null && byName != null) {
			HostEntry n = byName.get(name);
			if (n != null) return n;

			for (Map.Entry<String, HostEntry> e : byName.entrySet()) {
				String registered = e.getKey();
				if (registered.startsWith(name + ".")
						|| name.startsWith(registered + ".")) {
					return e.getValue();
				}
			}
		}

		logger.warn("ComplianceStitcher: no " + resourceKind
				+ " match for " + name + " (moid=" + moid + ")");
		return null;
	}

	/**
	 * Build 59: latest {@code VCF-CF Compliance|<control_id>|Compliant}
	 * values for a batch of resources, via
	 * {@code GET /api/resources/stats/latest?resourceId=..&statKey=..}
	 * (documented in the vendor operations API spec; same ambient identity
	 * and client as the /api/resources reads). Requests are chunked by
	 * {@link ComplianceDecisions#latestCompliantPaths}.
	 *
	 * <p>Returns resourceId -> (control id -> latest value); a key the
	 * resource does not have is simply absent. Returns NULL if any request
	 * fails or a response cannot be parsed: the caller then cleans nothing
	 * for the batch this cycle. Only numeric values are returned (a missing
	 * or non-numeric data point is skipped, never read as 0).
	 */
	public Map<String, Map<String, Double>> latestCompliant(
			List<String> resourceIds, java.util.Set<String> controlIds) {
		Map<String, Map<String, Double>> out = new HashMap<>();
		for (String rid : resourceIds) out.put(rid, new HashMap<>());
		for (String path : ComplianceDecisions.latestCompliantPaths(
				resourceIds, controlIds, 20, 30)) {
			try {
				SimpleJson parsed = SimpleJson.parse(stitcher.get(path));
				if (parsed == null || parsed.isNull()) return null;
				SimpleJson values = parsed.get("values");
				if (values == null || values.isNull()) continue;   // no stats
				if (!values.isList()) return null;
				for (SimpleJson v : values.asList()) {
					String rid = v.get("resourceId").asString(null);
					Map<String, Double> into = rid == null ? null : out.get(rid);
					if (into == null) continue;
					SimpleJson stats = v.get("stat-list").get("stat");
					if (stats == null || !stats.isList()) continue;
					for (SimpleJson st : stats.asList()) {
						String cid = ComplianceDecisions.controlIdOfCompliantKey(
								st.get("statKey").get("key").asString(null));
						SimpleJson data = st.get("data");
						if (cid == null || data == null || !data.isList()
								|| data.size() == 0) {
							continue;
						}
						Double d = numeric(data.get(data.size() - 1));
						if (d != null) into.put(cid, d);
					}
				}
			} catch (Exception e) {
				logger.warn("ComplianceStitcher: latest Compliant read failed ("
						+ e.getClass().getSimpleName() + ": " + e.getMessage()
						+ ")");
				return null;
			}
		}
		return out;
	}

	private static Double numeric(SimpleJson node) {
		if (node == null || node.isNull()) return null;
		String s = node.asString(null);
		if (s == null) return null;
		try {
			return Double.valueOf(s.trim());
		} catch (NumberFormatException e) {
			return null;
		}
	}

	public int countOfKind(String resourceKind) {
		Map<String, HostEntry> byName = resourcesByName.get(resourceKind);
		return byName == null ? 0 : byName.size();
	}

	public void pushProperties(String resourceId,
			Map<String, String> properties, long timestamp) {
		if (properties.isEmpty()) return;
		stitcher.pushProperties(resourceId, properties, timestamp);
	}

	public void pushStats(String resourceId,
			Map<String, Double> stats, long timestamp) {
		if (stats.isEmpty()) return;
		stitcher.pushStats(resourceId, stats, timestamp);
	}

	public int size() {
		return countOfKind("HostSystem");
	}

	/**
	 * Extract the platform resource UUID from a {@code /api/resources} entry.
	 * The public Suite API exposes it as the top-level {@code identifier}
	 * field (mirrors v1's {@code ResourceDto.getIdentifier()}). Returns null
	 * when absent / blank.
	 */
	private String findUuid(SimpleJson resource) {
		if (resource == null) return null;
		String s = resource.get("identifier").asString(null);
		if (s == null || s.isEmpty()) {
			logger.warn("ComplianceStitcher: resource entry has no "
					+ "'identifier' (UUID) field");
			return null;
		}
		return s;
	}

	/**
	 * Read the value of the resource identifier named {@code name} from a
	 * {@code resourceKey} JSON node. Mirrors v1's
	 * {@code ResourceKey.getIdentifiers()} walk: each entry under
	 * {@code resourceIdentifiers} carries {@code identifierType.name} +
	 * {@code value}.
	 */
	private static String getIdValue(SimpleJson key, String name) {
		if (key == null || key.isNull()) return null;
		SimpleJson ids = key.get("resourceIdentifiers");
		if (ids == null || !ids.isList()) return null;
		for (SimpleJson id : ids.asList()) {
			String idName = id.get("identifierType").get("name").asString(null);
			if (name.equals(idName)) {
				return id.get("value").asString(null);
			}
		}
		return null;
	}

	/**
	 * Resolved foreign-resource handle. {@code resourceId} is the VCF Ops
	 * resource UUID (the push target); {@code hostName}/{@code moid} are kept
	 * for diagnostic logging (the moid slot carries VCURL for the vCenter
	 * adapter-instance kind).
	 */
	public static final class HostEntry {
		public final String resourceId;
		public final String hostName;
		public final String moid;

		public HostEntry(String resourceId, String hostName, String moid) {
			this.resourceId = resourceId;
			this.hostName = hostName;
			this.moid = moid;
		}
	}
}
