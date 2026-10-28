package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.json.SimpleJson;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * v2 compliance stitcher — resolves foreign VMWARE resource UUIDs via the
 * framework {@code SuiteApiStitcher} facade and pushes per-control / rollup
 * data onto them.
 *
 * <p>Build 96 (issue #27): the class carries no SDK or framework type
 * except {@link SimpleJson}. The Suite API calls go through {@link SuiteApi}
 * (the adapter adapts its {@code SuiteApiStitcher}) and the logging through
 * {@link VSphereClient.Log} (the adapter adapts its platform logger), so the
 * class compiles and runs in ci/run_java_tests.sh against a fake.
 *
 * <p><b>v1 → v2 change.</b> v1 held an aria-ops-core {@code SuiteAPIClient}
 * (injected on {@code UnlicensedAdapter}) and used the
 * {@code com.vmware.ops.api.model.resource.ResourceDto} model + heavy
 * reflection to resolve resources and invoke {@code addProperties}/{@code
 * addStats}. v2 has no aria-ops-core and no {@code com.vmware.ops.*} on the
 * classpath: all transport goes through the ambient {@code SuiteApiStitcher},
 * which acquires/releases a Suite API token per call as {@code
 * maintenanceAdmin}. Resource resolution is now a plain authenticated
 * {@code GET /api/resources?...} parsed with {@link SimpleJson}; pushes go
 * through {@code SuiteApiStitcher#pushProperties}/{@code
 * SuiteApiStitcher#pushStats}.
 *
 * <p><b>Identity (build 102, issue #20).</b> Every vim25-backed VMWARE kind
 * resolves on {@code VMEntityObjectID} (MOID) plus {@code VMEntityVCID}
 * (vCenter Instance UUID) only, the identity the Broadcom vSphere-based
 * packs stitch on. There is no name match: the exact-name and dot-prefix
 * fallbacks (inherited from v1, "FQDN/shortname tolerance", walked a
 * {@code HashMap} so a shared prefix resolved at random) are gone. A row
 * with no {@code identifier} (UUID), no MOID or no {@code VMEntityVCID} is
 * not indexed, and a MOID carried by two rows of the owning vCenter is
 * ambiguous and indexed by neither; those rows are counted and named once
 * per load at INFO. An object with no match is not pushed (the adapter
 * counts it in Rollup|&lt;K&gt;|unmatched). The non-vim25
 * {@code VMwareAdapter Instance} resolves by {@code VMEntityVCID}, or an
 * exact {@code VCURL} (vCenter FQDN) only when the UUID is unreadable
 * (build 58, unchanged).
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
 * different vCenter is skipped. (sdk-adapter-reviewer, vcommunity build 1 —
 * MOID-trap WARNING; same defect confirmed corpus-wide.) Build 102 (issue
 * #20): a row with no {@code VMEntityVCID} is no longer kept unscoped, and
 * when the owning UUID itself is unknown the kind is not loaded at all and
 * is held back like a failed list read ({@link #loadFailed}: the adapter
 * sets Rollup|incomplete = 1 and the kind's rollup keeps its values),
 * rather than matched on a bare MOID.
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
public final class ComplianceStitcher
		implements ComplianceDecisions.PushSink {

	/**
	 * Build 96 (issue #27): the three Suite API calls this class makes, so
	 * it needs no framework type. The adapter passes its
	 * {@code SuiteApiStitcher}; tests pass a fake. Same contract as the
	 * framework methods: {@link #get} throws on a failed read, the pushes
	 * log and swallow their own failures.
	 */
	public interface SuiteApi {
		String get(String path) throws java.io.IOException,
				InterruptedException;
		void pushProperties(String resourceId, Map<String, String> properties,
				long timestamp);
		void pushStats(String resourceId, Map<String, Double> stats,
				long timestamp);
	}

	/** Build 96: a log that drops everything (no platform logger). */
	private static final VSphereClient.Log NO_LOG = new VSphereClient.Log() {
		@Override public void info(String m) {}
		@Override public void debug(String m) {}
		@Override public void warn(String m) {}
		@Override public boolean isDebugEnabled() { return false; }
	};

	private final SuiteApi stitcher;
	private final VSphereClient.Log logger;

	// Per-VMWARE-resource-kind lookup tables. Build 102 (issue #20): the
	// vim25-backed kinds index by MOID only (scoped to the owning vCenter);
	// byName holds the VMwareAdapter Instance display names only.
	private final Map<String, Map<String, HostEntry>> resourcesByName =
			new HashMap<>();
	private final Map<String, Map<String, HostEntry>> resourcesByMoid =
			new HashMap<>();

	// VMwareAdapter Instance-only indexes — keyed by VCURL (FQDN) and
	// VMEntityVCID (vCenter Instance UUID).
	private final Map<String, HostEntry> vcByHost = new HashMap<>();
	private final Map<String, HostEntry> vcByVcUuid = new HashMap<>();

	// The vCenter Instance UUID this adapter instance monitors. The
	// vim25-backed loaders keep only foreign resources whose VMEntityVCID
	// matches it, so a bare MOID can never resolve to a same-MOID resource in
	// another vCenter (the MOID trap). Build 102 (issue #20): null means no
	// vim25-backed kind can be matched; each is held back (loadFailed).
	private volatile String owningVcUuid;

	// Build 88: resource kinds whose /api/resources read did not end in a
	// complete list on the last load: an exception (HTTP error, timeout,
	// interrupt), an unparseable body, a page with no resourceList (unless
	// it reports a total of 0), a list short of its pageInfo.totalCount (an
	// empty page or the page cap), and since build 96 (issue #52) an empty
	// list for a kind whose last complete list had objects
	// (EMPTY_UNCONFIRMED, accepted the next cycle if still empty). Distinct
	// from "0 results": the adapter holds that kind's rollup back
	// (Rollup|incomplete = 1) instead of reporting every object as
	// unmatched.
	private final java.util.Set<String> failedLoads =
			java.util.Collections.synchronizedSet(new java.util.HashSet<>());

	// Build 96 (issue #52): rows in each kind's last complete list, and the
	// kinds whose last read was an empty list held back as unconfirmed. Kept
	// for the life of this stitcher (one instance configuration); a new
	// configuration starts with no history, so its first empty list is
	// accepted.
	private final Map<String, Integer> lastCompleteCount =
			java.util.Collections.synchronizedMap(new HashMap<>());
	private final java.util.Set<String> emptyHeldBack =
			java.util.Collections.synchronizedSet(new java.util.HashSet<>());

	// Build 95 (issue #17): this cycle's measurement, null for none. Every
	// Suite API call made through this class is counted; pushes are timed
	// as the pushes phase.
	private volatile CycleMetrics metrics;

	public void setMetrics(CycleMetrics m) {
		this.metrics = m;
	}

	private void countCall() {
		CycleMetrics m = metrics;
		if (m != null) m.suiteCall();
	}

	public ComplianceStitcher(SuiteApi stitcher, VSphereClient.Log logger) {
		this.stitcher = stitcher;
		this.logger = logger != null ? logger : NO_LOG;
	}

	/**
	 * Pin the owning vCenter Instance UUID (from
	 * {@code VSphereClient.getVCenterInstanceUuid()}). Call once per cycle
	 * BEFORE the {@code load*} calls. Build 102 (issue #20): a null/blank
	 * value holds every vim25-backed kind back this cycle (no bare-MOID
	 * matching).
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

		int noUuid = 0;
		for (SimpleJson r : resources) {
			String uuid = findUuid(r);
			if (uuid == null) {
				noUuid++;
				continue;
			}
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
				+ vcByVcUuid.size() + " by VMEntityVCID"
				+ (noUuid > 0 ? "; " + noUuid + " row(s) with no identifier "
						+ "(UUID) skipped" : ""));
	}

	/**
	 * Shared loader for any vim25-backed VMWARE resource kind. Build 102
	 * (issue #20): indexes {@code VMEntityObjectID} (MOID) for the rows of
	 * the owning vCenter ({@code VMEntityVCID}) that carry a platform UUID;
	 * every other row is counted by reason and the count with the first
	 * such row is logged once at INFO. A MOID on two of the owning
	 * vCenter's rows is ambiguous: neither is indexed. With the owning
	 * vCenter UUID unknown nothing is read and the kind is held back.
	 */
	private void loadResourcesForKind(String resourceKind) {
		Map<String, HostEntry> byName = new HashMap<>();
		Map<String, HostEntry> byMoid = new HashMap<>();
		resourcesByName.put(resourceKind, byName);
		resourcesByMoid.put(resourceKind, byMoid);

		String owner = owningVcUuid;
		if (owner == null) {
			// Held back like a failed list read: Rollup|incomplete = 1 and
			// the kind's keys keep their values, rather than a bare MOID
			// matched across vCenters or every object reported unmatched.
			failedLoads.add(resourceKind);
			logger.warn("ComplianceStitcher: " + resourceKind + " not "
					+ "loaded: the owning vCenter instance UUID is unknown, "
					+ "and objects are matched on MOID plus vCenter UUID only; "
					+ "this kind is held back this cycle");
			return;
		}

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
		int noUuid = 0;
		int noMoid = 0;
		int noVcid = 0;
		String firstSkipped = null;
		java.util.Set<String> ambiguous = new java.util.TreeSet<>();
		for (SimpleJson r : resources) {
			String uuid = findUuid(r);
			SimpleJson key = r.get("resourceKey");
			String name = getIdValue(key, "VMEntityName");
			String moid = getIdValue(key, "VMEntityObjectID");
			String vcUuid = getIdValue(key, "VMEntityVCID");

			String reason = null;
			if (vcUuid == null || vcUuid.isEmpty()) {
				noVcid++;
				reason = "no VMEntityVCID";
			} else if (!owner.equals(vcUuid)) {
				// Another vCenter's object (the MOID trap): expected in a
				// multi-vCenter VCF Ops, counted in the load line only.
				skippedForeignVc++;
				continue;
			} else if (uuid == null) {
				noUuid++;
				reason = "no identifier (UUID)";
			} else if (moid == null || moid.isEmpty()) {
				noMoid++;
				reason = "no VMEntityObjectID";
			}
			if (reason != null) {
				if (firstSkipped == null) {
					firstSkipped = "name=" + name + " moid=" + moid
							+ " VMEntityVCID=" + vcUuid + " identifier=" + uuid
							+ " (" + reason + ")";
				}
				continue;
			}
			if (ambiguous.contains(moid)) continue;
			if (byMoid.containsKey(moid)) {
				byMoid.remove(moid);
				ambiguous.add(moid);
				continue;
			}
			byMoid.put(moid, new HostEntry(uuid, name, moid));
		}

		int notIndexed = noVcid + noUuid + noMoid;
		if (notIndexed > 0 || !ambiguous.isEmpty()) {
			logger.info("ComplianceStitcher: " + resourceKind + ": "
					+ notIndexed + " row(s) not indexed (" + noVcid
					+ " no VMEntityVCID, " + noUuid + " no identifier, "
					+ noMoid + " no VMEntityObjectID)"
					+ (firstSkipped != null ? "; first: " + firstSkipped : "")
					+ (ambiguous.isEmpty() ? "" : "; " + ambiguous.size()
							+ " MOID(s) on more than one row, matched to "
							+ "neither; first: " + ambiguous.iterator().next())
					+ ". Objects they would match are counted unmatched, "
					+ "not pushed.");
		}

		logger.info("ComplianceStitcher: loaded "
				+ byMoid.size() + " " + resourceKind + " by MOID"
				+ " (scoped to vCenter " + owner + "; skipped "
				+ skippedForeignVc + " from other vCenters)");
	}

	/**
	 * Fetch all VMWARE resources of {@code resourceKind} via the Suite API,
	 * returning the {@code resourceList} entries as a list of
	 * {@link SimpleJson} objects. Never throws (a stitching read failure
	 * must not abort the collect cycle).
	 *
	 * <p>Build 88 (review W2): the list is paged ({@code pageSize=10000},
	 * {@code page=0, 1, ...}) until {@code pageInfo.totalCount} rows are
	 * read ({@link ComplianceDecisions#resourcePageOutcome}). The kind stays
	 * marked failed ({@link #loadFailed}) on an exception, an unparseable
	 * body, a page with no {@code resourceList} (unless it reports a total
	 * of 0), or a list still short of its total (an empty page, or
	 * {@link ComplianceDecisions#MAX_RESOURCE_PAGES} reached). Since build 88
	 * an object missing from this list leaves the rollup, so a short list
	 * must hold the kind back rather than pass as complete.
	 *
	 * <p>Build 96 (issue #52): an empty but valid list for a kind whose
	 * last complete list had objects is held back too, once
	 * ({@link ComplianceDecisions.ResourcePage#EMPTY_UNCONFIRMED}); the
	 * next cycle's empty list is accepted as genuinely empty. An interrupt
	 * during the read keeps the thread's interrupt flag, so the adapter's
	 * stop check ends the cycle.
	 */
	private List<SimpleJson> fetchResources(String resourceKind) {
		java.util.List<SimpleJson> out = new java.util.ArrayList<>();
		// Build 88: failed until the whole list is read.
		failedLoads.add(resourceKind);
		// Build 96 (issue #52): the kind's history; the unconfirmed-empty
		// mark lasts one read only.
		Integer prev = lastCompleteCount.get(resourceKind);
		int previousCount = prev == null ? 0 : prev;
		boolean heldEmpty = emptyHeldBack.remove(resourceKind);
		try {
			String enc = java.net.URLEncoder.encode(resourceKind, "UTF-8");
			int collected = 0;
			for (int page = 0; ; page++) {
				countCall();
				String body = stitcher.get(
						"/api/resources?adapterKind=VMWARE&resourceKind=" + enc
						+ "&pageSize=" + ComplianceDecisions.RESOURCE_PAGE_SIZE
						+ "&page=" + page);
				SimpleJson parsed = SimpleJson.parse(body);
				if (parsed == null || parsed.isNull()) {
					logger.warn("ComplianceStitcher: fetchResources("
							+ resourceKind + ") page " + page
							+ " returned an unparseable body");
					return out;
				}
				SimpleJson list = parsed.get("resourceList");
				boolean hasList = list != null && list.isList();
				int rows = hasList ? list.size() : 0;
				if (hasList) {
					for (SimpleJson r : list.asList()) {
						if (r != null && !r.isNull()) out.add(r);
					}
				}
				collected += rows;
				SimpleJson total = parsed.path("pageInfo.totalCount");
				Long totalCount = total.isNull() ? null : total.asLong();
				ComplianceDecisions.ResourcePage next =
						ComplianceDecisions.resourcePageOutcome(hasList,
								totalCount, collected, rows, page,
								previousCount, heldEmpty);
				if (next == ComplianceDecisions.ResourcePage.COMPLETE) {
					failedLoads.remove(resourceKind);
					lastCompleteCount.put(resourceKind, collected);
					if (heldEmpty && collected == 0) {
						logger.warn("ComplianceStitcher: fetchResources("
								+ resourceKind + ") empty again (pageInfo."
								+ "totalCount " + totalCount + "); accepted as "
								+ "genuinely empty after one held-back cycle "
								+ "(the last complete list had "
								+ previousCount + ")");
					}
					return out;
				}
				if (next == ComplianceDecisions.ResourcePage
						.EMPTY_UNCONFIRMED) {
					emptyHeldBack.add(resourceKind);
					logger.warn("ComplianceStitcher: fetchResources("
							+ resourceKind + ") returned an empty list "
							+ "(pageInfo.totalCount " + totalCount + ") but "
							+ "the last complete list had " + previousCount
							+ "; this kind is held back this cycle, and an "
							+ "empty list next cycle is accepted as empty");
					return out;
				}
				if (next == ComplianceDecisions.ResourcePage.INCOMPLETE) {
					logger.warn("ComplianceStitcher: fetchResources("
							+ resourceKind + ") incomplete: "
							+ (hasList ? "" : "no resourceList, ")
							+ collected + " row(s) read of pageInfo.totalCount "
							+ totalCount + " after page " + page
							+ "; this kind is held back this cycle");
					return out;
				}
			}
		} catch (Exception e) {
			if (e instanceof InterruptedException) {
				// Build 96: keep the interrupt for the adapter's stop check.
				Thread.currentThread().interrupt();
			}
			logger.warn("ComplianceStitcher: fetchResources(" + resourceKind
					+ ") failed: " + e.getClass().getName()
					+ ": " + e.getMessage());
		}
		return out;
	}

	/**
	 * Build 88: true when the last read of the VCF Ops resource list for
	 * {@code resourceKind} failed (not merely returned 0 resources).
	 */
	public boolean loadFailed(String resourceKind) {
		return failedLoads.contains(resourceKind);
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
	 * Generic resource matcher. Build 102 (issue #20): MOID only, within the
	 * owning vCenter (the index holds no other vCenter's rows). No name or
	 * prefix fallback: no match is null (not pushed, counted unmatched by
	 * the adapter). {@code name} is for the DEBUG line only.
	 */
	private HostEntry matchResource(String resourceKind, String name,
			String moid) {
		Map<String, HostEntry> byMoid = resourcesByMoid.get(resourceKind);

		if (moid != null && byMoid != null) {
			HostEntry m = byMoid.get(moid);
			if (m != null) return m;
		}

		// Build 88: DEBUG. The adapter names a kind's unmatched objects in
		// one INFO line per cycle (Rollup|<K>|unmatched), so a WARN per
		// object per cycle is no longer needed.
		if (logger.isDebugEnabled()) {
			logger.debug("ComplianceStitcher: no " + resourceKind
					+ " match for " + name + " (moid=" + moid + ")");
		}
		return null;
	}

	/** Outcome of one bulk latest-Compliant read (build 60, review W1). */
	public static final class LatestRead {
		/** resourceId -> (control id -> latest value); null when failed. */
		public final Map<String, Map<String, Double>> values;
		/** GET requests completed (all of them when not failed). */
		public final int requests;
		/** Numeric Compliant values returned across completed requests. */
		public final int valuesReturned;
		/** Failure reason, null on success. */
		public final String error;
		/**
		 * Build 96 (Codex P2 on PR #57): resourceId -> (control id ->
		 * the timestamps of the samples returned), so a push can be
		 * confirmed as landed; null when failed.
		 */
		public final Map<String, Map<String, java.util.Set<Long>>> times;

		LatestRead(Map<String, Map<String, Double>> values, int requests,
				int valuesReturned, String error) {
			this(values, null, requests, valuesReturned, error);
		}

		LatestRead(Map<String, Map<String, Double>> values,
				Map<String, Map<String, java.util.Set<Long>>> times, int requests,
				int valuesReturned, String error) {
			this.values = values;
			this.times = times;
			this.requests = requests;
			this.valuesReturned = valuesReturned;
			this.error = error;
		}

		public boolean failed() {
			return values == null;
		}
	}

	/**
	 * Latest {@code VCF-CF Compliance|<control_id>|Compliant} values for a
	 * batch of resources, via
	 * {@code GET /api/resources/stats/latest?resourceId=..&statKey=..}
	 * (vendor operations API spec; same ambient identity and client as the
	 * /api/resources reads). Requests are sized by URL length
	 * ({@link ComplianceDecisions#latestCompliantPaths}); the framework
	 * stitcher exposes GET only, so the POST .../query form is not used.
	 *
	 * <p>A key the resource does not have is simply absent. If any request
	 * fails or a response cannot be parsed, {@link LatestRead#values} is null
	 * and the caller cleans nothing for the batch this cycle. Only numeric
	 * data points are returned (a missing or non-numeric value is never read
	 * as 0). The counts are for the caller's log line, so "the read returned
	 * nothing" is visible and distinguishable from "nothing was stale".
	 */
	public LatestRead latestCompliant(List<String> resourceIds,
			java.util.Set<String> controlIds) {
		Map<String, Map<String, Double>> out = new HashMap<>();
		Map<String, Map<String, java.util.Set<Long>>> times = new HashMap<>();
		for (String rid : resourceIds) {
			out.put(rid, new HashMap<>());
			times.put(rid, new HashMap<>());
		}
		int requests = 0;
		int returned = 0;
		for (String path : ComplianceDecisions.latestCompliantPaths(
				resourceIds, controlIds, ComplianceDecisions.URL_BUDGET)) {
			try {
				countCall();
				SimpleJson parsed = SimpleJson.parse(stitcher.get(path));
				if (parsed == null || parsed.isNull()) {
					return new LatestRead(null, requests, returned,
							"empty response body");
				}
				SimpleJson values = parsed.get("values");
				if (values != null && !values.isNull()) {
					if (!values.isList()) {
						return new LatestRead(null, requests, returned,
								"'values' is not a list");
					}
					for (SimpleJson v : values.asList()) {
						String rid = v.get("resourceId").asString(null);
						Map<String, Double> into = rid == null ? null
								: out.get(rid);
						if (into == null) continue;
						SimpleJson stats = v.get("stat-list").get("stat");
						if (stats == null || !stats.isList()) continue;
						for (SimpleJson st : stats.asList()) {
							String cid = ComplianceDecisions
									.controlIdOfCompliantKey(st.get("statKey")
											.get("key").asString(null));
							SimpleJson data = st.get("data");
							if (cid == null || data == null || !data.isList()
									|| data.size() == 0) {
								continue;
							}
							// Build 96 (Codex P2 on PR #57): up to
							// LATEST_SAMPLES samples. The latest value is the
							// one at the newest timestamp (any order); with
							// no timestamps, the last one, as before. Every
							// sample time is kept, to confirm pushes landed.
							int at = data.size() - 1;
							SimpleJson tss = st.get("timestamps");
							java.util.Set<Long> seenTs = new java.util.HashSet<>();
							if (tss != null && tss.isList()
									&& tss.size() == data.size()) {
								long newest = Long.MIN_VALUE;
								for (int x = 0; x < tss.size(); x++) {
									Double t = numeric(tss.get(x));
									if (t == null) continue;
									seenTs.add(t.longValue());
									if (t.longValue() >= newest) {
										newest = t.longValue();
										at = x;
									}
								}
							}
							Double d = numeric(data.get(at));
							if (d != null) {
								into.put(cid, d);
								returned++;
								times.get(rid).put(cid, seenTs);
							}
						}
					}
				}
				requests++;
			} catch (Exception e) {
				if (e instanceof InterruptedException) {
					// Build 96: keep the interrupt for the stop check.
					Thread.currentThread().interrupt();
				}
				return new LatestRead(null, requests, returned,
						e.getClass().getSimpleName() + ": " + e.getMessage());
			}
		}
		return new LatestRead(out, times, requests, returned, null);
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
		// Build 102: the vim25-backed kinds are indexed by MOID only.
		Map<String, HostEntry> index = "VMwareAdapter Instance".equals(
				resourceKind) ? resourcesByName.get(resourceKind)
				: resourcesByMoid.get(resourceKind);
		return index == null ? 0 : index.size();
	}

	@Override
	public void pushProperties(String resourceId,
			Map<String, String> properties, long timestamp) {
		if (properties.isEmpty()) return;
		try (CycleMetrics.Scope s = CycleMetrics.scope(metrics,
				CycleMetrics.Phase.PUSHES)) {
			countCall();
			stitcher.pushProperties(resourceId, properties, timestamp);
		}
	}

	@Override
	public void pushStats(String resourceId,
			Map<String, Double> stats, long timestamp) {
		if (stats.isEmpty()) return;
		try (CycleMetrics.Scope s = CycleMetrics.scope(metrics,
				CycleMetrics.Phase.PUSHES)) {
			countCall();
			stitcher.pushStats(resourceId, stats, timestamp);
		}
	}

	public int size() {
		return countOfKind("HostSystem");
	}

	/**
	 * Extract the platform resource UUID from a {@code /api/resources} entry.
	 * The public Suite API exposes it as the top-level {@code identifier}
	 * field (mirrors v1's {@code ResourceDto.getIdentifier()}). Returns null
	 * when absent / blank. Build 102: the callers count such rows and log
	 * them once per load (it was a WARN per row per cycle).
	 */
	private static String findUuid(SimpleJson resource) {
		if (resource == null) return null;
		String s = resource.get("identifier").asString(null);
		return s == null || s.isEmpty() ? null : s;
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
