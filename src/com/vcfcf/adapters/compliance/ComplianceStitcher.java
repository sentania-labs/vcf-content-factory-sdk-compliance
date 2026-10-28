package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.json.SimpleJson;

import java.util.HashMap;
import java.util.LinkedHashMap;
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
 * {@code GET /api/resources?...} parsed with {@link SimpleJson}. Build 104
 * (issue #17): pushes are queued and go out through the framework batch
 * pushes, stats first, inside the walk at a size threshold and at the end
 * of the cycle ({@link #flushPushes}).
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
	 * Build 96 (issue #27): the Suite API calls this class makes, so it
	 * needs no framework type. The adapter passes its
	 * {@code SuiteApiStitcher}; tests pass a fake. Same contract as the
	 * framework methods: {@link #get} throws on a failed read, the pushes
	 * log and swallow their own failures. Build 104 (issue #17): the two
	 * per-id pushes are replaced by the buildkit 1.0.24 batch pushes
	 * ({@code SuiteApiStitcher.pushStatsBatch} and
	 * {@code pushPropertiesBatch}, chunked by count and bytes), called
	 * stats first (review W1), whose results come back as the SDK-free
	 * {@link BatchOutcome}.
	 */
	public interface SuiteApi {
		String get(String path) throws java.io.IOException,
				InterruptedException;
		BatchOutcome pushStatsBatch(Map<String, Map<String, Double>> stats,
				long timestamp);
		BatchOutcome pushPropertiesBatch(
				Map<String, Map<String, String>> properties, long timestamp);
	}

	/**
	 * Build 104 (issue #17): the framework's {@code SuiteApiBatchResult}
	 * without the framework type (same fields, same meaning). A 2xx batch is
	 * "accepted", not "landed": the Suite API drops an unknown id silently,
	 * so {@link #batchesOk} says nothing about stale ids (those are caught
	 * where ids are resolved, the per-cycle resource list).
	 */
	public static final class BatchOutcome {
		public final int sent;
		public final int batchesOk;
		public final int batchesFailed;
		public final int fellBack;
		public final int skipped;
		public final int dropped;
		public final boolean stopped;

		public BatchOutcome(int sent, int batchesOk, int batchesFailed,
				int fellBack, int skipped, int dropped, boolean stopped) {
			this.sent = sent;
			this.batchesOk = batchesOk;
			this.batchesFailed = batchesFailed;
			this.fellBack = fellBack;
			this.skipped = skipped;
			this.dropped = dropped;
			this.stopped = stopped;
		}

		static final BatchOutcome NONE =
				new BatchOutcome(0, 0, 0, 0, 0, 0, false);

		/** Same rule as {@code SuiteApiBatchResult.isClean()}. */
		public boolean isClean() {
			return batchesFailed == 0 && skipped == 0 && dropped == 0
					&& !stopped;
		}

		/** Suite API requests made: batch requests plus per-id re-sends. */
		public int requests() {
			return batchesOk + batchesFailed + fellBack;
		}

		BatchOutcome plus(BatchOutcome o) {
			return new BatchOutcome(sent + o.sent, batchesOk + o.batchesOk,
					batchesFailed + o.batchesFailed, fellBack + o.fellBack,
					skipped + o.skipped, dropped + o.dropped,
					stopped || o.stopped);
		}

		@Override
		public String toString() {
			return "sent=" + sent + " batchesOk=" + batchesOk
					+ " batchesFailed=" + batchesFailed + " fellBack="
					+ fellBack + " skipped=" + skipped + " dropped=" + dropped
					+ " stopped=" + stopped;
		}
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
	// Build 104 review N3: every VMwareAdapter Instance resource id of the
	// last list, to check a cached vCenter object id still exists.
	private final java.util.Set<String> vcResourceIds =
			java.util.Collections.synchronizedSet(new java.util.HashSet<>());

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
		vcResourceIds.clear();

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
			vcResourceIds.add(uuid);
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
	 * Build 102 (review W1): so is a list with rows but no row of the owning
	 * vCenter and at least one row with no {@code VMEntityVCID}, since its
	 * objects may be among the rows that cannot be scoped. The load line
	 * records, for every kind, how many rows carry {@code VMEntityVCID}.
	 */
	private void loadResourcesForKind(String resourceKind) {
		Map<String, HostEntry> byMoid = new HashMap<>();
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
		int ownerRows = 0;
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
			} else {
				ownerRows++;
				if (uuid == null) {
					noUuid++;
					reason = "no identifier (UUID)";
				} else if (moid == null || moid.isEmpty()) {
					noMoid++;
					reason = "no VMEntityObjectID";
				}
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

		int withVcid = resources.size() - noVcid;
		if (noVcid > 0 && ownerRows == 0) {
			// Review W1: rows exist, none is the owning vCenter's, and some
			// cannot be scoped at all. This vCenter's objects may be among
			// them, so reporting every object unmatched would zero the
			// kind's counts. Held back like a failed list read: the kind's
			// keys keep their values and Rollup|incomplete = 1.
			failedLoads.add(resourceKind);
			logger.warn("ComplianceStitcher: " + resourceKind + " not "
					+ "matched: " + noVcid + " of " + resources.size()
					+ " row(s) carry no VMEntityVCID and none belongs to "
					+ "vCenter " + owner + " (" + skippedForeignVc
					+ " from other vCenters)"
					+ (firstSkipped != null ? "; first: " + firstSkipped : "")
					+ "; this kind is held back this cycle");
			return;
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
				+ skippedForeignVc + " from other vCenters; " + withVcid
				+ " of " + resources.size() + " row(s) carry VMEntityVCID)");
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
	/**
	 * Build 104 review N3: whether the last VMwareAdapter Instance list
	 * ({@link #loadVCenterAdapterInstance}) has a resource with this id:
	 * TRUE or FALSE from a complete list, null when that list did not load
	 * (unknown). A batch push to an id that matches no resource is dropped
	 * silently, so a cached id is checked before it is used.
	 */
	public Boolean vCenterResourceListed(String resourceId) {
		if (loadFailed("VMwareAdapter Instance")) return null;
		return vcResourceIds.contains(resourceId);
	}

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

	// ----- build 104 (issue #17): batched pushes ---------------------------

	/**
	 * Build 104 review W2/W3: queued resource entries (a resource with
	 * properties and stats counts twice) at which the queue is sent inside
	 * the walk. About 500 VM-sized entries hold some 19 MB of heap.
	 */
	static final int FLUSH_ENTRIES = 500;
	/**
	 * Build 104 review W2/W3: estimated JSON bytes at which the queue is
	 * sent inside the walk (about 16 requests at the framework's 1 MB cap).
	 */
	static final long FLUSH_BYTES = 16L * 1024 * 1024;
	/** Per-value JSON overhead in the estimate (statKey, timestamps, braces). */
	private static final int VALUE_OVERHEAD = 60;

	/** One timestamp's queued values: resource id to key to value. */
	private static final class Queued {
		final Map<String, Map<String, String>> props = new LinkedHashMap<>();
		final Map<String, Map<String, Double>> stats = new LinkedHashMap<>();

		int entries() {
			return props.size() + stats.size();
		}
	}

	// Guarded by pushLock. While a cycle is open (beginPushCycle), every
	// push is queued by timestamp and sent by flushPushes: inside the walk
	// once the queue reaches the entry or byte threshold, and at the end of
	// the cycle. Outside a cycle a push is sent at once.
	private final Object pushLock = new Object();
	private boolean pushCycleOpen;
	private long pushCycleTs;
	private final java.util.TreeMap<Long, Queued> queued =
			new java.util.TreeMap<>();
	private int queuedEntries;
	private long queuedBytes;
	private int replacedValues;
	private int flushEntries = FLUSH_ENTRIES;
	private long flushBytes = FLUSH_BYTES;
	// The cycle's totals across its flushes, for the one summary line.
	private BatchOutcome cycleOutcome = BatchOutcome.NONE;
	private int cycleProps;
	private int cycleStats;
	private int cycleValues;
	private int cycleFlushes;
	private int cycleReplaced;
	private String cycleFailure;
	// Set while a send runs, so a push from inside it (none today) queues.
	private boolean sending;

	/**
	 * Build 104 review W2: Stop Collecting, checked before each Suite API
	 * request of a flush. The adapter passes its StopCheck condition; null
	 * (tests, outside the adapter) never stops.
	 */
	private volatile java.util.function.BooleanSupplier stopRequested;

	public void setStopRequested(java.util.function.BooleanSupplier s) {
		this.stopRequested = s;
	}

	private boolean stopRequested() {
		java.util.function.BooleanSupplier s = stopRequested;
		return s != null && s.getAsBoolean();
	}

	/** Test seam: the in-walk flush thresholds. */
	void setFlushThresholds(int entries, long bytes) {
		synchronized (pushLock) {
			flushEntries = entries;
			flushBytes = bytes;
		}
	}

	/**
	 * Build 104: open a push cycle. Every push until {@link #endPushCycle}
	 * or {@link #abandonPushCycle} is queued; the queue is sent inside the
	 * walk when it reaches {@link #FLUSH_ENTRIES} entries or about
	 * {@link #FLUSH_BYTES} bytes, and by {@link #flushPushes} at the end.
	 * The callers stamp their pushes with {@link #pushTimestamp()}, so a
	 * cycle is one timestamp. Anything left from an earlier cycle (none: the
	 * adapter closes every cycle in a finally) is dropped.
	 */
	public void beginPushCycle(long timestamp) {
		synchronized (pushLock) {
			queued.clear();
			queuedEntries = 0;
			queuedBytes = 0;
			replacedValues = 0;
			resetCycleTotals();
			pushCycleOpen = true;
			pushCycleTs = timestamp;
		}
	}

	private void resetCycleTotals() {
		cycleOutcome = BatchOutcome.NONE;
		cycleProps = 0;
		cycleStats = 0;
		cycleValues = 0;
		cycleFlushes = 0;
		cycleReplaced = 0;
		cycleFailure = null;
	}

	/**
	 * Build 104: the timestamp this cycle's pushes carry (the cycle's start),
	 * or now when no cycle is open. The retired-key read-back
	 * ({@link RetiredKeyRepeats}) matches on it exactly.
	 */
	public long pushTimestamp() {
		synchronized (pushLock) {
			return pushCycleOpen ? pushCycleTs : System.currentTimeMillis();
		}
	}

	@Override
	public void pushProperties(String resourceId,
			Map<String, String> properties, long timestamp) {
		if (properties.isEmpty()) return;
		boolean full;
		boolean queuedIt;
		synchronized (pushLock) {
			queuedIt = pushCycleOpen;
			if (pushCycleOpen) {
				Queued q = queuedAt(timestamp);
				Map<String, String> m = q.props.get(resourceId);
				if (m == null) {
					m = new LinkedHashMap<>();
					q.props.put(resourceId, m);
					queuedEntries++;
					queuedBytes += resourceId.length() + VALUE_OVERHEAD;
				}
				for (Map.Entry<String, String> e : properties.entrySet()) {
					String old = m.put(e.getKey(), e.getValue());
					if (old != null && !old.equals(e.getValue())) {
						replacedValues++;
					}
					if (old == null) {
						queuedBytes += len(e.getKey()) + len(e.getValue())
								+ VALUE_OVERHEAD;
					}
				}
				full = isFull();
			} else {
				full = false;
			}
		}
		if (!queuedIt) {
			Queued one = new Queued();
			one.props.put(resourceId, new LinkedHashMap<>(properties));
			sendAtOnce(timestamp, one);
			return;
		}
		if (full) flushInWalk();
	}

	@Override
	public void pushStats(String resourceId,
			Map<String, Double> stats, long timestamp) {
		if (stats.isEmpty()) return;
		boolean full;
		boolean queuedIt;
		synchronized (pushLock) {
			queuedIt = pushCycleOpen;
			if (pushCycleOpen) {
				Queued q = queuedAt(timestamp);
				Map<String, Double> m = q.stats.get(resourceId);
				if (m == null) {
					m = new LinkedHashMap<>();
					q.stats.put(resourceId, m);
					queuedEntries++;
					queuedBytes += resourceId.length() + VALUE_OVERHEAD;
				}
				for (Map.Entry<String, Double> e : stats.entrySet()) {
					Double old = m.put(e.getKey(), e.getValue());
					if (old != null && !old.equals(e.getValue())) {
						replacedValues++;
					}
					if (old == null) {
						queuedBytes += len(e.getKey()) + 24 + VALUE_OVERHEAD;
					}
				}
				full = isFull();
			} else {
				full = false;
			}
		}
		if (!queuedIt) {
			Queued one = new Queued();
			one.stats.put(resourceId, new LinkedHashMap<>(stats));
			sendAtOnce(timestamp, one);
			return;
		}
		if (full) flushInWalk();
	}

	private static int len(String s) {
		return s == null ? 4 : s.length();
	}

	private boolean isFull() {
		return !sending && (queuedEntries >= flushEntries
				|| queuedBytes >= flushBytes);
	}

	private Queued queuedAt(long timestamp) {
		return queued.computeIfAbsent(timestamp, k -> new Queued());
	}

	/** Queued resource entries not yet sent (tests). */
	int queuedEntries() {
		synchronized (pushLock) {
			return queuedEntries;
		}
	}

	/**
	 * Build 104 review W2/W3: the queue reached a threshold inside the walk.
	 * Sent now, so its time counts against the cycle budget (the walk's next
	 * vCenter call sees it) and the queue stays bounded. Skipped when Stop
	 * Collecting was requested: the walk stops at its next check and the
	 * cycle drops the queue ({@link #abandonPushCycle}).
	 */
	private void flushInWalk() {
		if (stopRequested() || budgetExhausted() != null) return;
		Map<Long, Queued> work = takeQueue();
		if (work != null) sendAndCount(work, true);
	}

	private Map<Long, Queued> takeQueue() {
		synchronized (pushLock) {
			if (queued.isEmpty()) return null;
			Map<Long, Queued> work = new java.util.TreeMap<>(queued);
			queued.clear();
			queuedEntries = 0;
			queuedBytes = 0;
			cycleReplaced += replacedValues;
			replacedValues = 0;
			return work;
		}
	}

	/**
	 * Build 104: send everything still queued (normally one timestamp: the
	 * cycle's) and log the cycle's one summary line, which covers every
	 * flush of the cycle: INFO when clean, WARN with the counts and the
	 * reason when not. Nothing sent this cycle: nothing logged. Never
	 * throws; a value not delivered keeps its last value, as a failed per-id
	 * push did. The cycle stays open (a later push queues again and the
	 * finally's {@link #endPushCycle} sends it).
	 *
	 * @return the cycle's outcome so far, all flushes summed
	 */
	public BatchOutcome flushPushes() {
		Map<Long, Queued> work = takeQueue();
		if (work != null) sendAndCount(work, false);
		return logCycleSummary();
	}

	/** Build 104: flush, then close the cycle (pushes go out at once again). */
	public BatchOutcome endPushCycle() {
		try {
			return flushPushes();
		} finally {
			synchronized (pushLock) {
				pushCycleOpen = false;
			}
		}
	}

	/**
	 * Build 104 review W2: the cycle was stopped (Stop Collecting or an
	 * interrupt). What is still queued is dropped, not sent: nothing more
	 * goes to the Suite API after a stop, as in build 103, where the walk
	 * stopped and nothing after it was pushed. The values sent by the
	 * cycle's in-walk flushes stay sent. One WARN names what was dropped.
	 */
	public void abandonPushCycle(String why) {
		int entries;
		int values = 0;
		synchronized (pushLock) {
			entries = queuedEntries;
			for (Queued q : queued.values()) {
				for (Map<String, String> m : q.props.values()) values += m.size();
				for (Map<String, Double> m : q.stats.values()) values += m.size();
			}
			queued.clear();
			queuedEntries = 0;
			queuedBytes = 0;
			replacedValues = 0;
			pushCycleOpen = false;
		}
		logCycleSummary();
		if (entries > 0) {
			logger.warn("Suite API push: " + why + ": " + entries
					+ " queued resource entr(ies) (" + values + " value(s)) "
					+ "were not sent; those values keep their last value "
					+ "until the next cycle");
		}
	}

	private void sendAtOnce(long timestamp, Queued one) {
		// Build 104 review N5: outside a cycle (no production caller), the
		// summary is DEBUG, a failure still WARN.
		Sent r = send(java.util.Collections.singletonMap(timestamp, one),
				false);
		BatchOutcome o = r.outcome;
		String line = pushSummary(o, one.props.size(), one.stats.size(),
				valuesIn(one), 1, 0, r.failure);
		if (o.isClean()) {
			logger.debug(line);
		} else {
			logger.warn(line);
		}
	}

	private static int valuesIn(Queued q) {
		int v = 0;
		for (Map<String, String> m : q.props.values()) v += m.size();
		for (Map<String, Double> m : q.stats.values()) v += m.size();
		return v;
	}

	private void sendAndCount(Map<Long, Queued> work, boolean inWalk) {
		Sent r = send(work, inWalk);
		synchronized (pushLock) {
			cycleOutcome = cycleOutcome.plus(r.outcome);
			cycleProps += r.propResources;
			cycleStats += r.statResources;
			cycleValues += r.values;
			cycleFlushes++;
			if (r.failure != null) cycleFailure = r.failure;
		}
	}

	private BatchOutcome logCycleSummary() {
		BatchOutcome total;
		String line;
		synchronized (pushLock) {
			if (cycleFlushes == 0) return BatchOutcome.NONE;
			total = cycleOutcome;
			line = pushSummary(total, cycleProps, cycleStats, cycleValues,
					cycleFlushes, cycleReplaced, cycleFailure);
			resetCycleTotals();
		}
		if (total.isClean()) {
			logger.info(line);
		} else {
			logger.warn(line);
		}
		return total;
	}

	/**
	 * Codex P2 on PR #70: most resources in one slice, the framework's
	 * per-request resource cap (100), so the framework sends a slice as
	 * exactly one request.
	 */
	static final int SLICE_RESOURCES = 100;
	/**
	 * Codex P2 on PR #70: most estimated JSON bytes in one slice, well under
	 * the framework's 1,000,000-byte request cap. The estimate
	 * ({@link #jsonBytes}) is an upper bound on what the framework writes
	 * (every escape and UTF-8 byte counted, generous per-item overhead), so
	 * the framework never re-splits a slice. One resource over it goes
	 * alone, as the framework would send it.
	 */
	static final long SLICE_BYTES = 600_000L;

	/** Upper bound of a JSON string's UTF-8 bytes, quotes included. */
	static long jsonBytes(String v) {
		if (v == null) return 4;
		long n = 2;
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			if (c < 0x20) n += 6;
			else if (c == '"' || c == '\\') n += 2;
			else if (c < 0x80) n += 1;
			else if (c < 0x800) n += 2;
			else n += 3;
		}
		return n;
	}

	private static <V> long entryBytes(String rid, Map<String, V> m) {
		long n = 200 + jsonBytes(rid);
		for (Map.Entry<String, V> e : m.entrySet()) {
			Object v = e.getValue();
			n += 100 + jsonBytes(e.getKey()) + (v instanceof String
					? jsonBytes((String) v) : 32);
		}
		return n;
	}

	/**
	 * Codex P2 on PR #70: split one half (stats or properties) into slices
	 * the framework sends as one request each.
	 */
	static <V> List<Map<String, Map<String, V>>> slices(
			Map<String, Map<String, V>> half, int maxResources,
			long maxBytes) {
		List<Map<String, Map<String, V>>> out = new java.util.ArrayList<>();
		Map<String, Map<String, V>> cur = new LinkedHashMap<>();
		long bytes = 0;
		for (Map.Entry<String, Map<String, V>> e : half.entrySet()) {
			long b = entryBytes(e.getKey(), e.getValue());
			if (!cur.isEmpty() && (cur.size() >= maxResources
					|| bytes + b > maxBytes)) {
				out.add(cur);
				cur = new LinkedHashMap<>();
				bytes = 0;
			}
			cur.put(e.getKey(), e.getValue());
			bytes += b;
		}
		if (!cur.isEmpty()) out.add(cur);
		return out;
	}

	/** Test seam: the slice caps. */
	void setSliceCaps(int resources, long bytes) {
		synchronized (pushLock) {
			sliceResources = resources;
			sliceBytes = bytes;
		}
	}

	private int sliceResources = SLICE_RESOURCES;
	private long sliceBytes = SLICE_BYTES;

	/**
	 * Codex P2 on PR #70: the cycle budget's reason to end, or null while
	 * it may go on. The adapter passes its CycleBudget; null never ends.
	 */
	private volatile java.util.function.Supplier<String> budget;

	public void setBudgetExhausted(java.util.function.Supplier<String> b) {
		this.budget = b;
	}

	private String budgetExhausted() {
		java.util.function.Supplier<String> b = budget;
		return b == null ? null : b.get();
	}

	/** What one send did, for the cycle's summary. */
	private static final class Sent {
		BatchOutcome outcome = BatchOutcome.NONE;
		int propResources;
		int statResources;
		int values;
		String failure;
	}

	private static final class Slice {
		final long ts;
		final boolean stats;
		final Map<String, Map<String, String>> props;
		final Map<String, Map<String, Double>> statMap;

		Slice(long ts, Map<String, Map<String, String>> props,
				Map<String, Map<String, Double>> statMap) {
			this.ts = ts;
			this.stats = statMap != null;
			this.props = props;
			this.statMap = statMap;
		}

		int entries() {
			return stats ? statMap.size() : props.size();
		}

		int values() {
			int v = 0;
			if (stats) {
				for (Map<String, Double> m : statMap.values()) v += m.size();
			} else {
				for (Map<String, String> m : props.values()) v += m.size();
			}
			return v;
		}
	}

	/**
	 * Build 104 review W1, Codex P2 on PR #70: every stats slice of the
	 * flush (all timestamps), then every properties slice; each slice is one
	 * Suite API request. Before every slice: Stop Collecting (sends nothing
	 * more; the rest counts as not delivered), and for a flush inside the
	 * walk the cycle budget (the rest goes back to the queue for the
	 * end-of-cycle flush, which sends regardless of the budget, as build
	 * 103's pushes did, so the rollup and Rollup|incomplete still land). A
	 * stopped call (5xx, 429, timeout, token failure, interrupt) or a
	 * thrown push sends nothing more either.
	 */
	private Sent send(Map<Long, Queued> work, boolean inWalk) {
		List<Slice> plan = new java.util.ArrayList<>();
		int sr;
		long sb;
		synchronized (pushLock) {
			sr = sliceResources;
			sb = sliceBytes;
		}
		for (Map.Entry<Long, Queued> e : work.entrySet()) {
			for (Map<String, Map<String, Double>> m
					: slices(e.getValue().stats, sr, sb)) {
				plan.add(new Slice(e.getKey(), null, m));
			}
		}
		for (Map.Entry<Long, Queued> e : work.entrySet()) {
			for (Map<String, Map<String, String>> m
					: slices(e.getValue().props, sr, sb)) {
				plan.add(new Slice(e.getKey(), m, null));
			}
		}
		Sent r = new Sent();
		BatchOutcome total = BatchOutcome.NONE;
		int notTried = 0;
		String failure = null;
		List<Slice> deferred = new java.util.ArrayList<>();
		synchronized (pushLock) {
			sending = true;
		}
		try (CycleMetrics.Scope sc = CycleMetrics.scope(metrics,
				CycleMetrics.Phase.PUSHES)) {
			for (Slice sl : plan) {
				if (failure == null && !total.stopped && stopRequested()) {
					failure = "Stop Collecting was requested";
				}
				if (failure == null && !total.stopped && inWalk
						&& (!deferred.isEmpty()
								|| budgetExhausted() != null)) {
					deferred.add(sl);
					continue;
				}
				if (sl.stats) r.statResources += sl.entries();
				else r.propResources += sl.entries();
				r.values += sl.values();
				if (total.stopped || failure != null) {
					notTried += sl.entries();
					continue;
				}
				BatchOutcome o;
				try {
					o = sl.stats ? stitcher.pushStatsBatch(sl.statMap, sl.ts)
							: stitcher.pushPropertiesBatch(sl.props, sl.ts);
				} catch (RuntimeException ex) {
					// The framework never throws; a fake or a drift might.
					failure = "the push threw " + ex.getClass().getSimpleName()
							+ ": " + ex.getMessage();
					notTried += sl.entries();
					continue;
				}
				if (o == null) o = BatchOutcome.NONE;
				total = total.plus(o);
				CycleMetrics m = metrics;
				if (m != null) {
					for (int i = 0; i < o.requests(); i++) m.suiteCall();
				}
			}
		} finally {
			synchronized (pushLock) {
				sending = false;
			}
		}
		if (!deferred.isEmpty()) requeue(deferred);
		if (notTried > 0) {
			total = total.plus(new BatchOutcome(0, 0, 0, 0, notTried, 0,
					true));
		}
		r.outcome = total;
		r.failure = failure;
		return r;
	}

	/**
	 * Codex P2 on PR #70: slices an in-walk flush did not send because the
	 * cycle budget ran out go back to the queue (a value pushed since keeps
	 * precedence), for the end-of-cycle flush.
	 */
	private void requeue(List<Slice> deferred) {
		synchronized (pushLock) {
			for (Slice sl : deferred) {
				Queued q = queuedAt(sl.ts);
				if (sl.stats) {
					for (Map.Entry<String, Map<String, Double>> e
							: sl.statMap.entrySet()) {
						Map<String, Double> m = new LinkedHashMap<>(e.getValue());
						Map<String, Double> later = q.stats.get(e.getKey());
						if (later != null) m.putAll(later);
						else queuedEntries++;
						q.stats.put(e.getKey(), m);
					}
				} else {
					for (Map.Entry<String, Map<String, String>> e
							: sl.props.entrySet()) {
						Map<String, String> m = new LinkedHashMap<>(e.getValue());
						Map<String, String> later = q.props.get(e.getKey());
						if (later != null) m.putAll(later);
						else queuedEntries++;
						q.props.put(e.getKey(), m);
					}
				}
			}
		}
	}

	/**
	 * Build 104: the one line a cycle's pushes log. Package-private for the
	 * tests.
	 */
	static String pushSummary(BatchOutcome o, int propResources,
			int statResources, int values, int flushes, int replaced,
			String failure) {
		StringBuilder b = new StringBuilder();
		b.append(o.isClean() ? "Suite API push: "
				: "Suite API push NOT clean: ");
		b.append(statResources).append(" resource(s) with stats and ")
				.append(propResources).append(" with properties, ")
				.append(values).append(" value(s), in ").append(o.requests())
				.append(" request(s)");
		if (flushes > 1) {
			b.append(" (").append(flushes).append(" flushes)");
		}
		b.append(" [").append(o).append("]");
		if (replaced > 0) {
			b.append("; ").append(replaced).append(" value(s) replaced by a "
					+ "later push to the same key this cycle");
		}
		if (o.isClean()) return b.toString();
		java.util.List<String> why = new java.util.ArrayList<>();
		if (failure != null) {
			why.add(failure);
		} else if (o.stopped) {
			why.add("the call stopped early (a server error, 429, timeout, "
					+ "token failure or interrupt; see the "
					+ "SuiteApiStitchClient WARN above)");
		}
		if (o.batchesFailed > 0) {
			why.add(o.batchesFailed + " batch request(s) failed"
					+ (o.fellBack > 0 ? ", " + o.fellBack + " resource "
							+ "entr(ies) re-sent one at a time" : ""));
		}
		if (o.skipped > 0) {
			why.add(o.skipped + " resource entr(ies) not delivered");
		}
		if (o.dropped > 0) {
			why.add(o.dropped + " value(s) dropped before sending (null "
					+ "or not finite)");
		}
		b.append("; ").append(String.join("; ", why))
				.append(". What was not delivered keeps its last value; "
						+ "scoring is unaffected and the next cycle pushes "
						+ "again");
		return b.toString();
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
