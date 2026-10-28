package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Build 103, issue #17 build 2: the bulk read is primary.
 *
 * <ul>
 *   <li>VSphereClient: the bulk path set per kind; one RetrieveProperties
 *       for a page of objects; an InvalidProperty path shortened once and
 *       remembered; a failed page throws (never an empty result); a
 *       recipe read from the bulk row makes no call, a value missing from
 *       the row is read per object, and missing both ways is UNREADABLE
 *       with the per-object reason, never a pass.</li>
 *   <li>The adapter cycle: a fixture cycle (12 hosts, 60 VMs) makes 36
 *       SOAP calls, 4 of them bulk reads, where build 102 made 572
 *       (measured on the same fixture); its pushes are identical to the
 *       ones made when every bulk page fails and every object is read one
 *       at a time; a value missing from both reads is not pushed and the
 *       object is flagged.</li>
 *   <li>Review fixes: a page refused by the cycle budget cuts the
 *       object reading it and the next cycle's page starts there (W3);
 *       a page over the response cap sends the rest of the kind per
 *       object for the cycle (N5).</li>
 *   <li>Folded from the build 102 review: an esxcli call takes the
 *       client's read timeout (no fixed 120 s), so a held esxcli call is
 *       cut at that timeout and the cycle budget then ends the cycle
 *       (the #63 latch style).</li>
 *   <li>A RuntimeException while a request is sent or its answer read
 *       releases the connection (both clients), like an I/O failure.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build103BulkPrimaryTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) throws Exception {
		primaryPaths();
		retrieveObjectsOnePage();
		rowFirstThenPerObject();
		fixtureCallCount();
		bulkEqualsPerObject();
		missingBothWaysIsUnreadable();
		refusedPageResumesThere();
		overCapPageRemembered();
		esxcliTakesClientTimeout();
		heldEsxcliCutByBudget();
		runtimeExceptionDropsConnection();
		shadowLabels();
		System.out.println("Build103BulkPrimaryTest: all assertions passed");
	}

	static BenchmarkProfile.Control vim(String id, String kind, String param,
			String expected, String recipe) {
		return Build95CollectionTest.vim(id, kind, param, expected, recipe);
	}

	static void primaryPaths() {
		List<BenchmarkProfile.Control> host = Arrays.asList(
				vim("esx.lockdown", "HostSystem", "lockdown", "lockdownNormal",
						"scalar:config.lockdownMode"),
				Build95CollectionTest.adv("esx.shell", "HostSystem",
						"UserVars.ESXiShellTimeOut", "900"));
		Set<String> hp = VSphereClient.primaryPaths("HostSystem",
				Arrays.asList(host));
		T.check(hp.containsAll(Arrays.asList("config.lockdownMode",
				"config.option", "runtime.connectionState",
				"summary.config.product.version", "config.product.version")),
				"host paths: controls, options, connection, version: " + hp);
		List<BenchmarkProfile.Control> vsan = Arrays.asList(vim("c.v",
				"ClusterComputeResource", "csum", "true",
				"bool:configurationEx.vsanConfigInfo.defaultConfig.checksum"));
		T.check(VSphereClient.primaryPaths("ClusterComputeResource",
				Arrays.asList(vsan)).contains(
						VSphereClient.CLUSTER_PROBE_PATH),
				"a cluster with vim controls reads the vSAN probe in bulk");
		T.check(VSphereClient.primaryPaths("HostSystem", Arrays.asList(
				new ArrayList<BenchmarkProfile.Control>())).isEmpty(),
				"nothing to read: no bulk read");
		// The bundled benchmarks: every kind with vim controls has paths.
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkSelector sel = BenchmarkSelector.auto(all);
		T.eq(all.size(), sel.profilesFor(BenchmarkSelector.Kind.HOST).size(),
				"Auto: every profile can apply");
		List<List<BenchmarkProfile.Control>> slices = new ArrayList<>();
		for (BenchmarkProfile p : sel.profilesFor(BenchmarkSelector.Kind.VM)) {
			slices.add(p.vmControls());
		}
		T.check(VSphereClient.primaryPaths("VirtualMachine", slices)
				.contains("config.extraConfig"), "VMs read extraConfig in bulk");
		BenchmarkProfile pin = all.get("VMware_SCG_8.0");
		Map<BenchmarkSelector.Kind, BenchmarkProfile> pins =
				new java.util.EnumMap<>(BenchmarkSelector.Kind.class);
		pins.put(BenchmarkSelector.Kind.HOST, pin);
		T.eq(1, sel.withPins(pins).profilesFor(BenchmarkSelector.Kind.HOST)
				.size(), "a pinned kind: its pin only");
	}

	static void retrieveObjectsOnePage() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				List<String> paths = FakeVCenter.pathSets(r.body);
				if (paths.contains("config.vmwareOnly.thing")) {
					return FakeVCenter.invalidProperty("config.vmwareOnly.thing");
				}
				StringBuilder b = new StringBuilder();
				for (String[] o : FakeVCenter.objs(r.body)) {
					if (o[1].equals("host-3")) continue;   // not returned
					b.append(FakeVCenter.objectContent("returnval", o[0], o[1],
							FakeVCenter.vals("config.lockdownMode",
									"<val>lockdownNormal</val>",
									"config.vmwareOnly", "<val><thing>1</thing>"
									+ "</val>")));
				}
				return FakeVCenter.ok("RetrieveProperties", b.toString());
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			List<VSphereClient.MoRef> refs = new ArrayList<>();
			for (int i = 1; i <= 3; i++) {
				refs.add(new VSphereClient.MoRef("HostSystem", "host-" + i));
			}
			List<String> paths = Arrays.asList("config.lockdownMode",
					"config.vmwareOnly.thing");
			int before = f.count("RetrieveProperties");
			VSphereClient.BulkStats st = new VSphereClient.BulkStats();
			Map<String, VSphereClient.BulkRow> rows = c.retrieveObjects(
					"HostSystem", refs, paths, st);
			T.eq(2, f.count("RetrieveProperties") - before,
					"one call, plus one after the invalid path was shortened");
			T.eq(1, st.pathFixes, "one fix");
			T.eq(2, rows.size(), "host-3 not returned: absent, not empty");
			T.eq("lockdownNormal", VSphereClient.textOf(rows.get("host-1"),
					"config.lockdownMode"), "value in the row");
			T.check(rows.get("host-2").exact("config.vmwareOnly") != null,
					"the shortened path is read");
			before = f.count("RetrieveProperties");
			c.retrieveObjects("HostSystem", refs, paths, null);
			T.eq(1, f.count("RetrieveProperties") - before,
					"the next cycle sends the accepted set: one call");
			f.handler = r -> FakeVCenter.fault("ManagedObjectNotFound",
					"The object has already been deleted");
			try {
				c.retrieveObjects("HostSystem", refs, paths, null);
				throw new AssertionError("a failed page must throw");
			} catch (VimOptions.ReadFault e) {
				T.check(e.getMessage().contains("RetrieveProperties"),
						e.getMessage());
			}
		}
	}

	static void rowFirstThenPerObject() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				// Per object: lockdown and the firewall policy; the
				// ftEncryption path is unset everywhere.
				String path = FakeVCenter.pathSets(r.body).get(0);
				String[] o = FakeVCenter.obj(r.body);
				Map<String, String> v = FakeVCenter.vals();
				if (path.equals("config.lockdownMode")) {
					v = FakeVCenter.vals(path, "<val>lockdownStrict</val>");
				}
				return FakeVCenter.ok("RetrieveProperties",
						FakeVCenter.objectContent("returnval", o[0], o[1], v));
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			c.beginCycle();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			List<BenchmarkProfile.Control> ctl = Arrays.asList(
					vim("esx.lockdown", "HostSystem", "lockdown",
							"lockdownNormal", "scalar:config.lockdownMode"),
					vim("esx.ft", "HostSystem", "ft", "x",
							"scalar:config.ftThing"));
			// A row that carries the lockdown mode (as vCenter answered
			// the bulk read) and nothing for config.ftThing.
			VSphereClient.BulkRow row = rowOf(h, "config.lockdownMode",
					"<val>lockdownNormal</val>");
			int before = f.count("RetrieveProperties");
			Map<String, Object> v = c.readVimProperties(h, ctl, row);
			T.eq("lockdownNormal", v.get("lockdown"),
					"from the row (not the per-object value)");
			T.check(v.get("ft") == VSphereClient.UNREADABLE,
					"missing both ways: UNREADABLE, never a pass");
			T.check(c.lastReadReasons().get("ft").startsWith("prefix-cap"),
					"the per-object reason: " + c.lastReadReasons());
			T.eq(1, f.count("RetrieveProperties") - before,
					"only the miss was read per object");
			T.eq(1, c.bulkFallbackReads(), "one control read per object");
			// No row: everything per object, as build 102.
			before = f.count("RetrieveProperties");
			v = c.readVimProperties(h, ctl, null);
			T.eq("lockdownStrict", v.get("lockdown"), "per object");
			T.eq(2, f.count("RetrieveProperties") - before, "two reads");
			c.beginCycle();
			T.eq(0, c.bulkFallbackReads(), "the count is per cycle");
		}
		VSphereClient.BulkRow empty = new VSphereClient.BulkRow(
				new VSphereClient.MoRef("VirtualMachine", "vm-1"));
		T.eq(null, VSphereClient.advancedOf(empty),
				"no extraConfig in the row: null (read per object)");
		T.eq(null, VSphereClient.hostVersionOf(null), "no row: null");
		T.eq(null, VSphereClient.vsanOf(empty), "no probe value: null");
	}

	/** A bulk row with the given path/val pairs, parsed like vCenter's. */
	static VSphereClient.BulkRow rowOf(VSphereClient.MoRef ref,
			String... pathVal) throws Exception {
		VSphereClient.BulkRow row = new VSphereClient.BulkRow(ref);
		for (int i = 0; i + 1 < pathVal.length; i += 2) {
			org.w3c.dom.Document d = VSphereClient.parseXml(
					new java.io.ByteArrayInputStream(pathVal[i + 1]
							.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
			row.values.put(pathVal[i], d.getDocumentElement());
		}
		return row;
	}

	static AdapterHarness fixture() throws Exception {
		String[] pairs = new String[24];
		for (int i = 0; i < 12; i++) {
			pairs[2 * i] = "host-" + (100 + i);
			pairs[2 * i + 1] = "esx" + (100 + i);
		}
		AdapterHarness h = new AdapterHarness(pairs);
		for (int i = 0; i < 60; i++) {
			h.vm("vm-" + (1000 + i), "app" + i, "host-" + (100 + (i % 12)));
		}
		return h;
	}

	/**
	 * The fixture's steady-state cycle: 36 SOAP calls. Build 102 made 572
	 * on the same fixture (534 RetrieveProperties, 13 QueryOptions); the
	 * CHANGELOG records both. Hosts and VMs are 2 pages each; no host
	 * QueryOptions (config.option comes in the page).
	 */
	static void fixtureCallCount() throws Exception {
		try (AdapterHarness h = fixture()) {
			h.cycle();
			int before = h.vc.requests.size();
			h.cycle();
			Map<String, Integer> by = new TreeMap<>();
			int bulk = 0;
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req r : h.vc.requests.subList(before,
						h.vc.requests.size())) {
					by.merge(r.action.replace("urn:vim25/", ""), 1,
							Integer::sum);
					if (FakeVCenter.objs(r.body).size() > 1) bulk++;
				}
			}
			int total = h.vc.requests.size() - before;
			T.eq(36, total, "fixture cycle SOAP calls: " + by);
			T.eq(4, bulk, "two host pages (10 + 2) and two VM pages (50 + 10)");
			T.eq(1, by.get("QueryOptions"), "the vCenter's own settings only");
			T.check(h.logged("Bulk read Host: 12 of 12 object(s) in 2 call(s)"),
					"host summary");
			T.check(h.logged("0 control(s) read one at a time"),
					"nothing fell back");
		}
	}

	/**
	 * The bulk path pushes exactly what the per-object path pushes: the
	 * same fixture with every bulk page failing (so every object is read
	 * one at a time, as build 102) pushes the same values to the same
	 * objects; the failure is one WARN and the summary counts the rest.
	 */
	static void bulkEqualsPerObject() throws Exception {
		List<String> viaBulk = pushesOfOneCycle(false);
		List<String> perObject = pushesOfOneCycle(true);
		T.check(viaBulk.size() > 1000, "a real comparison: " + viaBulk.size());
		T.eq(perObject, viaBulk, "identical pushes");
	}

	static List<String> pushesOfOneCycle(boolean failBulk) throws Exception {
		try (AdapterHarness h = fixture()) {
			h.cycle();
			if (failBulk) {
				h.override = r -> FakeVCenter.objs(r.body).size() > 1
						? FakeVCenter.fault("ManagedObjectNotFound",
								"The object has already been deleted")
						: null;
			}
			int before = h.suite.pushes.size();
			h.cycle();
			if (failBulk) {
				T.check(h.logged("Bulk read of 10 Host object(s) failed"),
						"one WARN for the kind");
				T.check(h.logged("12 object(s) read one at a time (2 failed "
						+ "page(s)"), "the summary counts the pages");
			}
			List<String> lines = pushLines(h, before);
			return lines;
		}
	}

	/** Every property and stat pushed since {@code from}, sorted. */
	static List<String> pushLines(AdapterHarness h, int from) {
		List<String> lines = new ArrayList<>();
		synchronized (h.suite.pushes) {
			for (FakeSuiteApi.Push p : h.suite.pushes.subList(from,
					h.suite.pushes.size())) {
				if (p.props != null) {
					for (Map.Entry<String, String> e
							: new TreeMap<>(p.props).entrySet()) {
						lines.add(p.resourceId + " P " + e.getKey() + "="
								+ e.getValue());
					}
				}
				if (p.stats != null) {
					for (Map.Entry<String, Double> e
							: new TreeMap<>(p.stats).entrySet()) {
						lines.add(p.resourceId + " S " + e.getKey() + "="
								+ e.getValue());
					}
				}
			}
		}
		java.util.Collections.sort(lines);
		return lines;
	}

	/**
	 * Unreadable stays not-compliant: a VM whose config.version is unset
	 * (absent from the bulk row and from the per-object read) gets no
	 * Compliant value for that control, is flagged has_unreadable = 1, and
	 * is scored only over what was read.
	 */
	static void missingBothWaysIsUnreadable() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			h.vm("vm-1", "app01", "host-10").vm("vm-2", "app02", "host-10");
			h.cycle();
			String key = "VCF-CF Compliance|vm.virtual-hardware|Compliant";
			Map<String, Double> ok = h.suite.statsFor("r-vm-2");
			T.eq(1.0, ok.get(key), "vmx-21 passes when read: " + ok.keySet());
			h.hidden = (moid, path) -> moid.equals("vm-1")
					&& path.equals("config.version");
			AdapterHarness fresh = h;
			int before = fresh.suite.pushes.size();
			fresh.cycle();
			Map<String, Double> vm1 = new java.util.HashMap<>();
			synchronized (fresh.suite.pushes) {
				for (FakeSuiteApi.Push p : fresh.suite.pushes.subList(before,
						fresh.suite.pushes.size())) {
					if (p.stats != null && p.resourceId.equals("r-vm-1")) {
						vm1.putAll(p.stats);
					}
				}
			}
			T.check(!vm1.containsKey(key), "not pushed: no pass, no fail");
			T.eq(1.0, vm1.get(ComplianceDecisions.HAS_UNREADABLE),
					"flagged has_unreadable");
			T.check(h.logged("1 control(s) read one at a time"),
					"the bulk miss was read per object first");
		}
	}

	/**
	 * Review W3: the budget refuses a page's own RetrieveProperties. The
	 * 12-host fixture reads hosts in two pages (host-100..109, then
	 * host-110 and host-111). The clock jumps past the budget exactly when
	 * the second page's call is checked (after walk.next has started
	 * host-110), so the call is refused, host-110's per-object reads are
	 * refused in turn, and host-110 is dropped: not pushed, no partial
	 * score, Rollup|incomplete = 1, the summary counts the refused page.
	 * The next cycle resumes at host-110 with a page that starts there,
	 * and the two cycles together push all 12 hosts.
	 */
	static void refusedPageResumesThere() throws Exception {
		try (AdapterHarness h = fixture()) {
			AtomicLong now = new AtomicLong(0);
			final boolean[] armed = {false};
			final boolean[] jumped = {false};
			h.adapter.budgetClock = () -> {
				if (armed[0] && !jumped[0] && inRetrieveObjects()) {
					now.addAndGet(300L * 1_000_000_000L);
					jumped[0] = true;
				}
				return now.get();
			};
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 1 complete");

			// Cycle 2: arm the jump once the first host page is answered,
			// so the next bulk call (the second host page) is the one cut.
			int before = h.suite.pushes.size();
			int reqBefore = h.vc.requests.size();
			h.override = r -> {
				List<String[]> objs = FakeVCenter.objs(r.body);
				if (objs.size() > 1 && objs.get(0)[1].equals("host-100")) {
					armed[0] = true;
				}
				return null;
			};
			h.cycle();
			T.check(jumped[0], "the clock jumped on a bulk page's budget check");
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req r : h.vc.requests.subList(reqBefore,
						h.vc.requests.size())) {
					T.check(!r.body.contains(">host-110<"), "nothing about "
							+ "host-110 reached vCenter: " + r.action);
				}
			}
			Map<String, Double> r2 = h.lastRollup();
			T.eq(1.0, r2.get(ComplianceRollup.INCOMPLETE_KEY),
					"ended early: incomplete = 1");
			for (int i = 100; i < 110; i++) {
				T.check(Build96BudgetTest.pushedTo(h, before, "r-host-" + i),
						"host-" + i + " (page 1) pushed");
			}
			T.check(!Build96BudgetTest.pushedTo(h, before, "r-host-110"),
					"host-110, its page refused, not pushed (no partial score)");
			T.check(!Build96BudgetTest.pushedTo(h, before, "r-host-111"),
					"host-111 not reached");
			T.check(h.logged("Bulk read Host: 10 of 12 object(s) in 1 call(s)"),
					"the summary counts the one page read");
			T.check(h.logged("1 object(s) read one at a time (0 failed page(s), "
					+ "1 refused by the cycle budget)"),
					"the summary counts the refused page");
			T.check(h.logged("Cycle ended early while reading host esx110"),
					"the WARN names host-110");
			T.eq("host-109", h.holder.resume.cursor(
					BenchmarkSelector.Kind.HOST), "resume after host-109");
			T.eq(BenchmarkSelector.Kind.HOST, h.holder.resume.startKind(),
					"the next cycle starts at the hosts");

			// Cycle 3: resumes at host-110, its page starts there.
			h.override = null;
			int before3 = h.suite.pushes.size();
			int req3 = h.vc.requests.size();
			h.cycle();
			List<String> firstHostPage = null;
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req r : h.vc.requests.subList(req3,
						h.vc.requests.size())) {
					List<String[]> objs = FakeVCenter.objs(r.body);
					if (objs.size() > 1 && objs.get(0)[0].equals("HostSystem")) {
						firstHostPage = new ArrayList<>();
						for (String[] o : objs) firstHostPage.add(o[1]);
						break;
					}
				}
			}
			T.eq(Arrays.asList("host-110", "host-111"), firstHostPage,
					"the next cycle's host page starts at host-110");
			T.check(Build96BudgetTest.pushedTo(h, before3, "r-host-110"),
					"host-110 read");
			T.check(Build96BudgetTest.pushedTo(h, before3, "r-host-111"),
					"host-111 read");
			for (int i = 100; i < 110; i++) {
				T.check(!Build96BudgetTest.pushedTo(h, before3, "r-host-" + i),
						"host-" + i + ", read in cycle 2, not read again");
			}
			for (int i = 100; i < 112; i++) {
				T.check(Build96BudgetTest.pushedTo(h, before, "r-host-" + i),
						"two cycles push host-" + i);
			}
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"the pass completed: incomplete cleared");
			T.eq(12.0, h.lastRollup().get(P + "Host|scored"),
					"Host over all 12 (cycle 2's share carried)");
		}
	}

	/**
	 * Review N5: a VM page over the response cap is not tried again for
	 * every page of the kind: the rest of the VMs are read one at a time
	 * this cycle (one bulk VM call instead of two), with one WARN, and the
	 * pushes are the same as when every page is read.
	 */
	static void overCapPageRemembered() throws Exception {
		List<String> expected = pushesOfOneCycle(false);
		try (AdapterHarness h = fixture()) {
			h.cycle();
			h.client.setMaxResponseBytes(256 * 1024);
			StringBuilder pad = new StringBuilder("<!--");
			for (int i = 0; i < 300 * 1024; i++) pad.append('x');
			String big = pad.append("-->").toString();
			h.override = r -> {
				List<String[]> objs = FakeVCenter.objs(r.body);
				return objs.size() > 1 && objs.get(0)[0].equals("VirtualMachine")
						? FakeVCenter.ok("RetrieveProperties", big) : null;
			};
			int before = h.suite.pushes.size();
			int req = h.vc.requests.size();
			h.cycle();
			int vmPages = 0;
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req r : h.vc.requests.subList(req,
						h.vc.requests.size())) {
					List<String[]> objs = FakeVCenter.objs(r.body);
					if (objs.size() > 1 && objs.get(0)[0].equals("VirtualMachine")) {
						vmPages++;
					}
				}
			}
			T.eq(1, vmPages, "the second VM page is not fetched after the "
					+ "first was over the cap");
			T.check(h.logged("the rest of the VM objects are read one at a "
					+ "time this cycle"), "one WARN says so");
			T.check(h.logged("60 object(s) read one at a time (1 failed "
					+ "page(s), 0 refused by the cycle budget; over the "
					+ "response cap, the rest of the kind read one at a time)"),
					"the summary says so");
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"complete: nothing lost");
			List<String> lines = pushLines(h, before);
			T.eq(expected, lines, "the same pushes as a cycle read in bulk");
		}
	}

	/** True when the budget clock is read from inside a bulk page call. */
	static boolean inRetrieveObjects() {
		for (StackTraceElement e : Thread.currentThread().getStackTrace()) {
			if (e.getClassName().endsWith(".VSphereClient")
					&& e.getMethodName().equals("retrieveObjects")) {
				return true;
			}
		}
		return false;
	}

	/** The esxcli client is made with the client's timeout and follows it. */
	static void esxcliTakesClientTimeout() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			final CountDownLatch release = new CountDownLatch(1);
			f.handler = r -> r.action.endsWith("/RetrieveManagedMethodExecuter")
					? Build96BudgetTest.held(release, Build96BudgetTest
							.esxcliExecuter(r))
					: FakeVCenter.fault("NotSupported", "not in the fake");
			VSphereClient c = f.client();
			c.setReadTimeoutMs(300);
			c.ensureConnected();
			c.beginCycle();
			List<BenchmarkProfile.Control> ctl = Arrays.asList(
					new BenchmarkProfile.Control("esx.syslog", "P1",
							"HostSystem", "VMWARE", "persistent", "esxcli",
							"boolean", "true", "esx.syslog", "", "", "",
							"esxcli:system.syslog.config.get:"
							+ "LocalLogOutputIsPersistent"));
			long t0 = System.nanoTime();
			Object v;
			try {
				v = c.readVimProperties(new VSphereClient.MoRef("HostSystem",
						"host-1"), ctl).get("persistent");
			} finally {
				release.countDown();
			}
			long ms = (System.nanoTime() - t0) / 1_000_000L;
			T.check(v == VSphereClient.UNREADABLE, "held: UNREADABLE");
			T.check(ms < 5000, "cut at the client's 300 ms, not 120 s or the "
					+ "60 s latch (" + ms + " ms)");
			T.check(String.valueOf(c.takeEsxcliUnreachable("host-1"))
					.contains("SocketTimeoutException"),
					"the reason is the timeout");
		}
	}

	/**
	 * Folded from the build 102 review (issue #17 comment 2026-10-28), the
	 * #63 latch style: host-10's esxcli executer lookup is held on a latch
	 * that is only released after the cycle, and the cycle budget runs out
	 * as it is sent. The held call is cut at the client's read timeout
	 * (2 s here; before build 103 a fixed 120 s, which this latch would
	 * have held for its 60 s bound), host-10's other esxcli commands are
	 * not attempted, and the budget ends the cycle before host-11: the
	 * worst case is the budget plus one call, as CycleBudget documents.
	 */
	static void heldEsxcliCutByBudget() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.cycle();
			final int timeoutMs = 2000;
			h.client.setReadTimeoutMs(timeoutMs);
			final CountDownLatch release = new CountDownLatch(1);
			final AtomicInteger heldCalls = new AtomicInteger();
			h.override = r -> {
				if (r.action.endsWith("/RetrieveManagedMethodExecuter")
						&& r.body.contains(">host-10<")) {
					heldCalls.incrementAndGet();
					now.addAndGet(300L * 1_000_000_000L);   // budget gone
					return Build96BudgetTest.held(release,
							Build96BudgetTest.esxcliExecuter(r));
				}
				return null;
			};
			int before = h.suite.pushes.size();
			long t0 = System.nanoTime();
			try {
				h.cycle();
			} finally {
				release.countDown();   // free the held server thread
			}
			long ms = (System.nanoTime() - t0) / 1_000_000L;
			T.eq(1, heldCalls.get(), "one esxcli call to host-10, held");
			T.check(ms >= timeoutMs - 100, "it waited for the timeout ("
					+ ms + " ms)");
			T.check(ms < 3L * timeoutMs, "cut at the client's timeout, not "
					+ "a fixed 120 s (" + ms + " ms)");
			T.eq(1.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"the budget ended the cycle: incomplete = 1");
			T.check(h.logged("ENDED EARLY"), "the completion line says so");
			T.check(!Build96BudgetTest.pushedTo(h, before, "r-host-11"),
					"host-11 not reached");
			Map<String, Double> h10 = new java.util.HashMap<>();
			synchronized (h.suite.pushes) {
				for (FakeSuiteApi.Push p : h.suite.pushes.subList(before,
						h.suite.pushes.size())) {
					if (p.stats != null && p.resourceId.equals("r-host-10")) {
						h10.putAll(p.stats);
					}
				}
			}
			T.eq(1.0, h10.get(ComplianceDecisions.HAS_UNREADABLE),
					"host-10's esxcli controls are unreadable, flagged");
		}
	}

	/**
	 * A RuntimeException while a request is sent or its answer read
	 * releases the connection (both clients), like an I/O failure, so it
	 * is never left open and unreferenced. Pinned at the source: the JDK
	 * gives no clean way to raise one mid-call.
	 */
	static void runtimeExceptionDropsConnection() {
		String[][] files = {
				{"src/com/vcfcf/adapters/compliance/VSphereClient.java",
						"private Document postOnce("},
				{"src/com/vcfcf/adapters/compliance/EsxcliSoapClient.java",
						"private Document post("}};
		for (String[] f : files) {
			String b = OverridesTest.body(OverridesTest.readSrc(f[0]), f[1]);
			OverridesTest.inOrder(b, f[0], "catch (RuntimeException e) { "
					+ "conn.disconnect(); throw e; }",
					"catch (java.io.IOException e) {");
		}
	}

	static void shadowLabels() {
		ShadowComparator sc = ShadowComparator.perObjectCheck("Host", true);
		List<ControlEvaluator.ControlResult> bulk = Arrays.asList(
				new ControlEvaluator.ControlResult("a", "1", "1", true, ""));
		sc.record("host-1", "esx01", bulk,
				new HashSet<>(Arrays.asList("a")));
		sc.compare("host-1", Arrays.asList(
				new ControlEvaluator.ControlResult("a", "2", "1", false, "")));
		T.eq("Host esx01 (host-1) a: bulk '1 pass', per-object '2 fail'",
				sc.disagreementLines().get(0), "labels follow the direction");
		String sum = sc.summary(-1, 7);
		T.check(sum.endsWith("7 ms (scores come from the bulk read)")
				&& !sum.contains("page(s)"), sum);
	}
}
