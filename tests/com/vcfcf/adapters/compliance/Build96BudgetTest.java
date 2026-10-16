package com.vcfcf.adapters.compliance;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Build 96, issue #16 (DEF-026): the per-cycle time budget, the
 * consecutive-timeout breaker and the shorter timeout for cheap calls.
 *
 * <ul>
 *   <li>CycleBudget: the interval source (platform, else resource, else the
 *       5 minute default; an unbelievable value is not used), 80 percent,
 *       the breaker counts timeouts in a row and an answer resets it, both
 *       limits latch.</li>
 *   <li>VSphereClient: a scalar read and the keepalive use the short
 *       timeout, a listing the normal one; once a limit is reached no call
 *       is made (CycleBudget.Exhausted) and a recipe read is UNREADABLE,
 *       never a value; a hung vCenter (no answer at all) trips the
 *       breaker after five timeouts.</li>
 *   <li>The adapter cycle: the budget used up after the first host ends
 *       the cycle before the second, holds back Host and every later kind
 *       with Rollup|incomplete = 1, still pushes the rollup, and the next
 *       cycle is complete; a hung vCenter ends the cycle through the
 *       breaker in seconds, not 120 s per call.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build96BudgetTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) throws Exception {
		intervalAndBudget();
		resumeOrderByMoid();
		breakerAndDeadline();
		shortTimeoutForCheapCalls();
		refusedOnceExhausted();
		esxcliAndVamiRefusals();
		hungVCenterTripsBreaker();
		adapterBudgetEndsCycle();
		twoCyclesVisitEverything();
		vmsNotStarved();
		objectLongerThanBudget();
		dropsMustBeConsecutive();
		deadlineAfterReadsDoesNotDrop();
		hungHostCostsOneTimeout();
		noPartialScore();
		adapterBreakerEndsCycle();
		System.out.println("Build96BudgetTest: all assertions passed");
	}

	static void intervalAndBudget() {
		CycleBudget.Interval a = CycleBudget.interval(300, 600);
		T.eq(300, a.seconds, "platform interval first");
		T.check(a.source.contains("platform"), "source named: " + a.source);
		T.eq(600, CycleBudget.interval(null, 600).seconds, "resource next");
		T.eq(300, CycleBudget.interval(null, null).seconds, "default 5 min");
		// Review N3: a reported value out of range is clamped, not replaced.
		T.eq(60, CycleBudget.interval(5, null).seconds, "5 s raised to 60 s");
		T.check(CycleBudget.interval(5, null).source.contains(
				"5 s raised to the 60 s minimum"), "the clamp is named");
		T.eq(60, CycleBudget.interval(30, 900).seconds,
				"the platform value wins, clamped");
		T.eq(86400, CycleBudget.interval(90000, null).seconds,
				"25 h lowered to 24 h");
		T.eq(600, CycleBudget.interval(0, 600).seconds,
				"0 is not reported: the resource's value");
		T.eq(300, CycleBudget.interval(-1, null).seconds,
				"nothing reported: the default");
		T.eq(285000L, CycleBudget.budgetMs(300), "95% of 5 minutes (peer review item 3)");
		T.eq(5, CycleBudget.BREAKER_TIMEOUTS, "breaker default");
	}

	/** Peer review item 7: each kind is walked in MOID order. */
	static void resumeOrderByMoid() {
		ResumeCursor c = new ResumeCursor();
		List<String> listed = Arrays.asList("host-3", "host-1", "host-2");
		T.eq("[host-1, host-2, host-3]", c.order(BenchmarkSelector.Kind.HOST,
				listed, x -> x).toString(), "sorted, whatever vCenter's order");
		c.stoppedAfter(BenchmarkSelector.Kind.HOST, "host-1");
		T.eq("[host-2, host-3]", c.order(BenchmarkSelector.Kind.HOST,
				Arrays.asList("host-2", "host-3", "host-1"), x -> x).toString(),
				"the tail after the cursor in MOID order");
	}

	static void breakerAndDeadline() {
		AtomicLong now = new AtomicLong(0);
		CycleBudget b = new CycleBudget(10_000, 3, now::get);
		b.timedOut();
		b.timedOut();
		b.answered();          // the run is broken
		b.timedOut();
		b.timedOut();
		T.eq(null, b.exhausted(), "two in a row: not yet");
		b.timedOut();
		T.check(b.exhausted().contains("3 vCenter calls in a row timed out"),
				"three in a row: breaker open");
		b.answered();
		T.check(b.exhausted() != null, "breaker latches for the cycle");

		CycleBudget d = new CycleBudget(10_000, 3, now::get);
		now.addAndGet(9_999_000_000L);
		T.eq(null, d.exhausted(), "inside the budget");
		now.addAndGet(1_000_000L);
		T.check(d.exhausted().contains("budget of 10 s"), "budget used up");
		try {
			d.check();
			throw new AssertionError("check() must throw");
		} catch (CycleBudget.Exhausted e) {
			T.check(e.getMessage().startsWith("cycle ended early: "),
					e.getMessage());
		}
	}

	/** Answer after {@code ms} (no status line until then). */
	static FakeVCenter.Resp late(long ms, FakeVCenter.Resp r) {
		try {
			Thread.sleep(ms);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		return r;
	}

	static void shortTimeoutForCheapCalls() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				String[] o = FakeVCenter.obj(r.body);
				if (o != null && "ContainerView".equals(o[0])) {
					return late(600, FakeVCenter.ok("RetrieveProperties",
							FakeVCenter.objectContent("returnval",
									"HostSystem", "host-1", FakeVCenter.vals(
											"name", "<val>esx01</val>"))));
				}
				return late(600, FakeVCenter.ok("RetrieveProperties",
						FakeVCenter.objectContent("returnval", "HostSystem",
								"host-1", FakeVCenter.vals(
										"runtime.connectionState",
										"<val>connected</val>"))));
			};
			VSphereClient c = f.client();
			c.setReadTimeoutMs(3000);
			c.setShortReadTimeoutMs(200);
			c.ensureConnected();
			long t0 = System.nanoTime();
			try {
				c.getHostConnectionState(
						new VSphereClient.MoRef("HostSystem", "host-1"));
				throw new AssertionError("a 600 ms scalar read must time out");
			} catch (java.net.SocketTimeoutException e) {
				long ms = (System.nanoTime() - t0) / 1_000_000L;
				T.check(ms < 550, "short timeout used (" + ms + " ms)");
			}
			T.eq(1, c.getHosts().size(),
					"a 600 ms listing keeps the normal timeout");
		}
	}

	static void refusedOnceExhausted() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> FakeVCenter.ok("RetrieveProperties",
					FakeVCenter.objectContent("returnval", "HostSystem",
							"host-1", FakeVCenter.vals("config.lockdownMode",
									"<val>lockdownNormal</val>")));
			VSphereClient c = f.client();
			c.ensureConnected();
			AtomicLong now = new AtomicLong(0);
			CycleBudget b = new CycleBudget(1000, 5, now::get);
			c.setCycleBudget(b);
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			List<BenchmarkProfile.Control> ctl = Arrays.asList(
					Build95CollectionTest.vim("esx.lockdown", "HostSystem",
							"lockdown", "lockdownNormal",
							"scalar:config.lockdownMode"));
			T.eq("lockdownNormal", c.readVimProperties(h, ctl).get("lockdown"),
					"inside the budget: read");
			now.set(2_000_000_000L);
			int before = f.requests.size();
			Object v = c.readVimProperties(h, ctl).get("lockdown");
			T.check(v == VSphereClient.UNREADABLE,
					"over budget: UNREADABLE, never the value");
			T.check(c.lastReadReasons().get("lockdown").contains(
					"cycle ended early"), "reason names the budget: "
					+ c.lastReadReasons());
			T.eq(before, f.requests.size(), "no request was made");
			try {
				c.getHosts();
				throw new AssertionError("a listing must be refused");
			} catch (CycleBudget.Exhausted e) {
				// a refused listing holds its kind back in the adapter
			}
			c.setCycleBudget(null);
			T.eq("lockdownNormal", c.readVimProperties(h, ctl).get("lockdown"),
					"next cycle (no budget set): read again");
		}
	}

	/**
	 * Review N2: an esxcli command refused by the budget says "budget
	 * reached" and does not mark the host unreachable. Review N10: the
	 * appliance (VAMI) calls are refused too, with no request made.
	 */
	static void esxcliAndVamiRefusals() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			VSphereClient c = f.client();
			c.ensureConnected();
			AtomicLong now = new AtomicLong(0);
			CycleBudget b = new CycleBudget(1000, 5, now::get);
			c.setCycleBudget(b);
			now.set(2_000_000_000L);
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			List<BenchmarkProfile.Control> ctl = Arrays.asList(
					new BenchmarkProfile.Control("esx.syslog", "P1",
							"HostSystem", "VMWARE", "persistent", "esxcli",
							"boolean", "true", "esx.syslog", "", "", "",
							"esxcli:system.syslog.config.get:"
							+ "LocalLogOutputIsPersistent"));
			int before = f.requests.size();
			Object v = c.readVimProperties(h, ctl).get("persistent");
			T.check(v == VSphereClient.UNREADABLE, "refused: UNREADABLE");
			String why = c.lastReadReasons().get("persistent");
			T.check(why != null && why.startsWith("esxcli-budget-reached"),
					"reason says budget: " + why);
			T.eq(null, c.takeEsxcliUnreachable("host-1"),
					"the host is not marked unreachable");
			T.eq(before, f.requests.size(), "no request made");
		}
		AtomicLong now = new AtomicLong(0);
		CycleBudget b = new CycleBudget(1000, 5, now::get);
		now.set(2_000_000_000L);
		VamiApiClient vami = new VamiApiClient("https://127.0.0.1:9",
				"u", "p", null, null);
		vami.setCycleBudget(b);
		T.check(vami.readField("access/ssh", "enabled") == VamiApiClient.FAILED,
				"VAMI refused: FAILED (UNREADABLE)");
		T.check(String.valueOf(vami.failureReason("access/ssh", "enabled"))
				.contains("cycle ended early"), "VAMI reason says budget: "
				+ vami.failureReason("access/ssh", "enabled"));
	}

	static void hungVCenterTripsBreaker() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> late(400, FakeVCenter.ok("RetrieveProperties", ""));
			VSphereClient c = f.client();
			c.ensureConnected();
			c.setReadTimeoutMs(100);
			CycleBudget b = new CycleBudget(600_000, 5, System::nanoTime);
			c.setCycleBudget(b);
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			int timeouts = 0;
			int refused = 0;
			for (int i = 0; i < 8; i++) {
				try {
					c.getHostConnectionState(h);
				} catch (CycleBudget.Exhausted e) {
					refused++;
				} catch (java.net.SocketTimeoutException e) {
					timeouts++;
				}
			}
			T.eq(5, timeouts, "five timeouts");
			T.eq(3, refused, "then every call refused");
			T.check(b.exhausted().contains("5 vCenter calls in a row"),
					b.exhausted());
		}
	}

	/** Pushes to {@code id} in pushes[from..]. */
	static boolean pushedTo(AdapterHarness h, int from, String id) {
		synchronized (h.suite.pushes) {
			for (FakeSuiteApi.Push p : h.suite.pushes.subList(from,
					h.suite.pushes.size())) {
				if (p.resourceId.equals(id)) return true;
			}
		}
		return false;
	}

	/**
	 * The budget is used up while host-11 is being read. The small kinds
	 * (vCenter, switches, portgroups, clusters) ran first and are pushed;
	 * host-11 is not pushed at all (review W2: no partial score); Host and
	 * VM are held back with incomplete = 1; the next cycle starts with
	 * host-11 (review B1) and is complete.
	 */
	static void adapterBudgetEndsCycle() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02", "host-12", "esx03")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 1 complete");
			T.check(h.logged("Cycle limits: time budget 285 s (95% of the "
					+ "300 s interval, the default collection interval"),
					"budget line names its source");

			int before = h.suite.pushes.size();
			final boolean[] jumped = {false};
			h.override = r -> {
				if (!jumped[0] && r.body.contains(">host-11<")) {
					now.addAndGet(300L * 1_000_000_000L);
					jumped[0] = true;
				}
				return null;
			};
			h.cycle();
			Map<String, Double> r2 = h.lastRollup();
			T.eq(1.0, r2.get(ComplianceRollup.INCOMPLETE_KEY),
					"ended early: incomplete = 1");
			for (String k : new String[] {"Host", "VM", "All"}) {
				T.check(!r2.containsKey(P + k + "|scored"), k + " held back");
			}
			T.check(r2.containsKey(P + "vCenter|scored"),
					"the vCenter object ran before the hosts and is pushed");
			T.check(h.logged("Cycle ended early while reading host esx02"),
					"one WARN says where");
			T.check(h.logged("ENDED EARLY"), "completion line says so");
			T.check(pushedTo(h, before, "r-host-10"), "host-10 pushed");
			T.check(!pushedTo(h, before, "r-host-11"),
					"host-11, cut mid-read, not pushed (no partial score)");
			T.check(!pushedTo(h, before, "r-host-12"), "host-12 not reached");
			T.eq("host-10", h.holder.resume.cursor(
					BenchmarkSelector.Kind.HOST), "resume after host-10");

			T.eq(BenchmarkSelector.Kind.HOST, h.holder.resume.startKind(),
					"the next cycle starts at the hosts");

			// Cycle 3 resumes the host walk with host-11 (the tail of the
			// pass), then VMs and round to the small kinds. Peer review item
			// 3: the round completes, so Host is pushed over all three
			// hosts (host-10's share carried from cycle 2), not held back.
			h.override = null;
			int before3 = h.suite.pushes.size();
			h.cycle();
			T.check(pushedTo(h, before3, "r-host-11"), "host-11 read");
			T.check(pushedTo(h, before3, "r-host-12"), "host-12 read");
			T.check(!pushedTo(h, before3, "r-host-10"),
					"host-10, read earlier in this pass, is not read again");
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"the round completed: incomplete cleared");
			T.eq(3.0, h.lastRollup().get(P + "Host|scored"),
					"Host over all three hosts (carried share added)");
			T.eq(null, h.holder.resume.cursor(BenchmarkSelector.Kind.HOST),
					"the pass reached the end of the hosts");
			T.eq(null, h.holder.resume.startKind(), "and the round");

			// Cycle 4: a full pass again, complete.
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"full pass: complete");
			T.eq(3.0, h.lastRollup().get(P + "Host|scored"),
					"all three hosts scored");
		}
	}

	/**
	 * Review B1: two consecutive budget-ended cycles together visit every
	 * object. Each host costs 50 s of the 285 s budget, so a cycle reads
	 * four of six hosts and is cut in the fifth; the next cycle starts
	 * after the last host finished.
	 */
	static void twoCyclesVisitEverything() throws Exception {
		String[] pairs = new String[12];
		for (int i = 0; i < 6; i++) {
			pairs[2 * i] = "host-" + (20 + i);
			pairs[2 * i + 1] = "esx" + (20 + i);
		}
		try (AdapterHarness h = new AdapterHarness(pairs)) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.override = r -> {
				if (r.body.contains("runtime.connectionState")) {
					now.addAndGet(50L * 1_000_000_000L);
				}
				return null;
			};
			java.util.Set<String> pushed = new java.util.TreeSet<>();
			for (int cycle = 1; cycle <= 2; cycle++) {
				int before = h.suite.pushes.size();
				h.cycle();
				// Cycle 1 ends early; cycle 2 reads the rest and completes
				// the round, so Host is pushed over all six (item 3).
				T.eq(cycle == 1 ? 1.0 : 0.0, h.lastRollup().get(
						ComplianceRollup.INCOMPLETE_KEY), "cycle " + cycle);
				if (cycle == 2) {
					T.eq(6.0, h.lastRollup().get(P + "Host|scored"),
							"Host over all six hosts");
				}
				synchronized (h.suite.pushes) {
					for (FakeSuiteApi.Push p : h.suite.pushes.subList(before,
							h.suite.pushes.size())) {
						if (p.resourceId.startsWith("r-host-")) {
							pushed.add(p.resourceId);
						}
					}
				}
			}
			T.eq(6, pushed.size(), "every host visited over two cycles: "
					+ pushed);
		}
	}

	/**
	 * Review B1-r2 (a): the host walk alone overruns the budget (4 hosts at
	 * 100 s each, 285 s budget) and the vCenter object costs 150 s, and
	 * every VM is still read within 3 cycles, because the next cycle
	 * carries on from the hosts into the VMs instead of starting again at
	 * the small kinds. (Restarting at the top each cycle, the vCenter's
	 * 150 s plus one host fill every cycle and the VMs wait about 8.)
	 */
	static void vmsNotStarved() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02", "host-12", "esx03", "host-13", "esx04")) {
			h.vm("vm-1", "app01", "host-10").vm("vm-2", "app02", "host-11")
					.vm("vm-3", "app03", "host-12");
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.override = r -> {
				if (r.body.contains("runtime.connectionState")) {
					now.addAndGet(100L * 1_000_000_000L);
				} else if (r.body.contains(">VpxSettings<")) {
					now.addAndGet(150L * 1_000_000_000L);
				} else if (r.body.contains("config.extraConfig")) {
					now.addAndGet(10L * 1_000_000_000L);
				}
				return null;
			};
			java.util.Set<String> vmsPushed = new java.util.TreeSet<>();
			for (int cycle = 1; cycle <= 3; cycle++) {
				int before = h.suite.pushes.size();
				h.cycle();
				synchronized (h.suite.pushes) {
					for (FakeSuiteApi.Push p : h.suite.pushes.subList(before,
							h.suite.pushes.size())) {
						if (p.resourceId.startsWith("r-vm-")) {
							vmsPushed.add(p.resourceId);
						}
					}
				}
			}
			T.eq("[r-vm-1, r-vm-2, r-vm-3]", vmsPushed.toString(),
					"every VM read within 3 cycles");
		}
	}

	/**
	 * Review B1-r2 (b): one object takes longer than the whole budget. It
	 * is dropped once (cycle 1), pushed flagged with what was read on the
	 * second consecutive drop (cycle 2: Not Read = 1, Host held back), and
	 * the walk moves past it (cycle 3 reads the next host).
	 */
	static void objectLongerThanBudget() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.cycle();   // a full read first: host-10's score on record
			Double before = h.suite.statsFor("r-host-10").get(
					"VCF-CF Compliance|score");
			T.check(before != null, "host-10 scored by a full read");
			h.override = r -> {
				if (r.body.contains("runtime.connectionState")
						&& r.body.contains(">host-10<")) {
					now.addAndGet(300L * 1_000_000_000L);
				}
				return null;
			};
			int b1 = h.suite.pushes.size();
			h.cycle();
			T.check(!pushedTo(h, b1, "r-host-10"), "cycle 1: dropped");
			T.check(!pushedTo(h, b1, "r-host-11"), "cycle 1: not reached");

			int b2 = h.suite.pushes.size();
			h.cycle();
			Map<String, Double> h10 = new java.util.HashMap<>();
			Map<String, String> h10p = new java.util.HashMap<>();
			synchronized (h.suite.pushes) {
				for (FakeSuiteApi.Push p : h.suite.pushes.subList(b2,
						h.suite.pushes.size())) {
					if (!p.resourceId.equals("r-host-10")) continue;
					if (p.stats != null) h10.putAll(p.stats);
					if (p.props != null) h10p.putAll(p.props);
				}
			}
			T.eq(1.0, h10.get(ComplianceDecisions.HAS_UNREADABLE),
					"cycle 2: Not Read = 1");
			// Peer review item 2: markers only.
			T.eq(java.util.Collections.singleton(
					ComplianceDecisions.HAS_UNREADABLE), h10.keySet(),
					"cycle 2: no score, counter or per-control key pushed");
			T.check(h10p.get(ComplianceDecisions.UNREADABLE_REASON)
					.startsWith("cut by cycle budget twice"), "the reason");
			T.eq(before, h.suite.statsFor("r-host-10").get(
					"VCF-CF Compliance|score"), "the score did not move");
			T.eq(1.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 2: Host held back");
			T.check(h.logged("cut by cycle budget twice"), "the WARN says so");

			int b3 = h.suite.pushes.size();
			h.cycle();
			T.check(pushedTo(h, b3, "r-host-11"),
					"cycle 3: the walk moved past host-10");
		}
	}

	/**
	 * Peer review item 5: the two-drop rule needs consecutive drops. A drop
	 * in one cycle, clean cycles after it, then a drop again counts as a
	 * first drop (not pushed), not a second.
	 */
	static void dropsMustBeConsecutive() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			final boolean[] slow = {true};
			h.override = r -> {
				if (slow[0] && r.body.contains("runtime.connectionState")
						&& r.body.contains(">host-10<")) {
					now.addAndGet(300L * 1_000_000_000L);
				}
				return null;
			};
			int b = h.suite.pushes.size();
			h.cycle();   // cycle N: dropped
			T.check(!pushedTo(h, b, "r-host-10"), "cycle N: dropped");
			slow[0] = false;
			for (int i = 1; i <= 4; i++) {
				b = h.suite.pushes.size();
				h.cycle();   // clean cycles
				T.check(pushedTo(h, b, "r-host-10"), "clean cycle " + i);
			}
			slow[0] = true;
			b = h.suite.pushes.size();
			h.cycle();   // cycle N+5: a first drop again
			T.check(!pushedTo(h, b, "r-host-10"),
					"cycle N+5: dropped (a first drop), not pushed as a second");
		}
	}

	/**
	 * Review N2-r2: the deadline passes during an object's last read (no
	 * call refused while it was read): it is pushed in full, and the walk
	 * stops before the next object.
	 */
	static void deadlineAfterReadsDoesNotDrop() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			int r0 = h.vc.requests.size();
			h.cycle();
			int n = 0;
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req q : h.vc.requests.subList(r0,
						h.vc.requests.size())) {
					if (q.body.contains("host-10")) n++;
				}
			}
			Double full = h.suite.statsFor("r-host-10").get(
					"VCF-CF Compliance|score");
			final int last = n;
			final int[] seenCalls = {0};
			h.override = r -> {
				if (r.body.contains("host-10") && ++seenCalls[0] == last) {
					now.addAndGet(300L * 1_000_000_000L);
				}
				return null;
			};
			int before = h.suite.pushes.size();
			h.cycle();
			T.check(pushedTo(h, before, "r-host-10"),
					"read in full before the deadline: pushed");
			Map<String, Double> h10 = new java.util.HashMap<>();
			synchronized (h.suite.pushes) {
				for (FakeSuiteApi.Push p : h.suite.pushes.subList(before,
						h.suite.pushes.size())) {
					if (p.stats != null && p.resourceId.equals("r-host-10")) {
						h10.putAll(p.stats);
					}
				}
			}
			T.eq(full, h10.get("VCF-CF Compliance|score"), "its full score");
			T.check(!pushedTo(h, before, "r-host-11"),
					"the walk stops before the next host");
		}
	}

	/**
	 * Review B1, peer review item 1: a host whose hostd hangs (vCenter
	 * still says connected) costs one host-relayed timeout: its QueryOptions
	 * times out, and none of its esxcli commands is attempted. Properties
	 * vCenter answers from its own inventory are still read, exactly as in
	 * build 95, so the host scores the same controls build 95 would
	 * (advanced settings and esxcli unreadable, vCenter-answered controls
	 * read); the next host is read normally.
	 */
	static void hungHostCostsOneTimeout() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			h.cycle();
			h.client.setReadTimeoutMs(200);
			h.client.setShortReadTimeoutMs(200);
			final int[] relayed = {0};
			h.override = r -> {
				boolean hostTen = r.body.contains(">host-10<")
						|| r.body.contains("EsxHostAdvSettings-host-10");
				boolean hostRelayed = r.action.endsWith("/QueryOptions")
						|| r.action.endsWith("/ExecuteSoap")
						|| r.action.endsWith("/RetrieveManagedMethodExecuter");
				if (hostTen && hostRelayed) {
					relayed[0]++;
					return late(1000, FakeVCenter.ok("QueryOptions", ""));
				}
				return null;
			};
			int reqBefore = h.vc.requests.size();
			int before = h.suite.pushes.size();
			h.cycle();
			T.eq(1, relayed[0], "one host-relayed call to the hung host");
			boolean lockdownRead = false;
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req q : h.vc.requests.subList(reqBefore,
						h.vc.requests.size())) {
					if (q.body.contains(">host-10<")
							&& q.body.contains("config.lockdownMode")) {
						lockdownRead = true;
					}
				}
			}
			T.check(lockdownRead,
					"a vCenter-answered property of host-10 is still read");
			T.check(pushedTo(h, before, "r-host-11"),
					"the next host is read and pushed");
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
					"advanced settings and esxcli unreadable: flagged");
			T.eq(1.0, h10.get("VCF-CF Compliance|esx.lockdown-mode|Compliant"),
					"the vCenter-answered control is read and scored");
			T.check(h10.containsKey("VCF-CF Compliance|score"),
					"scored over what was read, as build 95 would");
		}
	}

	/**
	 * Review W2: a host whose full read scores 64.58 never shows 100 from a
	 * partial read cut by the budget: the cut object is not pushed.
	 */
	static void noPartialScore() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.cycle();
			Double full = h.suite.statsFor("r-host-10").get(
					"VCF-CF Compliance|score");
			T.check(full != null && full < 100.0,
					"the full read fails some controls: " + full);
			// The budget runs out after the advanced settings are read
			// (passing reads only would follow).
			h.override = r -> {
				if (r.action.endsWith("/QueryOptions")
						&& r.body.contains("EsxHostAdvSettings-host-10")) {
					now.addAndGet(300L * 1_000_000_000L);
				}
				return null;
			};
			int before = h.suite.pushes.size();
			h.cycle();
			T.check(!pushedTo(h, before, "r-host-10"),
					"not pushed: no partial score");
			T.eq(1.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"Host held back, incomplete = 1");
			T.eq(full, h.suite.statsFor("r-host-10").get(
					"VCF-CF Compliance|score"), "its last score stays");
		}
	}

	static void adapterBreakerEndsCycle() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02", "host-12", "esx03")) {
			h.cycle();   // logs in, normal cycle
			h.client.setReadTimeoutMs(150);
			// vCenter stops answering per-object reads (the listing still
			// answers, so the loop starts).
			h.override = r -> {
				String[] o = FakeVCenter.obj(r.body);
				boolean listing = o != null && "ContainerView".equals(o[0]);
				if (listing || r.action.endsWith("/CurrentTime")
						|| r.action.endsWith("/CreateContainerView")) {
					return null;
				}
				return late(1000, FakeVCenter.ok("RetrieveProperties", ""));
			};
			long t0 = System.nanoTime();
			h.cycle();
			long ms = (System.nanoTime() - t0) / 1_000_000L;
			Map<String, Double> r = h.lastRollup();
			T.eq(1.0, r.get(ComplianceRollup.INCOMPLETE_KEY),
					"breaker: incomplete = 1");
			T.check(!r.containsKey(P + "Host|scored"), "Host held back");
			T.check(h.logged("vCenter calls in a row timed out"),
					"the breaker is named");
			T.check(ms < 10_000, "ended in seconds (" + ms + " ms)");
		}
	}
}
