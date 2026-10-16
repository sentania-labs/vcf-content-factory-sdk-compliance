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
		breakerAndDeadline();
		shortTimeoutForCheapCalls();
		refusedOnceExhausted();
		hungVCenterTripsBreaker();
		adapterBudgetEndsCycle();
		adapterBreakerEndsCycle();
		System.out.println("Build96BudgetTest: all assertions passed");
	}

	static void intervalAndBudget() {
		CycleBudget.Interval a = CycleBudget.interval(300, 600);
		T.eq(300, a.seconds, "platform interval first");
		T.check(a.source.contains("platform"), "source named: " + a.source);
		T.eq(600, CycleBudget.interval(null, 600).seconds, "resource next");
		T.eq(300, CycleBudget.interval(null, null).seconds, "default 5 min");
		T.eq(300, CycleBudget.interval(5, null).seconds,
				"5 (minutes, not seconds) is not believed");
		T.check(CycleBudget.interval(5, null).source.contains("reported 5 s"),
				"the unbelieved value is named");
		T.eq(900, CycleBudget.interval(30, 900).seconds,
				"an unbelievable platform value falls to the resource");
		T.eq(240000L, CycleBudget.budgetMs(300), "80% of 5 minutes");
		T.eq(5, CycleBudget.BREAKER_TIMEOUTS, "breaker default");
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

	static void adapterBudgetEndsCycle() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02", "host-12", "esx03")) {
			AtomicLong now = new AtomicLong(0);
			h.adapter.budgetClock = now::get;
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 1 complete");
			T.check(h.logged("Cycle limits: time budget 240 s (80% of the "
					+ "300 s interval, the default collection interval"),
					"budget line names its source");

			// Cycle 2: the clock passes the budget during host-11's first
			// read. host-11's remaining reads are refused (UNREADABLE, it
			// is pushed flagged), and the loop stops before host-12.
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
			for (String k : new String[] {"Host", "VM", "vCenter", "Cluster",
					"vDS", "Portgroup", "All"}) {
				T.check(!r2.containsKey(P + k + "|scored"),
						k + " held back");
			}
			T.check(h.logged("Cycle ended early before host esx03"),
					"one WARN says where");
			T.check(h.logged("ENDED EARLY"), "completion line says so");
			boolean pushed12 = false;
			synchronized (h.suite.pushes) {
				for (FakeSuiteApi.Push p : h.suite.pushes.subList(before,
						h.suite.pushes.size())) {
					if (p.resourceId.equals("r-host-12")) pushed12 = true;
				}
			}
			T.check(!pushed12, "host-12 not read or pushed");

			h.override = null;
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"next cycle complete");
			T.eq(3.0, h.lastRollup().get(P + "Host|scored"),
					"all three hosts scored again");
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
