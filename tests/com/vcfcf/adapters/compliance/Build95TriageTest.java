package com.vcfcf.adapters.compliance;

import java.util.Map;

/**
 * Build 95, open-issue triage items. The behaviour is run on the SDK-free
 * classes (review N5 moved the host-listing hold-back and the stop flag
 * into them, and the client tests run against a local fake vCenter); only
 * the adapter's wiring, which needs the SDK, is still pinned from source
 * (the per-object loops' stop checks, the cycle order, configure's
 * build-swap-release order, short "uses the helper" pins).
 *
 * <ul>
 *   <li>#18: a failed host listing holds the Host kind back (with All and
 *       Benchmark), sets Rollup|incomplete = 1 and lets the other kinds be
 *       collected, instead of failing the cycle with no signal.</li>
 *   <li>#16 (first slice): every per-object loop checks the stop flag
 *       before each object, so Stop Collecting abandons the cycle within
 *       one object, and the abandoned cycle is logged.</li>
 *   <li>#24: a SOAP response is read through a cap and parsed straight
 *       from the stream; a response over the cap fails the call
 *       (UNREADABLE, reason response-too-large), and the next call works
 *       on a fresh connection.</li>
 *   <li>#23 / #28: configure builds the new vCenter and Suite API clients,
 *       swaps them in, then releases the previous ones (review W4); a
 *       released client is closed: it never logs in again, so a cycle
 *       still on it fails its calls, and its Logout wait is bounded; the
 *       dead REST client field is gone.</li>
 *   <li>#25: REST and VAMI Basic auth encode the credential as UTF-8,
 *       whatever the platform charset.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build95TriageTest {

	private static final String P = ComplianceRollup.PREFIX;
	private static final String CA =
			"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java";

	public static void main(String[] args) throws Exception {
		hostListingFailure();
		stopBetweenObjects();
		responseCap();
		releaseOnReconfigure();
		basicAuthUtf8();
		System.out.println("Build95TriageTest: all assertions passed");
	}

	/** #18. */
	static void hostListingFailure() {
		// Review N5: the hold-back decision is SDK-free, so it is run, not
		// matched in the source. A failed listing: reported once, the kind
		// held back, null (never an empty inventory).
		ComplianceRollup held = new ComplianceRollup();
		java.util.List<Exception> reported = new java.util.ArrayList<>();
		java.util.List<String> none = ComplianceDecisions.listOrHoldBack(
				() -> { throw new VimOptions.ReadFault("listing failed"); },
				held, BenchmarkSelector.Kind.HOST, reported::add);
		T.check(none == null, "a failed listing returns null, not empty");
		T.eq(1, reported.size(), "reported once");
		T.near(1, held.toStats().get(ComplianceRollup.INCOMPLETE_KEY),
				"kind held back: incomplete = 1");
		ComplianceRollup fine = new ComplianceRollup();
		java.util.List<String> listed = ComplianceDecisions.listOrHoldBack(
				() -> java.util.Arrays.asList("host-1"), fine,
				BenchmarkSelector.Kind.HOST, e -> T.check(false, "no report"));
		T.eq(java.util.Arrays.asList("host-1"), listed, "listing returned");
		T.check(!fine.toStats().containsKey(ComplianceRollup.INCOMPLETE_KEY)
				|| fine.toStats().get(ComplianceRollup.INCOMPLETE_KEY) == 0,
				"nothing held back on success");
		// Wiring (the adapter needs the SDK): collectHosts uses it for the
		// Host kind and returns when it says the listing failed.
		String ca = OverridesTest.readSrc(CA);
		OverridesTest.inOrder(OverridesTest.body(ca,
				"private java.util.Map<String, String> collectHosts("),
				"collectHosts", "ComplianceDecisions.listOrHoldBack(",
				"return vsphere.getHosts();",
				"rollup, BenchmarkSelector.Kind.HOST,",
				"if (hosts == null) { return hostVersions; }");
		// The cycle still runs every other kind after collectHosts returns.
		OverridesTest.inOrder(OverridesTest.body(ca,
				"private void collectWorldCycle("), "collectWorldCycle",
				"hostVersions = collectHosts(selector, rollup, cs, seen);",
				"collectVms(selector, hostVersions, rollup, cs, seen);",
				"vcEntry = collectVCenter(selector, vcVersion, rollup, cs, seen);",
				"collectDvs(", "collectDvpg(", "collectClusters(",
				"pushRollup(vcEntry, rollup);");

		// What the rollup then pushes: Host, All and Benchmark held back,
		// the other kinds pushed, incomplete = 1.
		ComplianceRollup r = new ComplianceRollup();
		r.markIncomplete(BenchmarkSelector.Kind.HOST);
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19, 4, 0,
				ControlEvaluator.score(15, 4));
		r.recordEvaluated(BenchmarkSelector.Kind.VCENTER, "SCG_9.1", 10, 5, 0,
				ControlEvaluator.score(5, 5));
		Map<String, Double> s = r.toStats();
		T.near(1, s.get(ComplianceRollup.INCOMPLETE_KEY), "incomplete = 1");
		for (String k : new String[] {"scored", "non_compliant",
				"controls_evaluated", "pass_rate", "unmatched"}) {
			T.check(!s.containsKey(P + "Host|" + k), "Host|" + k + " held back");
			T.check(!s.containsKey(P + "All|" + k), "All|" + k + " held back");
		}
		T.check(!s.containsKey(P + "Benchmark|SCG_9.1|objects"),
				"Benchmark held back");
		T.near(1, s.get(P + "VM|scored"), "VMs still collected");
		T.near(50, s.get(P + "vCenter|pass_rate"), "vCenter still collected");

		// VMs read their host's version on demand when the host map is
		// empty (the host listing failed).
		String[] asked = {null};
		String v = ComplianceDecisions.resolveVmHostVersion("host-7",
				new java.util.HashMap<>(), moid -> {
					asked[0] = moid;
					return "9.0.1";
				});
		T.eq("host-7", asked[0], "host version read on demand");
		T.eq("9.0.1", v, "VM governed by the on-demand version");
	}

	/** #16 first slice. */
	static void stopBetweenObjects() throws Exception {
		boolean[] flag = {false};
		StopCheck sc = new StopCheck(() -> flag[0]);
		int processed = 0;
		String[] objects = {"esx01", "esx02", "esx03", "esx04"};
		try {
			for (String o : objects) {
				sc.check("host " + o);
				processed++;
				if (o.equals("esx02")) flag[0] = true;   // Stop requested
			}
			T.check(false, "a requested stop throws");
		} catch (InterruptedException e) {
			T.check(e.getMessage().contains("before host esx03"),
					"names where it stopped: " + e.getMessage());
		}
		T.eq(2, processed, "stopped within one object of the request");
		T.eq("host esx03", sc.stoppedAt(), "stoppedAt");
		new StopCheck(() -> false).check("x");   // no stop: no throw

		String ca = OverridesTest.readSrc(CA);
		String[][] loops = {
				{"private java.util.Map<String, String> collectHosts(",
						"for (VSphereClient.HostInfo hostInfo : hosts) { "
						+ "stop.check(\"host \" + hostInfo.name);"},
				{"private void collectVms(",
						"for (VSphereClient.VmInfo vm : vms) { "
						+ "stop.check(\"VM \" + vm.name);"},
				{"private void collectDvs(",
						"for (VSphereClient.DvsInfo dvs : switches) { "
						+ "stop.check(\"vDS \" + dvs.name);"},
				{"private void collectDvpg(",
						"for (VSphereClient.DvpgInfo pg : pgs) { "
						+ "stop.check(\"portgroup \" + pg.name);"},
				{"private void collectClusters(",
						"for (VSphereClient.ClusterInfo cluster : clusters) { "
						+ "stop.check(\"cluster \" + cluster.name);"},
				{"private void runShadow(",
						"for (VSphereClient.BulkRow row : rows) { "
						+ "stop.check(\"bulk shadow \""},
				{"private void cleanStaleControls(",
						"i += CLEANUP_BATCH) { stop.check(\"per-control "
						+ "cleanup of \""},
		};
		for (String[] l : loops) {
			String b = OverridesTest.body(ca, l[0]);
			T.check(b.contains(l[1]), l[0] + " checks the stop flag first "
					+ "in its loop");
		}
		// runShadow does not swallow the stop; the cycle logs it.
		OverridesTest.inOrder(OverridesTest.body(ca, "private void runShadow("),
				"runShadow", "catch (InterruptedException e) { throw e; }",
				"catch (Exception e) {");
		// Review N4: an abandoned cycle logs ONE WARN carrying where it
		// stopped and the timing summary; no second "failed" line.
		String abandoned = ComplianceDecisions.cycleEndLine(false,
				"stopped before host esx03", 1234,
				"phases: host reads 1000 ms");
		T.check(abandoned.startsWith("ComplianceAdapter cycle abandoned after "
				+ "1234 ms: stopped before host esx03."), abandoned);
		T.check(abandoned.endsWith(" phases: host reads 1000 ms"),
				"timing summary on the abandoned line: " + abandoned);
		T.check(!abandoned.contains("failed"), "not also a failure line");
		T.eq("ComplianceAdapter cycle took 9 ms",
				ComplianceDecisions.cycleEndLine(true, null, 9, null), "done");
		T.check(ComplianceDecisions.cycleEndLine(false, null, 9, null)
				.startsWith("ComplianceAdapter cycle failed after 9 ms"),
				"other failures unchanged");
		CycleMetrics cm = new CycleMetrics();
		T.check(ComplianceDecisions.cycleEndLine(false, "x", 1, cm.summary())
				.endsWith(cm.summary()), "carries CycleMetrics.summary()");
		// Wiring (the adapter needs the SDK): one end line from the
		// finally, with the summary when abandoned.
		String cw = OverridesTest.body(ca, "private void collectWorld(");
		OverridesTest.inOrder(cw, "collectWorld",
				"catch (InterruptedException e) {",
				"abandonedAt = String.valueOf(e.getMessage()); throw e; }",
				"finally {",
				"ComplianceDecisions.cycleEndLine(completed, abandonedAt, ms, "
						+ "abandonedAt != null ? metrics.summary() : null);");
		T.eq(0, OverridesTest.count(cw, "logWarn(\"ComplianceAdapter cycle"),
				"no other cycle-end WARN");
		// Review N5: the adapter's flag (framework stop request OR an
		// interrupt of the collect thread) is StopCheck.orInterrupted, run
		// here rather than matched in the source.
		boolean[] abort = {false};
		StopCheck adapterStop = StopCheck.orInterrupted(() -> abort[0]);
		adapterStop.check("nothing requested");   // no throw
		abort[0] = true;
		boolean threw = false;
		try {
			adapterStop.check("host esx09");
		} catch (InterruptedException e) {
			threw = true;
		}
		T.check(threw, "the framework stop request stops the cycle");
		abort[0] = false;
		Thread.currentThread().interrupt();
		threw = false;
		try {
			adapterStop.check("host esx10");
		} catch (InterruptedException e) {
			threw = true;
		}
		T.check(Thread.interrupted(), "the interrupt flag is left set "
				+ "(cleared here by the test)");
		T.check(threw, "an interrupt of the collect thread stops the cycle");
		T.check(OverridesTest.stripComments(ca).replaceAll("\\s+", " ")
				.contains("StopCheck.orInterrupted( this::isAbortRequested)")
				|| OverridesTest.stripComments(ca).replaceAll("\\s+", " ")
				.contains("StopCheck.orInterrupted(this::isAbortRequested)"),
				"the adapter's stop is the framework request or an interrupt");
	}

	/** #24. */
	static void responseCap() throws Exception {
		T.eq(64L * 1024 * 1024, VSphereClient.MAX_SOAP_RESPONSE_BYTES,
				"default cap 64 MB");
		byte[] hundred = new byte[100];
		VSphereClient.CappedInputStream ok = new VSphereClient.CappedInputStream(
				new java.io.ByteArrayInputStream(hundred), 100);
		T.eq(100, ok.read(new byte[200], 0, 200), "exactly the cap reads");
		T.check(!ok.exceeded(), "not exceeded at the cap");
		VSphereClient.CappedInputStream over =
				new VSphereClient.CappedInputStream(
						new java.io.ByteArrayInputStream(hundred), 50);
		boolean threw = false;
		try {
			over.read(new byte[200], 0, 200);
		} catch (VSphereClient.ResponseTooLarge e) {
			threw = true;
		}
		T.check(threw && over.exceeded(), "over the cap throws and remembers");
		T.eq("abc", VSphereClient.readCapped(new java.io.ByteArrayInputStream(
				"abcdef".getBytes("UTF-8")), 3), "fault body bounded");
		org.w3c.dom.Document d = VSphereClient.parseXml(
				new java.io.ByteArrayInputStream("<a><b>1</b></a>"
						.getBytes("UTF-8")));
		T.eq("1", d.getDocumentElement().getTextContent(), "stream parse");

		StringBuilder big = new StringBuilder("<val>");
		for (int i = 0; i < 2000; i++) big.append("0123456789");
		big.append("</val>");
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> Build95CollectionTest.perObject(r,
					FakeVCenter.map("host-1|config.lockdownMode", big.toString(),
							"host-1|runtime.connectionState",
							"<val>connected</val>"), null);
			VSphereClient c = f.client();
			c.ensureConnected();
			c.setMaxResponseBytes(8 * 1024);
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			Map<String, Object> v = c.readVimProperties(h, java.util.Arrays
					.asList(Build95CollectionTest.vim("esx.lockdown",
							"HostSystem", "lockdown", "lockdownNormal",
							"scalar:config.lockdownMode")));
			T.check(v.get("lockdown") == VSphereClient.UNREADABLE,
					"oversized response: UNREADABLE, never a value");
			String why = c.lastReadReasons().get("lockdown");
			T.eq("response-too-large", UnreadableReasons.category(why),
					"reason category: " + why);
			T.eq("connected", c.getHostConnectionState(h),
					"the next call works on a fresh connection");
		}

		// Review N2: a 2xx whose body stops mid-transfer (a read timeout,
		// not the cap) keeps the transport error as the reason, as build 94
		// did, instead of "missing-element", and drops the connection; the
		// next call works on a fresh one.
		try (FakeVCenter f = new FakeVCenter()) {
			boolean[] cut = {false};
			Map<String, String> table = FakeVCenter.map(
					"host-1|config.service", "<val><service><key>TSM-SSH</key>"
					+ "<running>false</running></service></val>",
					"host-1|runtime.connectionState", "<val>connected</val>");
			f.handler = r -> {
				FakeVCenter.Resp resp = Build95CollectionTest.perObject(r,
						table, null);
				if (cut[0]) {
					cut[0] = false;
					return resp.stalled(1500);
				}
				return resp;
			};
			VSphereClient c = f.client();
			c.setReadTimeoutMs(300);
			c.ensureConnected();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			T.eq("connected", c.getHostConnectionState(h), "before");
			java.util.List<BenchmarkProfile.Control> ssh = java.util.Arrays
					.asList(Build95CollectionTest.vim("esx.ssh", "HostSystem",
							"ssh", "false", "service_state:TSM-SSH:running"));
			T.eq(Boolean.FALSE, c.readVimProperties(h, ssh).get("ssh"),
					"read normally");
			cut[0] = true;
			Map<String, Object> v = c.readVimProperties(h, ssh);
			T.check(v.get("ssh") == VSphereClient.UNREADABLE,
					"a body stalled mid-transfer: UNREADABLE, never a value");
			String why = c.lastReadReasons().get("ssh");
			T.check(why != null && why.startsWith("exception: ")
					&& why.contains("SocketTimeoutException"), "the reason "
					+ "names the transport error, not a missing element: "
					+ why);
			int portsBefore = ports(f).size();
			T.eq("connected", c.getHostConnectionState(h),
					"the next call works");
			T.eq(portsBefore + 1, ports(f).size(),
					"on a new connection (the broken one was dropped)");
		}
	}

	private static java.util.Set<Integer> ports(FakeVCenter f) {
		java.util.Set<Integer> out = new java.util.HashSet<>();
		synchronized (f.requests) {
			for (FakeVCenter.Req r : f.requests) out.add(r.clientPort);
		}
		return out;
	}

	/** #23 (leak part, review W4) and #28 (dead vcApi). */
	static void releaseOnReconfigure() throws Exception {
		String ca = OverridesTest.readSrc(CA);
		String code = OverridesTest.stripComments(ca);
		T.check(!code.contains("vcApi"), "no vcApi field or use (#28)");
		// Configure needs the SDK, so its order is pinned from source:
		// build, swap, then release (no null window, review W4).
		String configure = OverridesTest.body(ca,
				"protected void configureAdapter(");
		OverridesTest.inOrder(configure, "configureAdapter",
				"VSphereClient oldVsphere = this.vsphere;",
				"SuiteApiStitcher oldSuite = this.suiteStitcher;",
				"VSphereClient newVsphere = new VSphereClient(",
				"newSuite = SuiteApiStitcher.create(",
				"this.vsphere = newVsphere;",
				"this.suiteStitcher = newSuite;",
				"this.stitcher = newStitcher;",
				"releaseClients(oldVsphere, oldSuite);");
		T.eq(1, OverridesTest.count(configure, "releaseClients("),
				"released once per configure");
		String flat = code.replaceAll("\\s+", " ");
		for (String nul : new String[] {"vsphere = null;",
				"this.vsphere = null;", "stitcher = null;"}) {
			T.check(!flat.contains(" " + nul), "no client field is nulled: "
					+ nul);
		}
		OverridesTest.inOrder(OverridesTest.body(ca,
				"private void releaseClients("), "releaseClients",
				"oldVsphere.disconnect();", "oldSuite.discard();");
		T.check(OverridesTest.body(ca, "public void onDiscard()")
				.startsWith("releaseClients(vsphere, suiteStitcher);"),
				"discard releases too");

		// disconnect() logs the session out on vCenter and closes the
		// client: no later call logs in again.
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> Build95CollectionTest.perObject(r,
					FakeVCenter.map("host-1|runtime.connectionState",
							"<val>connected</val>"), null);
			VSphereClient c = f.client();
			c.ensureConnected();
			T.eq(1, f.validCookies.size(), "one live session");
			c.disconnect();
			T.eq(1, f.count("Logout"), "session logged out");
			T.eq(0, f.validCookies.size(), "no live session left");
			T.eq(1, f.count("Login"), "no re-login to log out");
			FakeVCenter.Req lo = f.of("Logout").get(0);
			T.check(lo.cookie != null && lo.cookie.contains("s1"),
					"the session's own cookie was logged out");
			T.check(c.isClosed(), "closed");
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem",
					"host-1");
			int calls = f.requests.size();
			boolean threw = false;
			try {
				c.getHostConnectionState(h);
			} catch (VimOptions.ReadFault e) {
				threw = e.getMessage().equals(VSphereClient.CLOSED);
			}
			T.check(threw, "a read on a closed client fails");
			threw = false;
			try {
				c.ensureConnected();
			} catch (VimOptions.ReadFault e) {
				threw = true;
			}
			T.check(threw, "a closed client does not connect again");
			T.eq(calls, f.requests.size(), "nothing sent after close");
			c.disconnect();   // idempotent
			T.eq(1, f.count("Logout"), "a second release sends nothing");
		}

		// A cycle still running on the old client when configure releases
		// it: the call in flight comes back NotAuthenticated (its session
		// was just logged out) and fails; no new session is opened.
		try (FakeVCenter f = new FakeVCenter()) {
			VSphereClient[] holder = new VSphereClient[1];
			f.handler = r -> {
				Thread t = new Thread(() -> holder[0].disconnect());
				t.start();   // configure's release, on another thread
				try {
					t.join(10000);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				return FakeVCenter.fault("NotAuthenticated",
						"The session is not authenticated.");
			};
			VSphereClient c = f.client();
			holder[0] = c;
			c.ensureConnected();
			c.beginCycle();
			T.eq(null, c.getHostConnectionState(new VSphereClient.MoRef(
					"HostSystem", "host-1")), "the in-flight read fails");
			T.eq(1, f.count("Login"), "no re-login on the released client");
			T.eq(1, f.count("Logout"), "the old session was logged out");
			T.eq(0, f.validCookies.size(), "no session left behind");
		}

		// The Logout wait is bounded: an unreachable or stuck old vCenter
		// holds configure for at most the bound, not 30 s + 120 s.
		T.eq(5000, VSphereClient.LOGOUT_TIMEOUT_MS, "Logout bound 5 s");
		try (FakeVCenter f = new FakeVCenter()) {
			VSphereClient c = f.client();
			c.ensureConnected();
			c.setLogoutTimeoutMs(300);
			f.logoutDelayMs = 5000;
			long t0 = System.nanoTime();
			c.disconnect();
			long ms = (System.nanoTime() - t0) / 1_000_000L;
			T.check(ms < 2500, "disconnect returned after " + ms + " ms with "
					+ "a 300 ms bound and a 5 s Logout");
			T.check(c.isClosed(), "closed even though Logout timed out");
		}
	}

	/** #25. */
	static void basicAuthUtf8() throws Exception {
		String h = ComplianceDecisions.basicAuthorization(
				"svc-compliance@vsphere.local", "p\u00e4ss\u20acw\u00f6rd");
		T.check(h.startsWith("Basic "), "Basic scheme");
		byte[] got = java.util.Base64.getDecoder().decode(h.substring(6));
		T.check(java.util.Arrays.equals(
				("svc-compliance@vsphere.local:p\u00e4ss\u20acw\u00f6rd")
						.getBytes(java.nio.charset.StandardCharsets.UTF_8), got),
				"credential bytes are UTF-8");
		T.eq("Basic dXNlcjpwYXNz",
				ComplianceDecisions.basicAuthorization("user", "pass"),
				"ASCII unchanged");
		for (String f : new String[] {
				"src/com/vcfcf/adapters/compliance/VamiApiClient.java",
				"src/com/vcfcf/adapters/compliance/VCenterApiClient.java"}) {
			String code = OverridesTest.stripComments(OverridesTest.readSrc(f));
			T.check(!code.contains(".getBytes()"), f + ": no platform charset");
			T.check(code.contains("ComplianceDecisions.basicAuthorization("),
					f + ": uses the UTF-8 helper");
		}
	}
}
