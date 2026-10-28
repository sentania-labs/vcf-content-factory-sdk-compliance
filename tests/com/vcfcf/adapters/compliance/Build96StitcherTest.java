package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Build 96, issue #52 (and DEF-023's open test): the VCF Ops resource list
 * read (ComplianceStitcher.fetchResources) run through the real loop
 * against a fake Suite API, and the decision table behind it.
 *
 * <ul>
 *   <li>A failed read (HTTP error, timeout, interrupt, unparseable body,
 *       an empty page short of pageInfo.totalCount) holds the kind back;
 *       an interrupt keeps the thread's interrupt flag.</li>
 *   <li>A list over one page (11 pages of up to 10,000) is read whole.</li>
 *   <li>An empty but valid list for a kind whose last complete list had
 *       objects is held back once (EMPTY_UNCONFIRMED: Rollup|incomplete =
 *       1, the kind's keys keep their values); empty two cycles in a row
 *       is accepted as genuinely empty.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build96StitcherTest {

	private static final String P = ComplianceRollup.PREFIX;
	private static final String KIND = "ClusterComputeResource";

	public static void main(String[] args) throws Exception {
		table();
		failedReads();
		elevenPages();
		emptyListRule();
		adapterHoldsBackUnconfirmedEmpty();
		System.out.println("Build96StitcherTest: all assertions passed");
	}

	static void table() {
		ComplianceDecisions.ResourcePage C =
				ComplianceDecisions.ResourcePage.COMPLETE;
		ComplianceDecisions.ResourcePage N =
				ComplianceDecisions.ResourcePage.NEXT_PAGE;
		ComplianceDecisions.ResourcePage I =
				ComplianceDecisions.ResourcePage.INCOMPLETE;
		ComplianceDecisions.ResourcePage E =
				ComplianceDecisions.ResourcePage.EMPTY_UNCONFIRMED;
		Object[][] rows = {
			// hasList, total, collected, rowsThisPage, page, prev, heldEmpty, want
			{true, 0L, 0, 0, 0, 0, false, C},     // empty, no history: accepted
			{true, 0L, 0, 0, 0, 3, false, E},     // empty after 3: held back once
			{true, 0L, 0, 0, 0, 3, true, C},      // empty again: accepted
			{false, 0L, 0, 0, 0, 3, false, E},    // no list, total 0, after 3: held
			{false, 0L, 0, 0, 0, 3, true, C},     // ... and accepted the next cycle
			{true, null, 0, 0, 0, 3, false, E},   // empty unpaged list after 3: held
			{true, 3L, 3, 3, 0, 3, false, C},     // the normal case
			{true, 3L, 3, 3, 0, 0, true, C},      // a non-empty list ignores the mark
			{true, 5L, 0, 0, 0, 3, false, I},     // empty page short of its total
			{true, 5L, 0, 0, 0, 0, false, I},     // same, no history
			{false, null, 0, 0, 0, 3, false, I},  // no list, no total
			{true, 20000L, 10000, 10000, 0, 3, false, N},
			{true, 20000L, 10000, 0, 1, 3, false, I},
		};
		for (Object[] r : rows) {
			T.eq(r[7], ComplianceDecisions.resourcePageOutcome((Boolean) r[0],
					(Long) r[1], (Integer) r[2], (Integer) r[3],
					(Integer) r[4], (Integer) r[5], (Boolean) r[6]),
					"outcome " + java.util.Arrays.toString(r));
		}
	}

	static String rows(int from, int n) {
		List<String> out = new ArrayList<>();
		for (int i = from; i < from + n; i++) {
			out.add(FakeSuiteApi.row("r-c" + i, "cl" + i, "domain-c" + i,
					"uuid-1"));
		}
		return String.join(",", out);
	}

	static String page(long total, int from, int n) {
		return "{\"pageInfo\":{\"totalCount\":" + total + "},"
				+ "\"resourceList\":[" + rows(from, n) + "]}";
	}

	static ComplianceStitcher stitcher(FakeSuiteApi s) {
		ComplianceStitcher st = new ComplianceStitcher(s, null);
		st.setOwningVcUuid("uuid-1");
		return st;
	}

	static void failedReads() {
		Object[][] cases = {
			{"HTTP error", new java.io.IOException("HTTP 500 Internal Server Error")},
			{"timeout", new java.net.SocketTimeoutException("Read timed out")},
			{"interrupt", new InterruptedException("stop")},
		};
		for (Object[] c : cases) {
			FakeSuiteApi s = new FakeSuiteApi();
			final Exception thrown = (Exception) c[1];
			s.answer = p -> {
				if (thrown instanceof InterruptedException) {
					throw (InterruptedException) thrown;
				}
				throw (java.io.IOException) thrown;
			};
			ComplianceStitcher st = stitcher(s);
			st.loadClusterResources();
			T.check(st.loadFailed(KIND), c[0] + ": kind held back");
			T.eq(0, st.countOfKind(KIND), c[0] + ": nothing indexed");
			boolean interrupted = Thread.interrupted();   // clears it
			T.eq(thrown instanceof InterruptedException, interrupted,
					c[0] + ": interrupt flag kept only for an interrupt");
		}

		FakeSuiteApi s = new FakeSuiteApi();
		s.answer = p -> "<html>not json</html>";
		ComplianceStitcher st = stitcher(s);
		st.loadClusterResources();
		T.check(st.loadFailed(KIND), "unparseable body: held back");

		s.answer = p -> "{\"pageInfo\":{\"totalCount\":5},\"resourceList\":[]}";
		st = stitcher(s);
		int before = s.gets.size();
		st.loadClusterResources();
		T.check(st.loadFailed(KIND),
				"empty page with totalCount > 0: held back");
		T.eq(1, s.gets.size() - before, "one read, no retry loop");
	}

	static void elevenPages() {
		FakeSuiteApi s = new FakeSuiteApi();
		final long total = 105000;
		s.answer = p -> {
			int page = Integer.parseInt(p.substring(p.indexOf("&page=") + 6));
			int from = page * ComplianceDecisions.RESOURCE_PAGE_SIZE;
			int n = (int) Math.min(ComplianceDecisions.RESOURCE_PAGE_SIZE,
					total - from);
			return page(total, from, Math.max(0, n));
		};
		ComplianceStitcher st = stitcher(s);
		st.loadClusterResources();
		T.check(!st.loadFailed(KIND), "11 pages: complete");
		T.eq(11, s.gets.size(), "11 page reads");
		T.eq(105000, st.countOfKind(KIND), "every row indexed");
		T.check(s.gets.get(10).endsWith("&page=10"), "last page is page 10");
		T.eq("r-c104999", st.matchCluster("cl104999", "domain-c104999").resourceId,
				"a row on the last page matches");
	}

	static void emptyListRule() {
		FakeSuiteApi s = new FakeSuiteApi();
		final String[] body = {page(3, 0, 3)};
		s.answer = p -> body[0];
		ComplianceStitcher st = stitcher(s);
		String empty = "{\"pageInfo\":{\"totalCount\":0},\"resourceList\":[]}";

		st.loadClusterResources();
		T.check(!st.loadFailed(KIND), "cycle 1: 3 clusters, complete");
		body[0] = empty;
		st.loadClusterResources();
		T.check(st.loadFailed(KIND),
				"cycle 2: empty after 3, held back (not read as zero)");
		st.loadClusterResources();
		T.check(!st.loadFailed(KIND),
				"cycle 3: empty again, accepted as genuinely empty");
		T.eq(0, st.countOfKind(KIND), "cycle 3: no clusters");
		st.loadClusterResources();
		T.check(!st.loadFailed(KIND), "cycle 4: still empty, accepted");

		// A blip: empty once between full lists is held, and the full list
		// after it clears the mark, so a later empty is held again.
		body[0] = page(3, 0, 3);
		st.loadClusterResources();
		body[0] = empty;
		st.loadClusterResources();
		T.check(st.loadFailed(KIND), "blip held back");
		body[0] = page(3, 0, 3);
		st.loadClusterResources();
		T.check(!st.loadFailed(KIND), "full list after the blip");
		body[0] = empty;
		st.loadClusterResources();
		T.check(st.loadFailed(KIND), "a later empty is held back again");

		// A failed read in between does not confirm an empty list.
		body[0] = page(3, 0, 3);
		st.loadClusterResources();
		body[0] = empty;
		st.loadClusterResources();
		T.check(st.loadFailed(KIND), "empty, held");
		body[0] = "not json";
		st.loadClusterResources();
		T.check(st.loadFailed(KIND), "failed read");
		body[0] = empty;
		st.loadClusterResources();
		T.check(st.loadFailed(KIND),
				"empty after a failed read is unconfirmed again");

		// No history (a new configuration): the first empty list stands.
		ComplianceStitcher fresh = stitcher(s);
		fresh.loadClusterResources();
		T.check(!fresh.loadFailed(KIND), "first read empty: accepted");
	}

	/**
	 * Through the adapter: the VCF Ops HostSystem list comes back empty
	 * (200, totalCount 0) after a cycle that listed both hosts. The Host
	 * kind is held back with Rollup|incomplete = 1 instead of both hosts
	 * counting as unmatched; the cycle after, still empty, accepts it.
	 */
	static void adapterHoldsBackUnconfirmedEmpty() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 1 complete");
			T.eq(2.0, h.lastRollup().get(P + "Host|scored"), "cycle 1 hosts");

			h.suite.bodies.put("resourceKind=HostSystem&",
					FakeSuiteApi.page(0));
			h.cycle();
			Map<String, Double> r2 = h.lastRollup();
			T.eq(1.0, r2.get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 2: empty list held back, incomplete = 1");
			T.check(!r2.containsKey(P + "Host|scored")
					&& !r2.containsKey(P + "Host|unmatched"),
					"cycle 2: Host keys held back, not 0 / 2 unmatched");
			T.check(!r2.containsKey(P + "All|scored"), "cycle 2: All held back");

			h.cycle();
			Map<String, Double> r3 = h.lastRollup();
			T.eq(0.0, r3.get(ComplianceRollup.INCOMPLETE_KEY),
					"cycle 3: empty again, accepted");
			T.eq(2.0, r3.get(P + "Host|unmatched"),
					"cycle 3: both hosts now unmatched");
		}
	}
}
