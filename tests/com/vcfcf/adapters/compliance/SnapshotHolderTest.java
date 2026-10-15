package com.vcfcf.adapters.compliance;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Build 95 review W12: one {@link Configured} holder per configuration.
 * The adapter publishes a new holder on every configure and each cycle
 * works only through the holder it copied at its start
 * (tests/test_cycle_snapshot.py pins that shape in the SDK-bound
 * adapter). This runs the two leaks the review names through the real
 * holder, {@link ComplianceDecisions#markNotCollected} and
 * {@link ComplianceDecisions#decide}: a cycle that spans an instance edit
 * from vCenter A to vCenter B refills A's holder, and the first cycle on
 * B must inherit nothing from it. Run from the repo root.
 */
public final class SnapshotHolderTest {

	private static final BenchmarkSelector.Kind VCENTER =
			BenchmarkSelector.Kind.VCENTER;
	private static final String VC_KEY =
			LastBenchmarkMemory.key(VCENTER, "vcenter");

	public static void main(String[] args) throws Exception {
		immutable();
		incompleteNeverOnTheOldVCenter();
		newVCenterNeverOnTheOldBenchmark();
		customBucketPerConfiguration();
		System.out.println("SnapshotHolderTest: all assertions passed");
	}

	private static Configured<Object, Object> holder(String host,
			boolean custom) {
		return new Configured<>(new ComplianceConfig(host, "svc", "pw",
				null, null), null, new BenchmarkLoader(), null, null, custom);
	}

	/** Every field is final: a holder is published once, never patched. */
	static void immutable() {
		for (Field f : Configured.class.getDeclaredFields()) {
			T.check(Modifier.isFinal(f.getModifiers()),
					"Configured." + f.getName() + " is final");
		}
	}

	/**
	 * Scenario 1. The old cycle, still on A after the edit, resolves A's
	 * vCenter object and remembers it (in A's holder). The first cycle on
	 * B cannot reach B: Rollup|incomplete goes to B's object (resolved by
	 * host) or nowhere, never to A's.
	 */
	static void incompleteNeverOnTheOldVCenter() {
		Configured<Object, Object> configured = holder("vc-a.example.org",
				false);
		Configured<Object, Object> oldCycle = configured;   // cycle start
		configured = holder("vc-b.example.org", false);      // edit
		oldCycle.rememberVcResourceId("res-vc-a");           // old cycle ends
		T.eq("res-vc-a", oldCycle.lastVcResourceId(),
				"the old cycle wrote its own holder");

		Configured<Object, Object> next = configured;        // next cycle
		T.eq("vc-b.example.org", next.account.vcenterHost, "next is on B");
		T.eq(null, next.lastVcResourceId(), "B starts with no vCenter id");

		List<String> pushedTo = new ArrayList<>();
		String id = ComplianceDecisions.markNotCollected(
				next.lastVcResourceId(), () -> null,
				(rid, stats) -> pushedTo.add(rid));
		T.eq(null, id, "B unresolved: nothing pushed");
		T.eq(0, pushedTo.size(), "nothing pushed to A's object");

		id = ComplianceDecisions.markNotCollected(next.lastVcResourceId(),
				() -> "res-vc-b", (rid, stats) -> pushedTo.add(rid));
		T.eq("res-vc-b", id, "B resolved by host: pushed to B");
		T.eq(List.of("res-vc-b"), pushedTo, "only B's object");
	}

	/**
	 * Scenario 2. The old cycle records A's vCenter benchmark (key
	 * VCENTER|vcenter, the same for every vCenter) in A's holder. On B
	 * the version read fails: B has no previous benchmark, so the outcome
	 * is version unreadable (flagged), not a score against A's SCG.
	 */
	static void newVCenterNeverOnTheOldBenchmark() {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkSelector auto = BenchmarkSelector.auto(all);
		Configured<Object, Object> configured = holder("vc-a.example.org",
				false);
		Configured<Object, Object> oldCycle = configured;   // cycle start
		configured = holder("vc-b.example.org", false);      // edit
		ComplianceDecisions.Decision a = ComplianceDecisions.decide(auto,
				VCENTER, "9.0.0", oldCycle.memory.previous(VC_KEY), all);
		T.eq(ComplianceDecisions.Outcome.SCORE, a.outcome, "A scored");
		oldCycle.memory.record(VC_KEY, a.profileName);       // afterPush on A

		// The control: had B inherited that entry, it would be scored
		// against A's benchmark. This is the leak the holder prevents.
		ComplianceDecisions.Decision leaked = ComplianceDecisions.decide(
				auto, VCENTER, null, oldCycle.memory.previous(VC_KEY), all);
		T.check(leaked.outcome == ComplianceDecisions.Outcome.SCORE
				&& leaked.reusedPrevious, "A's memory would score B");

		Configured<Object, Object> next = configured;        // next cycle
		T.eq(null, next.memory.previous(VC_KEY), "B has no benchmark");
		ComplianceDecisions.Decision b = ComplianceDecisions.decide(auto,
				VCENTER, null, next.memory.previous(VC_KEY), all);
		T.eq(ComplianceDecisions.Outcome.VERSION_UNREADABLE, b.outcome,
				"B with an unreadable version is flagged, not scored");
		T.check(!b.reusedPrevious, "B reuses nothing");
	}

	/**
	 * The retired Custom bucket is zeroed once per configuration: an old
	 * cycle clearing its flag does not cancel the new configuration's.
	 */
	static void customBucketPerConfiguration() {
		Configured<Object, Object> configured = holder("vc-a.example.org",
				true);
		Configured<Object, Object> oldCycle = configured;
		configured = holder("vc-a.example.org", true);       // edit
		oldCycle.customBucketZeroed();                       // old cycle
		T.check(!oldCycle.zeroCustomBucketPending(), "old one zeroed");
		T.check(configured.zeroCustomBucketPending(),
				"the new configuration still zeroes once");
		T.check(!holder("vc-a.example.org", false).zeroCustomBucketPending(),
				"not stored as Custom: nothing to zero");
	}
}
