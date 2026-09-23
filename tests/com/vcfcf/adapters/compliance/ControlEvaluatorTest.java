package com.vcfcf.adapters.compliance;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Evaluator changes in build 57: the vmx minimum-version mode and the
 * explicit unreadable marker on ControlResult.
 */
public final class ControlEvaluatorTest {

	public static void main(String[] args) {
		// vmx minimum mode.
		T.check(ControlEvaluator.isVmxMinimumMode("vmx-17 or higher"), "higher");
		T.check(ControlEvaluator.isVmxMinimumMode("vmx-13 or newer"), "newer");
		T.check(!ControlEvaluator.isVmxMinimumMode("vmx-21"), "bare is exact");
		T.check(ControlEvaluator.vimPropertyMatches("vmx-21",
				"vmx-17 or higher"), "21 >= 17");
		T.check(ControlEvaluator.vimPropertyMatches("vmx-17",
				"vmx-17 or higher"), "17 >= 17");
		T.check(!ControlEvaluator.vimPropertyMatches("vmx-15",
				"vmx-17 or higher"), "15 < 17");
		T.check(!ControlEvaluator.vimPropertyMatches("vmx-9",
				"vmx-13 or newer"), "9 < 13 (numeric, not string, compare)");
		T.check(ControlEvaluator.vimPropertyMatches("vmx-100",
				"vmx-13 or newer"), "100 >= 13 (numeric compare)");
		T.check(!ControlEvaluator.vimPropertyMatches("garbage",
				"vmx-17 or higher"), "unparseable actual fails");
		// Bare vmx-N keeps exact equality (8.0 / 9.0 semantics unchanged).
		T.check(ControlEvaluator.vimPropertyMatches("vmx-21", "vmx-21"),
				"exact equal");
		T.check(!ControlEvaluator.vimPropertyMatches("vmx-22", "vmx-21"),
				"exact unequal");

		// Unreadable vim control: marked unreadable, never compliant,
		// excluded from pass/fail/total.
		BenchmarkProfile.Control vh = new BenchmarkProfile.Control(
				"vm.virtual-hardware", "P0", "VirtualMachine", "VMWARE",
				"config.version", "vim_property", "string", "vmx-17 or higher",
				"t", "d", "SCG-9.1:x", "fix", "scalar:config.version");
		Object unreadable = new Object();
		Map<String, Object> vals = new HashMap<>();
		vals.put("config.version", unreadable);
		ControlEvaluator.ComplianceResult r =
				ControlEvaluator.evaluateVimProperties(Arrays.asList(vh), vals,
						"vm1", unreadable);
		T.eq(0, r.totalCount, "unreadable not in total");
		T.eq(1, r.unreadableCount, "unreadable counted");
		T.near(0, r.score, "build 63: only control unreadable -> score 0");
		T.check(r.controlResults.get(0).unreadable, "result marked unreadable");
		T.check(!r.controlResults.get(0).compliant, "unreadable not compliant");

		vals.put("config.version", "vmx-19");
		r = ControlEvaluator.evaluateVimProperties(Arrays.asList(vh), vals,
				"vm1", unreadable);
		T.eq(1, r.passCount, "vmx-19 passes the 17 floor");

		// Build 63: one pass + one unreadable -> 50 (unreadable counts as
		// failing), while fail_count stays 0 and unreadable_count 1.
		BenchmarkProfile.Control secure = new BenchmarkProfile.Control(
				"vm.secure-boot", "P0", "VirtualMachine", "VMWARE",
				"config.bootOptions.efiSecureBootEnabled", "vim_property",
				"boolean", "true", "t", "d", "SCG-9.1:x", "fix",
				"bool:config.bootOptions.efiSecureBootEnabled");
		Map<String, Object> mixed = new HashMap<>();
		mixed.put("config.version", "vmx-19");
		mixed.put("config.bootOptions.efiSecureBootEnabled", unreadable);
		ControlEvaluator.ComplianceResult m =
				ControlEvaluator.evaluateVimProperties(Arrays.asList(vh, secure),
						mixed, "vm1", unreadable);
		T.near(50, m.score, "partial unreadable lowers the score");
		T.eq(0, m.failCount, "fail_count unchanged by unreadable");
		T.eq(1, m.unreadableCount, "unreadable counted separately");
		T.eq(2, m.attempted(), "attempted = pass + fail + unreadable");
		T.check(!r.controlResults.get(0).unreadable, "read result not unreadable");

		// Advanced-setting unreadable fold marks every result unreadable.
		BenchmarkProfile.Control adv = new BenchmarkProfile.Control(
				"esx.x", "P0", "HostSystem", "VMWARE", "Security.X",
				"advanced_setting", "integer", "5", "t", "d", "SCG-9.1:x",
				"fix", "");
		ControlEvaluator.ComplianceResult u =
				ControlEvaluator.evaluateControlsUnreadable(Arrays.asList(adv),
						"h1");
		T.check(u.controlResults.get(0).unreadable, "adv unreadable marked");
		T.eq(0, u.totalCount, "adv unreadable not scored");

		// A compliant flag can never survive an unreadable marker.
		ControlEvaluator.ControlResult forced = new ControlEvaluator.ControlResult(
				"x", "(unreadable)", "1", true, "d", true);
		T.check(!forced.compliant, "unreadable overrides compliant=true");

		System.out.println("ControlEvaluatorTest: all assertions passed");
	}
}
