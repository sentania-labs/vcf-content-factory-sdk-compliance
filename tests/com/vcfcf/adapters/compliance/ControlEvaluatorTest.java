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
		// A bare vmx-N is plain equality. No bundled profile carries one
		// since build 97 (all are vmx-N or newer / or higher), but an
		// override can still set one.
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
		// Build 95 (point 7): nothing read, so no score; the value is the
		// zero-divisor placeholder, never pushed (build 63 said 0).
		T.near(100, r.score, "only control unreadable: placeholder");
		T.check(ComplianceDecisions.nothingReadable(r), "nothing read");
		T.check(!ComplianceDecisions.complianceStats(r).containsKey(
				"VCF-CF Compliance|score"), "and no score pushed");
		T.check(r.controlResults.get(0).unreadable, "result marked unreadable");
		T.check(!r.controlResults.get(0).compliant, "unreadable not compliant");

		vals.put("config.version", "vmx-19");
		r = ControlEvaluator.evaluateVimProperties(Arrays.asList(vh), vals,
				"vm1", unreadable);
		T.eq(1, r.passCount, "vmx-19 passes the 17 floor");

		// Build 95 (point 7): one pass + one unreadable -> 100 over what was
		// read (build 63 said 50: unreadable counted as failing);
		// fail_count stays 0 and unreadable_count 1.
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
		T.near(100, m.score, "an unreadable control no longer lowers it");
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

		absentAdvancedSetting();
		patternParameter();

		System.out.println("ControlEvaluatorTest: all assertions passed");
	}

	private static BenchmarkProfile.Control advCtl(String id, String param,
			String expected) {
		return new BenchmarkProfile.Control(id, "P0", "VirtualMachine",
				"VMWARE", param, "advanced_setting", "string", expected, "t",
				"d", "SCG-9.0:x", "fix", "");
	}

	/**
	 * Build 90 (DEF-022): on a successful read, an advanced setting absent
	 * on the object is a FAIL with Actual "(undefined)" unless the expected
	 * value allows absence. It used to be skipped (out of pass, fail and
	 * total), which raised the object's score.
	 */
	private static void absentAdvancedSetting() {
		BenchmarkProfile.Control lock = advCtl("vm.vmrc-lock",
				"tools.guest.desktop.autolock", "TRUE");
		BenchmarkProfile.Control copy = advCtl("vm.deactivate-console-copy",
				"isolation.tools.copy.disable", "TRUE or Undefined");
		BenchmarkProfile.Control notPresent = advCtl("vm.x-not-present",
				"x.not.present", "Not Present");
		BenchmarkProfile.Control orNotPresent = advCtl("vm.x-or-np",
				"x.or.np", "FALSE or Not Present");
		BenchmarkProfile.Control nonEmpty = advCtl("vm.x-nonempty",
				"x.nonempty", "(non-empty)");
		BenchmarkProfile.Control notEq = advCtl("vm.x-noteq", "x.noteq",
				"not:/tmp/scratch");
		java.util.List<BenchmarkProfile.Control> all = Arrays.asList(lock,
				copy, notPresent, orNotPresent, nonEmpty, notEq);

		// Every key absent: the read succeeded and nothing is set.
		ControlEvaluator.ComplianceResult r = ControlEvaluator
				.evaluateControls(all, new HashMap<>(), "vm1");
		T.eq(6, r.controlResults.size(), "every control has a result, none skipped");
		T.eq(3, r.passCount, "absence passes only where expected allows it");
		T.eq(3, r.failCount, "value-required controls fail when unset");
		T.eq(6, r.totalCount, "failing controls stay in the denominator");
		T.eq(0, r.unreadableCount, "absent is not unreadable");
		T.near(50, r.score, "score 3/6, not 3/3");
		Map<String, ControlEvaluator.ControlResult> by = new HashMap<>();
		for (ControlEvaluator.ControlResult c : r.controlResults) {
			by.put(c.scgId, c);
		}
		T.check(!by.get("vm.vmrc-lock").compliant, "plain TRUE, unset: fail");
		T.eq("(undefined)", by.get("vm.vmrc-lock").actual,
				"Actual (undefined) on the fail");
		T.check(!by.get("vm.vmrc-lock").unreadable, "a fail, not unreadable");
		T.check(by.get("vm.deactivate-console-copy").compliant,
				"X or Undefined, unset: pass");
		T.check(by.get("vm.x-not-present").compliant, "Not Present, unset: pass");
		T.check(by.get("vm.x-or-np").compliant, "X or Not Present, unset: pass");
		T.check(!by.get("vm.x-nonempty").compliant, "(non-empty), unset: fail");
		T.check(!by.get("vm.x-noteq").compliant,
				"not:X, unset: fail (absence is never 'not equal')");

		// Present-but-empty is the same as unset, except against an
		// expected value that is itself explicitly empty.
		Map<String, String> empty = new HashMap<>();
		empty.put("tools.guest.desktop.autolock", "");
		r = ControlEvaluator.evaluateControls(Arrays.asList(lock), empty, "vm1");
		T.eq(1, r.failCount, "empty value against TRUE: fail");
		BenchmarkProfile.Control dvf = new BenchmarkProfile.Control(
				"esx.network-dvfilter", "P0", "HostSystem", "VMWARE",
				"Net.DVFilterBindIpAddress", "advanced_setting", "string",
				"\"\"", "t", "d", "SCG-9.0:x", "fix", "");
		BenchmarkProfile.Control dvf67 = new BenchmarkProfile.Control(
				"esx.network-dvfilter-67", "P0", "HostSystem", "VMWARE",
				"Net.DVFilterBindIpAddress", "advanced_setting", "string",
				"NULL", "t", "d", "SCG-6.7:x", "fix", "");
		Map<String, String> host = new HashMap<>();
		host.put("Net.DVFilterBindIpAddress", "");
		r = ControlEvaluator.evaluateControls(Arrays.asList(dvf, dvf67), host,
				"h1");
		T.eq(2, r.passCount, "present and empty against \"\" / NULL: pass");
		host.put("Net.DVFilterBindIpAddress", "10.0.0.1");
		r = ControlEvaluator.evaluateControls(Arrays.asList(dvf), host, "h1");
		T.eq(1, r.failCount, "a bound address against \"\": fail");
		r = ControlEvaluator.evaluateControls(Arrays.asList(dvf),
				new HashMap<>(), "h1");
		T.eq(1, r.failCount, "absent against \"\": fail (undefined)");

		// A present value still compares as before.
		Map<String, String> set = new HashMap<>();
		set.put("tools.guest.desktop.autolock", "TRUE");
		set.put("isolation.tools.copy.disable", "FALSE");
		r = ControlEvaluator.evaluateControls(Arrays.asList(lock, copy), set,
				"vm1");
		T.eq(1, r.passCount, "TRUE set: pass");
		T.eq(1, r.failCount, "FALSE set against TRUE or Undefined: fail");
	}

	/**
	 * Build 90 (W3): a parameter containing "*" is matched as a key
	 * pattern. vm.dvfilter ("ethernet*.filter*.name", Not Present) used to
	 * look the pattern up as a literal key and always passed.
	 */
	private static void patternParameter() {
		BenchmarkProfile.Control dvf = advCtl("vm.dvfilter",
				"ethernet*.filter*.name", "Not Present");
		java.util.List<BenchmarkProfile.Control> one = Arrays.asList(dvf);

		// No filter keys: pass, Actual (undefined).
		Map<String, String> vm = new HashMap<>();
		vm.put("ethernet0.virtualDev", "vmxnet3");
		vm.put("ethernet0.present", "TRUE");
		ControlEvaluator.ComplianceResult r = ControlEvaluator
				.evaluateControls(one, vm, "vm1");
		T.eq(1, r.passCount, "no filter keys: pass");
		T.eq(1, r.totalCount, "no filter keys: counted");
		T.eq("(undefined)", r.controlResults.get(0).actual,
				"no filter keys: Actual (undefined)");

		// One filter key: fail, with the key named in Actual.
		vm.put("ethernet0.filter0.name", "dvfilter-generic-vmware");
		r = ControlEvaluator.evaluateControls(one, vm, "vm1");
		T.eq(1, r.failCount, "one filter key: fail");
		T.eq(0, r.passCount, "one filter key: no pass");
		T.check(!r.controlResults.get(0).compliant, "one filter key: not compliant");
		T.eq("ethernet0.filter0.name=dvfilter-generic-vmware",
				r.controlResults.get(0).actual, "Actual names the matched key");

		// Several, case-insensitive, sorted, listed together.
		vm.put("Ethernet1.Filter2.name", "nsx-dvfilter");
		r = ControlEvaluator.evaluateControls(one, vm, "vm1");
		T.eq(1, r.failCount, "two filter keys: one fail");
		T.eq("Ethernet1.Filter2.name=nsx-dvfilter; "
				+ "ethernet0.filter0.name=dvfilter-generic-vmware",
				r.controlResults.get(0).actual, "Actual lists every match");

		// A matching key with an empty value is unset, like a literal key.
		Map<String, String> blank = new HashMap<>();
		blank.put("ethernet0.filter0.name", "");
		r = ControlEvaluator.evaluateControls(one, blank, "vm1");
		T.eq(1, r.passCount, "empty filter name: unset, pass");

		// A non-matching key does not count.
		Map<String, String> near = new HashMap<>();
		near.put("ethernet0.filter0.name.extra", "x");
		near.put("ethernet0.filter.name", "x");
		r = ControlEvaluator.evaluateControls(one, near, "vm1");
		T.eq(1, r.passCount, "keys outside the pattern: pass");

		// A failed read stays unreadable: never a pass.
		r = ControlEvaluator.evaluateControlsUnreadable(one, "vm1");
		T.eq(1, r.unreadableCount, "read failure: unreadable");
		T.eq(0, r.passCount, "read failure: no pass");
		T.check(r.controlResults.get(0).unreadable, "read failure: marked unreadable");
		T.check(!r.controlResults.get(0).compliant, "read failure: not compliant");

		T.check(ControlEvaluator.keyPattern("ethernet*.filter*.name")
				.matcher("ethernet12.filter3.name").matches(), "pattern multi-digit");
	}
}
