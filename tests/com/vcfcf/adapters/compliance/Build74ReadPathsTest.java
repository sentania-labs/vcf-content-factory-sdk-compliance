package com.vcfcf.adapters.compliance;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;

/**
 * Build 74 read-path fixes (api-explorer write-ups
 * compliance_config_encryption_and_vsan_checksum_reads.md and
 * compliance_vami_appliance_api_read_path.md). Run from the repo root.
 */
public final class Build74ReadPathsTest {

	public static void main(String[] args) throws Exception {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");

		// ---- A: host encryption reads the esxcli channel in every profile
		String[][] enc = {
				{"esx.tpm-configuration", "Mode"},
				{"esx.secureboot-enforcement", "RequireSecureBoot"},
				{"esx.tpm-trusted-binaries",
						"RequireExecutablesOnlyFromInstalledVIBs"}};
		int encRows = 0;
		for (BenchmarkProfile p : all.values()) {
			for (String[] e : enc) {
				BenchmarkProfile.Control c = ProfileSetTest.find(p.controls, e[0]);
				if (c == null) continue;
				encRows++;
				T.eq("esxcli", c.parameterKind, p.name + " " + e[0] + " kind");
				T.eq("esxcli:system.settings.encryption.get:" + e[1],
						c.readRecipe, p.name + " " + e[0] + " recipe");
				T.check(c.isEvaluable(), p.name + " " + e[0] + " scored");
				T.check(!c.readRecipe.contains("encryptionState"),
						"no config.encryptionState read left");
			}
		}
		T.eq(9, encRows, "rows: 7.0 1 + 8.0 2 + 9.0 3 + 9.1 3");
		// esxcli field names tolerate case (not yet confirmed on the wire).
		Map<String, String> struct = new LinkedHashMap<>();
		struct.put("mode", "TPM");
		struct.put("RequireSecureBoot", "true");
		T.eq("TPM", EsxcliSoapClient.fieldIgnoreCase(struct, "Mode"),
				"case-insensitive field match");
		T.eq("true", EsxcliSoapClient.fieldIgnoreCase(struct,
				"RequireSecureBoot"), "exact match");
		T.eq(null, EsxcliSoapClient.fieldIgnoreCase(struct,
				"RequireExecutablesOnlyFromInstalledVIBs"), "absent -> null");
		// The evaluator compares TPM case-insensitively.
		T.check(ControlEvaluator.vimPropertyMatches("TPM", "TPM"), "TPM pass");
		T.check(!ControlEvaluator.vimPropertyMatches("NONE", "TPM"),
				"NONE is an honest FAIL, not unreadable");

		// ---- B: cluster.object-checksum is manual review everywhere
		for (BenchmarkProfile p : all.values()) {
			BenchmarkProfile.Control c =
					ProfileSetTest.find(p.controls, "cluster.object-checksum");
			if (c == null) continue;
			T.check(!c.isEvaluable() && c.manualReview,
					p.name + " cluster.object-checksum manual review");
		}

		// ---- C: vSAN gate reads vsanConfigInfo/enabled
		T.check(VsanGate.vsanEnabled(xml("<configurationEx><vsanConfigInfo>"
				+ "<enabled>true</enabled><defaultConfig><autoClaimStorage>false"
				+ "</autoClaimStorage></defaultConfig></vsanConfigInfo>"
				+ "</configurationEx>")), "enabled=true -> vSAN");
		T.check(!VsanGate.vsanEnabled(xml("<configurationEx><vsanConfigInfo>"
				+ "<enabled>false</enabled><defaultConfig><autoClaimStorage>false"
				+ "</autoClaimStorage></defaultConfig></vsanConfigInfo>"
				+ "</configurationEx>")),
				"enabled=false (the 9.x non-vSAN shape) -> not vSAN");
		T.check(!VsanGate.vsanEnabled(xml("<configurationEx><vsanConfigInfo>"
				+ "<defaultConfig/></vsanConfigInfo></configurationEx>")),
				"no enabled element -> not vSAN");
		T.check(!VsanGate.vsanEnabled(xml("<configurationEx/>")),
				"no vsanConfigInfo -> not vSAN");
		T.check(VsanGate.vsanEnabled(xml("<v:configurationEx xmlns:v=\"urn:vim25\">"
				+ "<v:vsanConfigInfo><v:enabled>true</v:enabled></v:vsanConfigInfo>"
				+ "</v:configurationEx>")), "namespaced elements");

		// ---- D: VAMI grammar, value mapping, recipe fixes
		VamiRecipe r = VamiRecipe.parse("vami:access/ssh:(value)");
		T.eq("access/ssh", r.appliancePath, "path");
		T.eq(VamiRecipe.SELF_VALUE, r.field, "value-only token");
		VamiRecipe r2 = VamiRecipe.parse(
				"vami:local-accounts/root:max_days_between_password_change");
		T.eq("local-accounts/root", r2.appliancePath, "root account path");
		T.eq(null, VamiRecipe.parse("vami:nofield"), "malformed");
		T.eq(Boolean.FALSE, VamiRecipe.scalarValue("false"), "bare boolean body");
		T.eq("NIST_2024", VamiRecipe.scalarValue("NIST_2024"), "string");
		T.eq(null, VamiRecipe.scalarValue(null), "no value -> unreadable");
		T.eq("a,b", VamiRecipe.listValue(Arrays.asList("a", "b")), "list join");
		T.eq("", VamiRecipe.listValue(java.util.Collections.<String>emptyList()),
				"empty list is a definitive empty value");
		// Empty list under (non-empty) scores FAIL, not UNREADABLE.
		BenchmarkProfile.Control ntp = new BenchmarkProfile.Control("vc.time",
				"P1", "VCenterAdapterInstance", "VMWARE", "vami.ntp.servers",
				"vami_api", "string", "(non-empty)", "t", "d", "SCG-9.1:x",
				"fix", "vami:ntp:(list)");
		Map<String, Object> vals = new HashMap<>();
		vals.put("vami.ntp.servers", VamiRecipe.listValue(
				java.util.Collections.<String>emptyList()));
		ControlEvaluator.ComplianceResult cr = ControlEvaluator.evaluateVimProperties(
				Arrays.asList(ntp), vals, "vc", VSphereClientSentinel.U);
		T.eq(1, cr.failCount, "empty NTP list FAILS");
		T.eq(0, cr.unreadableCount, "empty NTP list is not unreadable");
		for (BenchmarkProfile p : all.values()) {
			for (String id : new String[] {"vc.ssh", "vc.vami-access-ssh"}) {
				BenchmarkProfile.Control c = ProfileSetTest.find(p.controls, id);
				if (c != null) T.eq("vami:access/ssh:(value)", c.readRecipe,
						p.name + " " + id);
			}
			for (String id : new String[] {"vc.vami-password-max-age",
					"vc.vami-administration-password-expiration"}) {
				BenchmarkProfile.Control c = ProfileSetTest.find(p.controls, id);
				if (c != null) T.eq(
						"vami:local-accounts/root:max_days_between_password_change",
						c.readRecipe, p.name + " " + id);
			}
			BenchmarkProfile.Control f =
					ProfileSetTest.find(p.controls, "vc.fips-enable");
			if (f != null) T.eq("vami:system/global-fips:enabled",
					f.readRecipe, p.name + " vc.fips-enable path");
			for (BenchmarkProfile.Control c : p.controls) {
				T.check(!c.readRecipe.contains("local-accounts/policy"),
						p.name + " no local-accounts/policy read left");
			}
		}
		T.eq("NIST_2024_TLS_13_ONLY", ProfileSetTest.find(
				all.get("VMware_SCG_9.1").controls, "vc.tls-ciphers").expectedValue,
				"9.1 vendor baseline");
		T.eq("NIST_2024", ProfileSetTest.find(
				all.get("VMware_SCG_9.0").controls, "vc.tls-ciphers").expectedValue,
				"9.0 baseline unchanged");

		// ---- HOLD: "Read vCenter appliance settings"
		// The default is an owner decision (pending); whichever it is, the
		// describe.xml default must match the Java constant used for
		// instances with no stored value.
		String describe = new String(java.nio.file.Files.readAllBytes(
				java.nio.file.Paths.get("describe.xml")), StandardCharsets.UTF_8);
		java.util.regex.Matcher dm = java.util.regex.Pattern.compile(
				"key=\"read_appliance_settings\"[^>]*?default=\"(true|false)\"",
				java.util.regex.Pattern.DOTALL).matcher(describe);
		T.check(dm.find(), "describe.xml declares read_appliance_settings");
		T.eq(String.valueOf(ComplianceConfig.DEFAULT_READ_APPLIANCE),
				dm.group(1), "describe.xml default == DEFAULT_READ_APPLIANCE");
		T.eq(ComplianceConfig.DEFAULT_READ_APPLIANCE,
				ComplianceConfig.parseReadAppliance(null),
				"absent (pre-74 instance) takes the default");
		T.check(ComplianceConfig.parseReadAppliance("TRUE"), "true");
		T.check(!ComplianceConfig.parseReadAppliance("false"), "false");
		BenchmarkLoader off = new BenchmarkLoader();
		off.setApplianceReads(false);
		BenchmarkProfile off91 = off.loadAll(".").get("VMware_SCG_9.1");
		int vami = 0;
		for (BenchmarkProfile.Control c : off91.controls) {
			if (ProfileSetTest.find(all.get("VMware_SCG_9.1").controls,
					c.controlId).parameterKind.equals("vami_api")) {
				vami++;
				T.check(!c.isEvaluable() && c.manualReview,
						"off: " + c.controlId + " manual review");
			}
		}
		T.eq(5, vami, "9.1 has five appliance controls");
		BenchmarkLoader on = new BenchmarkLoader();
		on.setApplianceReads(true);
		T.check(ProfileSetTest.find(on.loadAll(".").get("VMware_SCG_9.1").controls,
				"vc.ssh").isEvaluable(), "on: vc.ssh scored");
		// Off: stale Compliant values for appliance controls are cleanup
		// candidates (demoted = candidate), so an old 0 is retired.
		java.util.Set<String> cand = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.VCENTER, off91, off.loadAll(".").values());
		T.check(cand.contains("vc.ssh"), "off: vc.ssh old values retired");
		// Fixed profile path honours the setting too.
		T.check(!ProfileSetTest.find(off.load("VMware_SCG_8.0", null, ".").controls,
				"vc.vami-access-ssh").isEvaluable(), "off: fixed 8.0 demoted");

		// ---- E: unreadable diagnostics tally
		UnreadableReasons u = new UnreadableReasons();
		u.record("esxcli-field-missing: system.settings.encryption.get Mode", 3);
		u.record("soap-fault: HTTP 500 InvalidProperty", 1);
		u.record("esxcli-field-missing: other", 2);
		u.record("vami-http-403: GET tls/profiles/global UNAUTHORIZED", 1);
		u.record("anything", 0);
		T.eq(7, u.total(), "total");
		T.eq("esxcli-field-missing=5, soap-fault=1, vami-http-403=1", u.summary(),
				"count by reason category");
		T.eq("unknown", UnreadableReasons.category(null), "null reason");

		System.out.println("Build74ReadPathsTest: all assertions passed");
	}

	/** Stand-in for VSphereClient.UNREADABLE (VSphereClient needs the SDK). */
	static final class VSphereClientSentinel {
		static final Object U = new Object();
	}

	static Element xml(String s) throws Exception {
		DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
		f.setNamespaceAware(true);
		return f.newDocumentBuilder().parse(new ByteArrayInputStream(
				s.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
	}
}
