package com.vcfcf.adapters.compliance;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Build 93: the certificate model (no Allow Insecure SSL, the accept dialog
 * through the certificateCheckUrls hook) and the WARN for an account that
 * stored allowInsecure=true. Plain JDK, no SDK.
 */
public final class CertificateTest {

	public static void main(String[] args) throws Exception {
		hookUrls();
		classify();
		messages();
		retiredAllowInsecure();
		sourceContract();
		System.out.println("CertificateTest: all assertions passed");
	}

	static void hookUrls() {
		List<String> one = Collections.singletonList(
				"https://vc01.lab.local:443/");
		T.eq(one, VCenterCertificates.checkUrls("vc01.lab.local", false),
				"host present, appliance off");
		// The appliance (VAMI) API is the same host and port: one URL.
		T.eq(one, VCenterCertificates.checkUrls("vc01.lab.local", true),
				"host present, appliance on");
		T.eq(one, VCenterCertificates.checkUrls("  vc01.lab.local ", true),
				"host is trimmed");
		T.eq(Collections.singletonList("https://10.0.0.5:443/"),
				VCenterCertificates.checkUrls("10.0.0.5", false), "IPv4");
		T.eq(Collections.singletonList("https://vc01:8443/"),
				VCenterCertificates.checkUrls("vc01:8443", true),
				"an entered port is the port dialled");
		T.eq(Collections.singletonList("https://[fd00::5]:443/"),
				VCenterCertificates.checkUrls("[fd00::5]", false),
				"bracketed IPv6");
		for (String blank : new String[] {null, "", "   "}) {
			for (boolean app : new boolean[] {false, true}) {
				T.eq(Collections.<String>emptyList(),
						VCenterCertificates.checkUrls(blank, app),
						"host blank '" + blank + "' appliance " + app);
			}
		}
		for (String bad : new String[] {"https://vc01", "vc01/sdk",
				"fd00::5", "vc01:99999", "vc 01"}) {
			T.eq(Collections.<String>emptyList(),
					VCenterCertificates.checkUrls(bad, false),
					"not dialable as entered: " + bad);
		}
	}

	static void classify() {
		Exception pkix = new javax.net.ssl.SSLHandshakeException(
				"PKIX path building failed: unable to find valid "
						+ "certification path to requested target");
		T.eq(VCenterCertificates.Failure.UNTRUSTED,
				VCenterCertificates.classify(new java.io.IOException("x", pkix)),
				"PKIX text in the cause");
		Exception typed = new RuntimeException("wrap",
				new java.security.cert.CertPathValidatorException("bad"));
		T.eq(VCenterCertificates.Failure.UNTRUSTED,
				VCenterCertificates.classify(typed), "CertPathValidator");
		Exception custom = new RuntimeException("wrap",
				new CustomCertificateException("not trusted"));
		T.eq(VCenterCertificates.Failure.UNTRUSTED,
				VCenterCertificates.classify(custom),
				"platform CustomCertificateException by name");
		Exception suppressed = new RuntimeException("outer");
		suppressed.addSuppressed(
				new java.security.cert.CertPathBuilderException("b"));
		T.eq(VCenterCertificates.Failure.UNTRUSTED,
				VCenterCertificates.classify(suppressed), "suppressed");
		T.eq(VCenterCertificates.Failure.NAME_MISMATCH,
				VCenterCertificates.classify(new java.io.IOException(
						"HTTPS hostname wrong:  should be <10.0.0.5>")),
				"HttpsURLConnection hostname check");
		T.eq(VCenterCertificates.Failure.NAME_MISMATCH,
				VCenterCertificates.classify(new RuntimeException("x",
						new java.security.cert.CertificateException(
								"No subject alternative DNS name matching "
										+ "vc01 found."))),
				"JDK hostname checker");
		T.eq(null, VCenterCertificates.classify(
				new javax.net.ssl.SSLHandshakeException(
						"Received fatal alert: certificate_unknown")),
				"a bare certificate_unknown alert is not ours to accept");
		T.eq(null, VCenterCertificates.classify(
				new java.net.ConnectException("Connection refused")),
				"connect failure");
		T.eq(null, VCenterCertificates.classify(null), "null");
		Exception loop = new Exception("a");
		Exception loop2 = new Exception("b", loop);
		loop.initCause(loop2);
		T.eq(null, VCenterCertificates.classify(loop), "cause cycle");
	}

	static void messages() {
		String u = VCenterCertificates.message(
				VCenterCertificates.Failure.UNTRUSTED, " vc01.lab.local ");
		T.check(u.contains("vCenter vc01.lab.local "), "names the host: " + u);
		T.check(u.contains("Open the account and click Validate Connection "
				+ "to review and accept the certificate"), "accept: " + u);
		T.check(u.contains("Enter vCenter by the name on its certificate"),
				"hostname rule: " + u);
		String n = VCenterCertificates.message(
				VCenterCertificates.Failure.NAME_MISMATCH, "10.0.0.5");
		T.check(n.contains("enter vCenter by the name on its certificate"),
				"rename: " + n);
		T.check(n.contains("does not fix a name mismatch"), "mismatch: " + n);
		for (String m : Arrays.asList(u, n)) {
			// The framework's onTest rewrites any message carrying these
			// into text that offers the removed Allow Insecure SSL.
			T.check(!m.contains("PKIX path building failed")
					&& !m.contains("unable to find valid certification path"),
					"no PKIX trigger text: " + m);
			T.check(!m.contains("Allow Insecure") && !m.contains("insecure"),
					"no removed setting: " + m);
			T.check(m.indexOf('\u2014') < 0, "no em dash");
		}
	}

	static void retiredAllowInsecure() {
		for (String stored : new String[] {"true", "TRUE", " true "}) {
			String w = ComplianceConfig.retiredAllowInsecureNotice(stored);
			T.check(w != null && w.contains("stored allowInsecure=true")
					&& w.contains("Validate Connection")
					&& w.contains("name on its certificate"),
					"WARN for '" + stored + "': " + w);
		}
		for (String quiet : new String[] {null, "", "false", "FALSE", "yes",
				"1"}) {
			T.eq(null, ComplianceConfig.retiredAllowInsecureNotice(quiet),
					"no WARN for '" + quiet + "'");
		}
	}

	/** The adapter wires the hook and keeps no trust-all path. */
	static void sourceContract() throws Exception {
		String ca = read(
				"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");
		OverridesTest.inOrder(ca, "certificateCheckUrls hook",
				"@Override",
				"protected List<String> certificateCheckUrls(ResourceConfig rc)",
				"VCenterCertificates.checkUrls(",
				"getIdentifier(rc, \"vcenter_host\")",
				"ComplianceConfig.READ_APPLIANCE_KEY");
		int hook = ca.indexOf("protected List<String> certificateCheckUrls(");
		String before = ca.substring(Math.max(0, hook - 40), hook);
		T.check(before.contains("@Override"),
				"@Override sits directly on the hook");
		T.check(!ca.contains("insecureSslContext"), "no trust-all context");
		T.check(!ca.contains("config.allowInsecure"), "no allowInsecure");
		OverridesTest.inOrder(ca, "configure WARN",
				"ComplianceConfig.RETIRED_ALLOW_INSECURE_KEY",
				"ComplianceConfig.retiredAllowInsecureNotice(storedAllowInsecure)",
				"logWarn(tlsNotice);");
		OverridesTest.inOrder(ca, "configure INFO",
				"ComplianceConfig.RETIRED_PROFILE_KEY",
				"ComplianceConfig.retiredProfileNotice(storedProfile)",
				"logInfo(profileNotice);");
		// Test Connection rethrows without the cause (see the comment there).
		OverridesTest.inOrder(ca, "tester",
				"VCenterCertificates.classify(e)",
				"throw new Exception(VCenterCertificates.message(f,",
				"+ \")\");");
		String vs = read("src/com/vcfcf/adapters/compliance/VSphereClient.java");
		T.check(!vs.contains("setHostnameVerifier"), "no hostname bypass");
		T.check(!vs.contains("trustAll"), "no trust-all factory");
	}

	static String read(String path) throws Exception {
		return new String(Files.readAllBytes(Paths.get(path)),
				StandardCharsets.UTF_8);
	}

	/** Stands in for the platform's CustomTrustManager exception (by name). */
	static final class CustomCertificateException extends Exception {
		CustomCertificateException(String m) { super(m); }
	}
}
