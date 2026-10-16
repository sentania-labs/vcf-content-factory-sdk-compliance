package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Build 96, issue #26: Test Connection also logs in over vSphere SOAP
 * (RetrieveServiceContent, Login, then Logout), which collection uses,
 * and fails when that login fails; and it reports whether the local Suite
 * API answers, without failing on it. The REST part is unchanged
 * (CertificateTest covers its certificate handling). Run from the repo
 * root.
 */
public final class Build96TestConnectionTest {

	public static void main(String[] args) throws Exception {
		soapLogin();
		suiteApiReported();
		testerWiring();
		System.out.println("Build96TestConnectionTest: all assertions passed");
	}

	static void call(ComplianceAdapter a, String name, Class<?>[] types,
			Object... args) throws Exception {
		Method m = ComplianceAdapter.class.getDeclaredMethod(name, types);
		m.setAccessible(true);
		try {
			m.invoke(a, args);
		} catch (InvocationTargetException e) {
			throw (Exception) e.getCause();
		}
	}

	static void soapLogin() throws Exception {
		Class<?>[] types = {VSphereClient.class, String.class};
		try (FakeVCenter f = new FakeVCenter()) {
			ComplianceAdapter a = new ComplianceAdapter();
			call(a, "testSoapLogin", types, f.client(), "vc.lab.example");
			T.eq(1, f.count("RetrieveServiceContent"), "service content read");
			T.eq(1, f.count("Login"), "logged in");
			T.eq(1, f.count("Logout"), "and logged out");

			f.loginFails = true;
			VSphereClient c = f.client();
			try {
				call(a, "testSoapLogin", types, c, "vc.lab.example");
				throw new AssertionError("a failed SOAP login must fail");
			} catch (Exception e) {
				T.check(e.getMessage().contains("vSphere SOAP (vim25) login"),
						"says which login failed: " + e.getMessage());
			}
			T.check(c.isClosed(), "the test client is closed either way");
		}
	}

	static void suiteApiReported() throws Exception {
		ComplianceAdapter a = new ComplianceAdapter();
		SuiteApiStitcher.testFactory = null;   // create() fails
		call(a, "testSuiteApi", new Class<?>[0]);
		T.check(a.testLog.stream().anyMatch(l -> l.startsWith("WARN ")
				&& l.contains("Suite API did not answer")),
				"unreachable Suite API: a WARN, the test still passes");

		final int[] gets = {0};
		final int[] discards = {0};
		SuiteApiStitcher.testFactory = new SuiteApiStitcher.Backend() {
			@Override public String get(String path) {
				gets[0]++;
				T.eq("/api/versions/current", path, "a cheap GET");
				return "{}";
			}
			@Override public void discard() { discards[0]++; }
		};
		try {
			ComplianceAdapter b = new ComplianceAdapter();
			call(b, "testSuiteApi", new Class<?>[0]);
			T.check(b.testLog.stream().anyMatch(l -> l.startsWith("INFO ")
					&& l.contains("Suite API answered")), "answered: INFO");
			T.eq(1, gets[0], "one GET");
			T.eq(1, discards[0], "token released");
		} finally {
			SuiteApiStitcher.testFactory = null;
		}
	}

	/** The tester runs REST, then SOAP, then the Suite API check. */
	static void testerWiring() throws Exception {
		String src = new String(java.nio.file.Files.readAllBytes(
				java.nio.file.Paths.get(
						"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java")),
				java.nio.charset.StandardCharsets.UTF_8);
		int rest = src.indexOf("testApi.listHosts();");
		int soap = src.indexOf("testSoapLogin(new VSphereClient(");
		int suite = src.indexOf("testSuiteApi();");
		int ok = src.indexOf("logInfo(\"Test OK: connected to \"");
		T.check(rest > 0 && soap > rest && suite > soap && ok > suite,
				"REST, SOAP, Suite API, then Test OK");
	}
}
