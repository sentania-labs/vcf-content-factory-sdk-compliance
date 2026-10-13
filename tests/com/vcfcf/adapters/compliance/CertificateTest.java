package com.vcfcf.adapters.compliance;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * Build 93: the certificate model (no Allow Insecure SSL, the accept dialog
 * through the certificateCheckUrls hook), the WARN for an account that
 * stored allowInsecure=true, the certificate name enforcement (review B1:
 * the matcher, and real TLS handshakes against a local HTTPS server with a
 * wrong-name certificate, through a chain-only trust manager standing in
 * for the platform's). Plain JDK, no SDK. The certificates are made
 * with the JDK's keytool.
 */
public final class CertificateTest {

	public static void main(String[] args) throws Exception {
		hookUrls();
		classify();
		messages();
		retiredAllowInsecure();
		Path dir = Files.createTempDirectory("vcfcf-cert-test");
		try {
			nameMatching(dir);
			liveHandshakes(dir);
		} finally {
			deleteTree(dir.toFile());
		}
		sourceContract();
		System.out.println("CertificateTest: all assertions passed");
	}

	static void hookUrls() {
		List<String> one = Collections.singletonList(
				"https://vc01.lab.local:443/");
		// One URL whatever Read vCenter appliance settings says: the
		// appliance (VAMI) API is the same host and port.
		T.eq(one, VCenterCertificates.checkUrls("vc01.lab.local"),
				"host present");
		T.eq(one, VCenterCertificates.checkUrls("  vc01.lab.local "),
				"host is trimmed");
		T.eq(Collections.singletonList("https://10.0.0.5:443/"),
				VCenterCertificates.checkUrls("10.0.0.5"), "IPv4");
		T.eq(Collections.singletonList("https://vc01:8443/"),
				VCenterCertificates.checkUrls("vc01:8443"),
				"an entered port is the port dialled");
		T.eq(Collections.singletonList("https://[fd00::5]:443/"),
				VCenterCertificates.checkUrls("[fd00::5]"),
				"bracketed IPv6");
		for (String blank : new String[] {null, "", "   "}) {
			T.eq(Collections.<String>emptyList(),
					VCenterCertificates.checkUrls(blank),
					"host blank '" + blank + "'");
		}
		for (String bad : new String[] {"https://vc01", "vc01/sdk",
				"fd00::5", "vc01:99999", "vc 01"}) {
			T.eq(Collections.<String>emptyList(),
					VCenterCertificates.checkUrls(bad),
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
		T.eq(VCenterCertificates.Failure.NAME_MISMATCH,
				VCenterCertificates.classify(new javax.net.ssl
						.SSLHandshakeException("No subject alternative name "
								+ "matching 10.0.0.5 in the vCenter "
								+ "certificate (subject CN=vc01)")),
				"the adapter's own name check");
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

	/**
	 * The adapter wires the hook, keeps no trust-all path, and every client
	 * that opens a connection to vCenter enforces the certificate name.
	 */
	static void sourceContract() throws Exception {
		String ca = read(
				"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");
		OverridesTest.inOrder(ca, "certificateCheckUrls hook",
				"@Override",
				"protected List<String> certificateCheckUrls(ResourceConfig rc)",
				"VCenterCertificates.checkUrls(",
				"getIdentifier(rc, \"vcenter_host\"));");
		int hook = ca.indexOf("protected List<String> certificateCheckUrls(");
		String before = ca.substring(Math.max(0, hook - 40), hook);
		T.check(before.contains("@Override"),
				"@Override sits directly on the hook");
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

		// B1: one TLS context for every vCenter client, name enforced.
		OverridesTest.inOrder(ca, "the shared context checks the name",
				"private javax.net.ssl.SSLContext sslContextFor() {",
				"return VCenterCertificates.nameChecking(getAdapterTrustManager(),",
				"getKeyManagers());");
		OverridesTest.inOrder(ca, "the SOAP factory is that context's",
				"private javax.net.ssl.SSLSocketFactory sslSocketFactoryFor() {",
				"javax.net.ssl.SSLContext ctx = sslContextFor();",
				"return ctx.getSocketFactory();");
		T.eq(1, OverridesTest.count(ca, "getSocketFactory()"),
				"the only socket factory is the name-checking context's");
		OverridesTest.inOrder(ca, "REST client", "this.vcApi = new "
				+ "VCenterApiClient(", "sslContextFor());");
		OverridesTest.inOrder(ca, "SOAP client", "this.vsphere = new "
				+ "VSphereClient(", "sslSocketFactoryFor(),");
		OverridesTest.inOrder(ca, "Test Connection client",
				"VCenterApiClient testApi = new VCenterApiClient(",
				"sslContextFor());");
		OverridesTest.inOrder(ca, "VAMI client", "new VamiApiClient(",
				"sslContextFor(), this::logWarn);");

		// Per client: the HttpsURLConnection clients set the strict
		// verifier through the shared helper; the HttpClient clients take
		// the context they are handed. None has its own trust path.
		String vs = read("src/com/vcfcf/adapters/compliance/VSphereClient.java");
		String ex = read(
				"src/com/vcfcf/adapters/compliance/EsxcliSoapClient.java");
		String rest = read(
				"src/com/vcfcf/adapters/compliance/VCenterApiClient.java");
		String vami = read(
				"src/com/vcfcf/adapters/compliance/VamiApiClient.java");
		for (Map.Entry<String, String> c : clients(vs, ex).entrySet()) {
			String src = c.getValue();
			T.eq(1, OverridesTest.count(src, "openConnection()"),
					c.getKey() + ": one connection site");
			OverridesTest.inOrder(src, c.getKey() + " secures it",
					"url.openConnection();",
					"if (conn instanceof HttpsURLConnection) {",
					"VCenterCertificates.secure((HttpsURLConnection) conn, "
							+ "sslFactory);",
					"conn.setRequestMethod(\"POST\");");
			T.check(!src.contains("setSSLSocketFactory"),
					c.getKey() + ": the factory is set by secure() only");
		}
		for (Map.Entry<String, String> c : clients(rest, vami).entrySet()) {
			String src = c.getValue();
			OverridesTest.inOrder(src, c.getKey() + " uses the context",
					"if (sslContext != null) {",
					"builder.sslContext(sslContext);");
		}
		Map<String, String> all = new LinkedHashMap<>();
		all.put("ComplianceAdapter", ca);
		all.put("VSphereClient", vs);
		all.put("EsxcliSoapClient", ex);
		all.put("VCenterApiClient", rest);
		all.put("VamiApiClient", vami);
		for (Map.Entry<String, String> c : all.entrySet()) {
			String src = c.getValue();
			for (String banned : new String[] {"X509TrustManager",
					"X509ExtendedTrustManager", "TrustManager[]",
					"TrustManagerFactory", "implements HostnameVerifier",
					"new HostnameVerifier", "setHostnameVerifier(",
					"-> true", "insecureSslContext", "trustAll",
					"getPlatformSslContext"}) {
				T.check(!src.contains(banned),
						c.getKey() + ": no own trust path (" + banned + ")");
			}
		}
	}

	private static Map<String, String> clients(String a, String b) {
		Map<String, String> m = new LinkedHashMap<>();
		m.put(a.contains("class VSphereClient") ? "VSphereClient"
				: "VCenterApiClient", a);
		m.put(b.contains("class EsxcliSoapClient") ? "EsxcliSoapClient"
				: "VamiApiClient", b);
		return m;
	}

	// ----- B1: the matcher --------------------------------------------------

	static void nameMatching(Path dir) throws Exception {
		X509Certificate both = cert(dir, "both", "CN=vc01.lab.local",
				"dns:vc01.lab.local,ip:10.0.0.5,ip:fd00:0:0:0:0:0:0:5");
		T.check(VCenterCertificates.nameMatches("vc01.lab.local", both),
				"DNS SAN");
		T.check(VCenterCertificates.nameMatches("VC01.Lab.Local.", both),
				"case and trailing dot");
		T.check(VCenterCertificates.nameMatches("10.0.0.5", both), "IP SAN");
		T.check(VCenterCertificates.nameMatches("[fd00::5]", both),
				"bracketed IPv6 SAN");
		T.check(!VCenterCertificates.nameMatches("vc01", both),
				"short name not on the certificate");
		T.check(!VCenterCertificates.nameMatches("10.0.0.6", both),
				"other IP");
		T.check(!VCenterCertificates.nameMatches("vc01.lab.local.evil",
				both), "suffix");
		T.check(!VCenterCertificates.nameMatches(null, both), "null host");
		T.check(!VCenterCertificates.nameMatches(" ", both), "blank host");

		X509Certificate wild = cert(dir, "wild", "CN=wild",
				"dns:*.lab.local,dns:*.com");
		T.check(VCenterCertificates.nameMatches("vc02.lab.local", wild),
				"wildcard, one label");
		T.check(!VCenterCertificates.nameMatches("a.vc02.lab.local", wild),
				"wildcard covers one label only");
		T.check(!VCenterCertificates.nameMatches("lab.local", wild),
				"wildcard needs a label");
		T.check(!VCenterCertificates.nameMatches("example.com", wild),
				"no wildcard directly under a top-level label");
		T.check(!VCenterCertificates.nameMatches("wild", wild),
				"CN ignored when DNS SANs exist");

		X509Certificate cnOnly = cert(dir, "cn", "CN=vc03.lab.local, O=Lab",
				null);
		T.check(VCenterCertificates.nameMatches("vc03.lab.local", cnOnly),
				"CN used when there are no DNS SANs");
		T.check(!VCenterCertificates.nameMatches("vc04.lab.local", cnOnly),
				"other CN");

		X509Certificate ipCn = cert(dir, "ipcn", "CN=10.0.0.9", null);
		T.check(!VCenterCertificates.nameMatches("10.0.0.9", ipCn),
				"an IP never matches the CN");

		X509Certificate ipOnly = cert(dir, "iponly", "CN=vc05.lab.local",
				"ip:10.0.0.7");
		T.check(VCenterCertificates.nameMatches("vc05.lab.local", ipOnly),
				"no DNS SAN: the CN is used for a DNS name");
		T.check(!VCenterCertificates.nameMatches("10.0.0.5", ipOnly),
				"IP SAN mismatch");

		for (String h : new String[] {null, "", "  "}) {
			try {
				VCenterCertificates.checkName(h,
						new X509Certificate[] {both});
				throw new AssertionError("no host must be refused: " + h);
			} catch (CertificateException expected) {
				T.check(expected.getMessage().contains("no peer host"),
						"fail closed: " + expected.getMessage());
			}
		}
	}

	// ----- B1: real handshakes ----------------------------------------------

	/**
	 * A local HTTPS server presents a certificate for othername.example; the
	 * clients dial it as localhost and 127.0.0.1. The client trust manager
	 * trusts that exact certificate and checks the chain only, as the
	 * platform's CustomTrustManager does (javap, review B1).
	 */
	static void liveHandshakes(Path dir) throws Exception {
		KeyStore wrongKs = keystore(dir, "wrongsrv", "CN=othername.example",
				"dns:othername.example");
		KeyStore rightKs = keystore(dir, "rightsrv", "CN=localhost",
				"dns:localhost,ip:127.0.0.1");
		X509Certificate wrongCert =
				(X509Certificate) wrongKs.getCertificate("vc");
		X509Certificate rightCert =
				(X509Certificate) rightKs.getCertificate("vc");

		HttpsServer wrong = server(wrongKs);
		HttpsServer right = server(rightKs);
		try {
			int wp = wrong.getAddress().getPort();
			int rp = right.getAddress().getPort();
			SSLContext chainOnly = context(new ChainOnly(wrongCert));
			SSLContext enforced = VCenterCertificates.nameChecking(
					new ChainOnly(wrongCert), null);

			// Controls: why the name had to be enforced in the adapter.
			T.eq(200, httpClient(chainOnly, "https://localhost:" + wp + "/"),
					"control: a chain-only trust manager lets HttpClient "
							+ "accept a wrong-name certificate");
			T.eq(200, urlConnection(chainOnly.getSocketFactory(),
					HttpsURLConnection.getDefaultHostnameVerifier(),
					"https://localhost:" + wp + "/"),
					"control: the JDK default hostname verifier, set "
							+ "explicitly, enforces nothing either");
			System.out.println("CertificateTest evidence: wrong-name "
					+ "certificate (othername.example) dialled as localhost "
					+ "through a chain-only trust manager: HttpClient 200, "
					+ "HttpsURLConnection with the default verifier set "
					+ "explicitly 200 (no name check without the fix)");

			// The fix, every client shape.
			String rest = refused(() -> httpClient(enforced,
					"https://localhost:" + wp + "/"));
			String soap = refused(() -> urlConnection(
					enforced.getSocketFactory(), null,
					"https://localhost:" + wp + "/"));
			String soapIp = refused(() -> urlConnection(
					enforced.getSocketFactory(), null,
					"https://127.0.0.1:" + wp + "/"));
			String verifierOnly = refused(() -> urlConnection(
					chainOnly.getSocketFactory(), null,
					"https://localhost:" + wp + "/"));
			System.out.println("CertificateTest evidence: nameChecking "
					+ "context, HttpClient (REST, VAMI, Test Connection): "
					+ rest);
			System.out.println("CertificateTest evidence: secure() with the "
					+ "nameChecking factory (vim25 SOAP, esxcli), as "
					+ "localhost: " + soap);
			System.out.println("CertificateTest evidence: same, as "
					+ "127.0.0.1: " + soapIp);
			System.out.println("CertificateTest evidence: secure() with a "
					+ "chain-only factory (the strict verifier alone): "
					+ verifierOnly);

			// An untrusted chain is still the platform's failure (the
			// accept dialog), even when the name is wrong too.
			SSLContext untrusted = VCenterCertificates.nameChecking(
					new ChainOnly(rightCert), null);
			try {
				httpClient(untrusted, "https://localhost:" + wp + "/");
				throw new AssertionError("untrusted chain must fail");
			} catch (Exception e) {
				T.eq(VCenterCertificates.Failure.UNTRUSTED,
						VCenterCertificates.classify(e),
						"chain failure first: " + e);
			}

			// The right name passes, by DNS name and by IP.
			SSLContext ok = VCenterCertificates.nameChecking(
					new ChainOnly(rightCert), null);
			for (String host : new String[] {"localhost", "127.0.0.1"}) {
				String u = "https://" + host + ":" + rp + "/";
				T.eq(200, httpClient(ok, u), "HttpClient, right name " + host);
				T.eq(200, urlConnection(ok.getSocketFactory(), null, u),
						"secure(), right name " + host);
			}
		} finally {
			wrong.stop(0);
			right.stop(0);
		}
	}

	private interface Call { int run() throws Exception; }

	/** The call must fail as NAME_MISMATCH; returns the JDK's text. */
	private static String refused(Call c) {
		try {
			int code = c.run();
			throw new AssertionError("wrong-name certificate accepted, HTTP "
					+ code);
		} catch (AssertionError a) {
			throw a;
		} catch (Exception e) {
			T.eq(VCenterCertificates.Failure.NAME_MISMATCH,
					VCenterCertificates.classify(e), "classified: " + e);
			String msg = VCenterCertificates.message(
					VCenterCertificates.classify(e), "localhost");
			T.check(msg.contains("issued for a different name"),
					"the name message: " + msg);
			return e.getClass().getSimpleName() + ": " + e.getMessage();
		}
	}

	private static int httpClient(SSLContext ctx, String url)
			throws Exception {
		HttpClient c = HttpClient.newBuilder().sslContext(ctx)
				.connectTimeout(Duration.ofSeconds(10)).build();
		HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(url))
				.timeout(Duration.ofSeconds(10)).GET().build(),
				HttpResponse.BodyHandlers.ofString());
		return r.statusCode();
	}

	/**
	 * {@code verifier} null: the adapter's own path,
	 * {@link VCenterCertificates#secure}. Otherwise that verifier is set.
	 */
	private static int urlConnection(javax.net.ssl.SSLSocketFactory f,
			javax.net.ssl.HostnameVerifier verifier, String url)
			throws Exception {
		HttpsURLConnection conn =
				(HttpsURLConnection) new URL(url).openConnection();
		if (verifier == null) {
			VCenterCertificates.secure(conn, f);
		} else {
			conn.setSSLSocketFactory(f);
			conn.setHostnameVerifier(verifier);
		}
		conn.setConnectTimeout(10000);
		conn.setReadTimeout(10000);
		try {
			return conn.getResponseCode();
		} finally {
			conn.disconnect();
		}
	}

	private static SSLContext context(TrustManager tm) throws Exception {
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, new TrustManager[] {tm}, null);
		return ctx;
	}

	private static HttpsServer server(KeyStore ks) throws Exception {
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(
				KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, PASS);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(kmf.getKeyManagers(), null, null);
		HttpsServer s = HttpsServer.create(new InetSocketAddress(
				InetAddress.getLoopbackAddress(), 0), 0);
		s.setHttpsConfigurator(new HttpsConfigurator(ctx));
		s.createContext("/", ex -> {
			byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
			ex.sendResponseHeaders(200, body.length);
			try (OutputStream os = ex.getResponseBody()) {
				os.write(body);
			}
		});
		s.start();
		return s;
	}

	/**
	 * Trusts exactly {@code trusted} and checks the chain only, ignoring
	 * the peer host: the platform CustomTrustManager's shape. An unknown
	 * certificate fails the way the platform's does (by class name).
	 */
	static final class ChainOnly extends X509ExtendedTrustManager {
		private final X509Certificate trusted;

		ChainOnly(X509Certificate trusted) {
			this.trusted = trusted;
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String a)
				throws CertificateException {
			if (chain == null || chain.length == 0
					|| !trusted.equals(chain[0])) {
				throw new CustomCertificateException("not accepted");
			}
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String a,
				Socket s) throws CertificateException {
			checkServerTrusted(chain, a);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String a,
				SSLEngine e) throws CertificateException {
			checkServerTrusted(chain, a);
		}

		@Override
		public void checkClientTrusted(X509Certificate[] c, String a) {}

		@Override
		public void checkClientTrusted(X509Certificate[] c, String a,
				Socket s) {}

		@Override
		public void checkClientTrusted(X509Certificate[] c, String a,
				SSLEngine e) {}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[] {trusted};
		}
	}

	// ----- keytool ----------------------------------------------------------

	private static final char[] PASS = "changeit".toCharArray();

	private static X509Certificate cert(Path dir, String name, String dname,
			String san) throws Exception {
		return (X509Certificate) keystore(dir, name, dname, san)
				.getCertificate("vc");
	}

	/** A PKCS12 keystore with one self-signed EC key pair, alias "vc". */
	private static KeyStore keystore(Path dir, String name, String dname,
			String san) throws Exception {
		File ks = dir.resolve(name + ".p12").toFile();
		File keytool = new File(System.getProperty("java.home"),
				"bin" + File.separator + "keytool");
		T.check(keytool.isFile(), "keytool not found at " + keytool
				+ " (the certificate tests need a full JDK)");
		List<String> cmd = new ArrayList<>(Arrays.asList(keytool.getPath(),
				"-genkeypair", "-alias", "vc", "-keyalg", "EC", "-groupname",
				"secp256r1", "-sigalg", "SHA256withECDSA", "-validity", "2",
				"-dname", dname, "-storetype", "PKCS12", "-keystore",
				ks.getPath(), "-storepass", new String(PASS), "-keypass",
				new String(PASS)));
		if (san != null) {
			cmd.add("-ext");
			cmd.add("SAN=" + san);
		}
		Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		String out = new String(p.getInputStream().readAllBytes(),
				StandardCharsets.UTF_8);
		T.check(p.waitFor() == 0, "keytool failed for " + name + ": " + out);
		KeyStore k = KeyStore.getInstance("PKCS12");
		try (InputStream in = new FileInputStream(ks)) {
			k.load(in, PASS);
		}
		return k;
	}

	private static void deleteTree(File f) {
		File[] kids = f.listFiles();
		if (kids != null) {
			for (File k : kids) deleteTree(k);
		}
		f.delete();
	}

	static String read(String path) throws Exception {
		return new String(Files.readAllBytes(Paths.get(path)),
				StandardCharsets.UTF_8);
	}

	/** Stands in for the platform's CustomTrustManager exception (by name). */
	static final class CustomCertificateException
			extends CertificateException {
		CustomCertificateException(String m) { super(m); }
	}
}
