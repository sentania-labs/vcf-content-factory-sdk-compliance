package com.vcfcf.adapters.compliance;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpsServer;

/**
 * Build 94: real handshakes with the BouncyCastle JSSE provider (BCJSSE)
 * as the JVM's TLS provider, as on VCF Operations 9.1.1 collectors, where
 * build 93's name check failed every connection ("the connection has no
 * peer host", certificate_unknown(46)). The clients dial a local HTTPS
 * server (SunJSSE) through the adapter's own paths: HttpsURLConnection
 * through {@link VCenterCertificates#secure} (vim25 SOAP, esxcli) and
 * HttpClient (REST, VAMI, Test Connection).
 *
 * <p>Needs the BouncyCastle jars on the classpath (ci/run_java_tests.sh
 * fetches them from Maven Central, checksum pinned); the providers are
 * loaded by name so the rest of the tests compile without them. Runs in
 * its own JVM because it installs BCJSSE as the default TLS provider.
 */
public final class BcHandshakeTest {

	public static void main(String[] args) throws Exception {
		Path dir = Files.createTempDirectory("vcfcf-bc-test");
		try {
			// Keystores first, with the JDK providers.
			KeyStore right = CertificateTest.keystore(dir, "right",
					"CN=localhost", "dns:localhost,ip:127.0.0.1");
			KeyStore wrong = CertificateTest.keystore(dir, "wrong",
					"CN=othername.example", "dns:othername.example");
			X509Certificate rightCert =
					(X509Certificate) right.getCertificate("vc");
			X509Certificate wrongCert =
					(X509Certificate) wrong.getCertificate("vc");
			HttpsServer rs = CertificateTest.server(right);
			HttpsServer ws = CertificateTest.server(wrong);
			try {
				installBouncyCastle();
				run(rs.getAddress().getPort(), ws.getAddress().getPort(),
						rightCert, wrongCert);
			} finally {
				rs.stop(0);
				ws.stop(0);
			}
		} finally {
			CertificateTest.deleteTree(dir.toFile());
		}
		System.out.println("BcHandshakeTest: all assertions passed");
	}

	/** Held so the level sticks (JUL keeps loggers weakly). */
	private static final java.util.logging.Logger BC_LOG =
			java.util.logging.Logger.getLogger("org.bouncycastle");

	private static void installBouncyCastle() throws Exception {
		// BCJSSE logs every alert and property at INFO with stack traces;
		// the test prints its own evidence.
		BC_LOG.setLevel(java.util.logging.Level.OFF);
		Provider bc = (Provider) Class.forName(
				"org.bouncycastle.jce.provider.BouncyCastleProvider")
				.getDeclaredConstructor().newInstance();
		Provider bcjsse = (Provider) Class.forName(
				"org.bouncycastle.jsse.provider.BouncyCastleJsseProvider")
				.getDeclaredConstructor().newInstance();
		Security.insertProviderAt(bc, 1);
		Security.insertProviderAt(bcjsse, 2);
	}

	private static void run(int rp, int wp, X509Certificate rightCert,
			X509Certificate wrongCert) throws Exception {
		for (String host : new String[] {"localhost", "127.0.0.1"}) {
			CertificateTest.PeerHostProbe probe =
					new CertificateTest.PeerHostProbe(rightCert);
			SSLContext ctx = VCenterCertificates.nameChecking(probe, null,
					host + ":" + rp);
			T.eq("BCJSSE", ctx.getProvider().getName(),
					"the adapter's context comes from BCJSSE");
			String u = "https://" + host + ":" + rp + "/";
			T.eq(200, urlConnection(ctx, u), "BCJSSE HttpsURLConnection, "
					+ "right name " + host);
			T.check(probe.called, "platform check ran: " + host);
			System.out.println("BcHandshakeTest evidence: BCJSSE "
					+ "HttpsURLConnection (SOAP path) dialled " + host
					+ ", provider peer host seen by the trust manager: "
					+ probe.peerHost + ", HTTP 200");
			CertificateTest.PeerHostProbe probe2 =
					new CertificateTest.PeerHostProbe(rightCert);
			SSLContext ctx2 = VCenterCertificates.nameChecking(probe2, null,
					host + ":" + rp);
			T.eq(200, httpClient(ctx2, u), "BCJSSE HttpClient, right name "
					+ host);
			System.out.println("BcHandshakeTest evidence: BCJSSE HttpClient "
					+ "(REST path) dialled " + host + ", provider peer host: "
					+ probe2.peerHost + ", HTTP 200");
		}
		for (String host : new String[] {"localhost", "127.0.0.1"}) {
			SSLContext ctx = VCenterCertificates.nameChecking(
					new CertificateTest.ChainOnly(wrongCert), null, host);
			String u = "https://" + host + ":" + wp + "/";
			for (int shape = 0; shape < 2; shape++) {
				try {
					int code = shape == 0 ? urlConnection(ctx, u)
							: httpClient(ctx, u);
					throw new AssertionError("wrong name accepted, HTTP "
							+ code);
				} catch (AssertionError a) {
					throw a;
				} catch (Exception e) {
					T.eq(VCenterCertificates.Failure.NAME_MISMATCH,
							VCenterCertificates.classify(e),
							"BCJSSE wrong name " + host + ": " + e);
					System.out.println("BcHandshakeTest evidence: BCJSSE "
							+ (shape == 0 ? "HttpsURLConnection"
									: "HttpClient")
							+ " wrong name " + host + ": " + rootText(e));
				}
			}
		}
		SSLContext untrusted = VCenterCertificates.nameChecking(
				new CertificateTest.ChainOnly(rightCert), null, "localhost");
		try {
			urlConnection(untrusted, "https://localhost:" + wp + "/");
			throw new AssertionError("untrusted chain accepted");
		} catch (AssertionError a) {
			throw a;
		} catch (Exception e) {
			T.eq(VCenterCertificates.Failure.UNTRUSTED,
					VCenterCertificates.classify(e),
					"BCJSSE untrusted chain first: " + e);
		}
	}

	private static String rootText(Throwable e) {
		Throwable t = e;
		while (t.getCause() != null && t.getCause() != t) t = t.getCause();
		return t.getClass().getSimpleName() + ": " + t.getMessage();
	}

	private static int urlConnection(SSLContext ctx, String url)
			throws Exception {
		HttpsURLConnection conn =
				(HttpsURLConnection) new URL(url).openConnection();
		VCenterCertificates.secure(conn, ctx.getSocketFactory());
		conn.setConnectTimeout(10000);
		conn.setReadTimeout(10000);
		try {
			return conn.getResponseCode();
		} finally {
			conn.disconnect();
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
}
