package com.vcfcf.adapters.compliance;

import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Build 93: the vCenter certificate model, with no VCF Ops SDK dependency so
 * it is unit-testable with a plain JDK.
 *
 * <p>The adapter always validates the vCenter certificate against the VCF
 * Operations trust path ({@code getPlatformSslContext()}); the Allow
 * Insecure SSL setting is removed. An untrusted certificate is accepted by
 * the admin through Validate Connection: the adapter's
 * {@code certificateCheckUrls} hook returns {@link #checkUrls}, VCF
 * Operations probes those URLs and shows its Review and Accept Certificate
 * dialog, and the accepted certificate is stored on the instance and trusted
 * on every cycle. A name mismatch is not fixed by accepting: vCenter must be
 * entered by the name on its certificate.
 *
 * <p>Build 93 (review B1): the name is enforced by this class, on every
 * client. The platform trust manager checks the chain only, and both JDK
 * HTTP clients hand the name check to the trust manager whenever the
 * JDK's default hostname verifier is in effect (setting it explicitly
 * changes nothing: {@code HttpsURLConnection} recognises it by class and
 * still skips its own check). So the adapter wraps the platform trust
 * manager in {@link #nameChecking}, which runs the platform chain check
 * and then matches the certificate to the host dialled, for the REST,
 * VAMI, SOAP and esxcli clients alike, during the handshake (before any
 * credential is sent). The SOAP and esxcli connections additionally set
 * {@link #strictHostnameVerifier} through {@link #secure}, which makes
 * the JDK's own name check run after the handshake as well.
 *
 * <p>Build 94: the host the certificate must carry is the host the adapter
 * dials (the account's vCenter Host / IP, port and IPv6 brackets removed),
 * given to {@link #nameChecking} when the context is built, not the peer
 * host the TLS provider reports. The BouncyCastle JSSE provider used by
 * VCF Operations 9.1.1 collectors reports no peer host on the sockets
 * {@code HttpsURLConnection} opens, so build 93's check failed every
 * connection there with {@code certificate_unknown(46)}.
 */
public final class VCenterCertificates {

	private VCenterCertificates() {}

	/** The vCenter HTTPS port the clients dial when the host names none. */
	static final int DEFAULT_PORT = 443;

	// host, host:port, [v6], [v6]:port. Anything else (a scheme, a path,
	// a bare IPv6 literal) is not a host the clients can dial as entered.
	private static final Pattern HOST_PORT = Pattern.compile(
			"^(\\[[0-9A-Fa-f:.]+\\]|[^:\\[\\]/\\s]+)(?::(\\d{1,5}))?$");

	/**
	 * The URLs whose certificate VCF Operations reviews on Validate
	 * Connection, derived only from the (possibly unsaved) account values.
	 *
	 * <p>Every client the adapter runs dials the same endpoint: the REST
	 * session and inventory ({@code https://<host>/api}), the vim25 SOAP
	 * walk and esxcli ({@code https://<host>/sdk}), and, when
	 * {@code readAppliance} is on, the appliance (VAMI) API, which on vCenter
	 * 7 and later is served by the same reverse proxy at
	 * {@code https://<host>/api/appliance} (the client is built on
	 * {@link ComplianceConfig#baseUrl()}). So the appliance setting adds no
	 * second endpoint, and this method does not take it: one URL covers
	 * every client whether the setting is on or off.
	 *
	 * @return {@code https://<host>:<port>/} (port 443 unless the host names
	 *         one), or an empty list when the host is blank or not a dialable
	 *         host as entered (the tester then reports the real error)
	 */
	public static List<String> checkUrls(String vcenterHost) {
		String root = rootUrl(vcenterHost);
		if (root == null) return Collections.emptyList();
		return Collections.singletonList(root);
	}

	/** {@code https://host:port/} for the entered host, or null. */
	static String rootUrl(String vcenterHost) {
		if (vcenterHost == null) return null;
		String h = vcenterHost.trim();
		if (h.isEmpty()) return null;
		Matcher m = HOST_PORT.matcher(h);
		if (!m.matches()) return null;
		int port = DEFAULT_PORT;
		if (m.group(2) != null) {
			port = Integer.parseInt(m.group(2));
			if (port < 1 || port > 65535) return null;
		}
		return "https://" + m.group(1) + ":" + port + "/";
	}

	/** Why a TLS connection to vCenter was refused on our side. */
	public enum Failure {
		/** The chain is not trusted: accept it through Validate Connection. */
		UNTRUSTED,
		/** The certificate is for another name: re-enter the host. */
		NAME_MISMATCH
	}

	/**
	 * Classify a connection failure by walking its causes and suppressed
	 * exceptions (cycle safe). Untrusted: the platform trust manager's
	 * {@code CustomCertificateException} (matched by name, no SDK on this
	 * class's classpath), a JDK {@code CertPathBuilderException} /
	 * {@code CertPathValidatorException}, or the JDK's PKIX text for a
	 * wrapper that dropped its cause. Name mismatch: the texts of
	 * {@link #checkName}, the JDK's hostname checker and
	 * {@code HttpsURLConnection}. A bare
	 * {@code certificate_unknown} alert is neither: that can be vCenter
	 * rejecting us, which accepting a certificate would not fix.
	 *
	 * @return the failure, or null when it is not a certificate problem
	 */
	public static Failure classify(Throwable t) {
		Set<Throwable> seen = Collections.newSetFromMap(
				new IdentityHashMap<Throwable, Boolean>());
		java.util.ArrayDeque<Throwable> todo = new java.util.ArrayDeque<>();
		if (t != null) todo.add(t);
		boolean nameHit = false;
		while (!todo.isEmpty()) {
			Throwable cur = todo.poll();
			if (!seen.add(cur)) continue;
			if (cur instanceof java.security.cert.CertPathBuilderException
					|| cur instanceof java.security.cert.CertPathValidatorException
					|| "CustomCertificateException".equals(
							cur.getClass().getSimpleName())) {
				return Failure.UNTRUSTED;
			}
			String m = cur.getMessage();
			if (m != null) {
				if (m.contains("PKIX path building failed")
						|| m.contains("unable to find valid certification path")
						|| m.contains("PKIX path validation failed")) {
					return Failure.UNTRUSTED;
				}
				if (m.contains("No subject alternative")
						|| m.contains("No name matching")
						|| isHostnameWrong(m)) {
					nameHit = true;
				}
			}
			if (cur.getCause() != null) todo.add(cur.getCause());
			for (Throwable s : cur.getSuppressed()) {
				if (s != null) todo.add(s);
			}
		}
		return nameHit ? Failure.NAME_MISMATCH : null;
	}

	/**
	 * {@code HttpsURLConnection}'s post-handshake hostname rejection. The
	 * wording moved between JDKs: 17 says {@code HTTPS hostname wrong:
	 * should be <host>}, 25 says {@code Wrong HTTPS hostname: should be
	 * <host>}. Also matched loosely (case-insensitive "https hostname"
	 * plus "should be") so a further rewording keeps the name-mismatch
	 * guidance. A bare "hostname" is not enough: an unrelated error such
	 * as an UnknownHostException saying "hostname vc01 should be
	 * resolvable" must not read as a name mismatch.
	 */
	static boolean isHostnameWrong(String m) {
		if (m == null) return false;
		String l = m.toLowerCase(java.util.Locale.ROOT);
		return l.contains("https hostname wrong")
				|| l.contains("wrong https hostname")
				|| (l.contains("https hostname") && l.contains("should be"));
	}

	/**
	 * The admin-facing message for {@code f}. Deliberately free of the JDK
	 * PKIX strings: the framework's Test Connection path rewrites any message
	 * carrying them into its generic text, which still offers the removed
	 * Allow Insecure SSL setting.
	 */
	public static String message(Failure f, String vcenterHost) {
		String host = vcenterHost == null ? "" : vcenterHost.trim();
		if (f == Failure.NAME_MISMATCH) {
			return "vCenter " + host + " presented a certificate issued for "
					+ "a different name. Edit the account and enter vCenter by "
					+ "the name on its certificate (the FQDN or address the "
					+ "certificate lists), then click Validate Connection. "
					+ "Accepting the certificate does not fix a name mismatch.";
		}
		return "The certificate presented by vCenter " + host + " is not "
				+ "trusted by this VCF Operations account. Open the account and "
				+ "click Validate Connection to review and accept the "
				+ "certificate. Enter vCenter by the name on its certificate: "
				+ "accepting a certificate does not fix a name mismatch.";
	}

	// ----- Certificate name enforcement (build 93, review B1) -------------

	/**
	 * The TLS context every vCenter client uses: {@code platform} (the VCF
	 * Operations trust manager, which trusts the trust store plus the
	 * certificates accepted on this account) wrapped so the certificate
	 * must also carry the name the client dialled. A failed chain check is
	 * thrown exactly as the platform threw it (the accept dialog still
	 * applies); a name that does not match throws a
	 * {@link CertificateException} whose text {@link #classify} reads as
	 * {@link Failure#NAME_MISMATCH}.
	 *
	 * @param platform the platform trust manager ({@code getAdapterTrustManager()})
	 * @param keyManagers the platform key managers (may be null)
	 * @param vcenterHost the host the clients using this context dial, as
	 *        the account entered it (build 94); see {@link #expectedHost}.
	 *        The certificate is matched against it on every handshake,
	 *        whatever peer host the TLS provider reports. When it yields no
	 *        host every handshake is refused (fail closed), never passed.
	 * @throws IllegalArgumentException when {@code platform} is not an
	 *         {@link X509TrustManager}
	 * @throws IllegalStateException when the context cannot be built
	 */
	public static SSLContext nameChecking(TrustManager platform,
			KeyManager[] keyManagers, String vcenterHost) {
		if (!(platform instanceof X509TrustManager)) {
			throw new IllegalArgumentException("not an X509TrustManager: "
					+ (platform == null ? "null"
							: platform.getClass().getName()));
		}
		try {
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(keyManagers, new TrustManager[] {
					new NameCheckingTrustManager((X509TrustManager) platform,
							expectedHost(vcenterHost))},
					null);
			return ctx;
		} catch (java.security.GeneralSecurityException e) {
			throw new IllegalStateException(
					"could not build the vCenter TLS context: " + e, e);
		}
	}

	/**
	 * Apply the vCenter TLS settings to a SOAP connection: the socket
	 * factory (null keeps the JDK default) and {@link #strictHostnameVerifier}.
	 * Every {@code HttpsURLConnection} the adapter opens to vCenter goes
	 * through here.
	 */
	public static void secure(HttpsURLConnection conn,
			SSLSocketFactory factory) {
		if (factory != null) {
			conn.setSSLSocketFactory(factory);
		}
		conn.setHostnameVerifier(STRICT_HOSTNAMES);
	}

	/**
	 * A hostname verifier that never overrides a failed name check.
	 * {@code HttpsURLConnection} runs its own RFC 2818 check after the
	 * handshake whenever the verifier is not the JDK default, and asks the
	 * verifier only when that check fails, so answering no makes the JDK's
	 * check final ("HTTPS hostname wrong" on JDK 17, "Wrong HTTPS hostname"
	 * on JDK 25, both read as
	 * {@link Failure#NAME_MISMATCH}). The JDK default verifier cannot be
	 * used for this: with it the JDK skips its own check and leaves the
	 * name to the trust manager, and the platform's checks the chain only.
	 */
	public static HostnameVerifier strictHostnameVerifier() {
		return STRICT_HOSTNAMES;
	}

	private static final HostnameVerifier STRICT_HOSTNAMES =
			new JdkNameCheckIsFinal();

	/** See {@link #strictHostnameVerifier}. */
	static final class JdkNameCheckIsFinal implements HostnameVerifier {
		@Override
		public boolean verify(String host, SSLSession session) {
			return false;
		}
	}

	/**
	 * The host a certificate must carry for a connection to the account's
	 * vCenter: {@code vcenterHost} trimmed, without a {@code :port}, without
	 * the brackets of an IPv6 literal, lower case, no trailing dot. A bare
	 * IPv6 literal (colons, no brackets) is taken whole. Null when blank or
	 * not a host as entered (a scheme, a path, a space): the name check then
	 * fails closed.
	 */
	static String expectedHost(String vcenterHost) {
		if (vcenterHost == null) return null;
		String h = vcenterHost.trim();
		if (h.isEmpty()) return null;
		Matcher m = HOST_PORT.matcher(h);
		if (m.matches()) return normalizeHost(m.group(1));
		if (BARE_IPV6.matcher(h).matches()) return normalizeHost(h);
		return null;
	}

	private static final Pattern BARE_IPV6 =
			Pattern.compile("^[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*$");

	/**
	 * The platform trust manager plus a name check against the host the
	 * adapter dialled, fixed when the context is built (build 94). Every
	 * overload matches the certificate to that host and ignores the peer
	 * host of the socket or engine, which some TLS providers (BouncyCastle
	 * JSSE on 9.1.1 collectors) do not report. Extends
	 * {@link X509ExtendedTrustManager} so JSSE uses it as is.
	 */
	static final class NameCheckingTrustManager
			extends X509ExtendedTrustManager {

		private final X509TrustManager platform;
		private final String expectedHost;

		/**
		 * @param expectedHost the normalized host from
		 *        {@link #expectedHost}; null refuses every handshake
		 */
		NameCheckingTrustManager(X509TrustManager platform,
				String expectedHost) {
			this.platform = platform;
			this.expectedHost = expectedHost;
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain,
				String authType, Socket socket) throws CertificateException {
			if (platform instanceof X509ExtendedTrustManager) {
				((X509ExtendedTrustManager) platform).checkServerTrusted(
						chain, authType, socket);
			} else {
				platform.checkServerTrusted(chain, authType);
			}
			checkName(expectedHost, chain);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain,
				String authType, SSLEngine engine)
				throws CertificateException {
			if (platform instanceof X509ExtendedTrustManager) {
				((X509ExtendedTrustManager) platform).checkServerTrusted(
						chain, authType, engine);
			} else {
				platform.checkServerTrusted(chain, authType);
			}
			checkName(expectedHost, chain);
		}

		/**
		 * The chain check, then the name check against the dialled host,
		 * as the socket and engine forms do. JSSE providers normally call
		 * those forms for this class.
		 */
		@Override
		public void checkServerTrusted(X509Certificate[] chain,
				String authType) throws CertificateException {
			platform.checkServerTrusted(chain, authType);
			checkName(expectedHost, chain);
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain,
				String authType, Socket socket) throws CertificateException {
			throw new CertificateException("client certificates are not "
					+ "accepted on a vCenter connection");
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain,
				String authType, SSLEngine engine)
				throws CertificateException {
			throw new CertificateException("client certificates are not "
					+ "accepted on a vCenter connection");
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain,
				String authType) throws CertificateException {
			throw new CertificateException("client certificates are not "
					+ "accepted on a vCenter connection");
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return platform.getAcceptedIssuers();
		}
	}

	/** The fail-closed text when there is no host to match (build 94). */
	static final String NO_HOST_MESSAGE = "The vCenter certificate name "
			+ "cannot be checked: the account has no usable vCenter host. "
			+ "Edit the account and set vCenter Host / IP to the name or "
			+ "address on the vCenter certificate (no https://, no path).";

	/**
	 * Throw unless the leaf of {@code chain} carries {@code host}. The text
	 * starts "No subject alternative name matching", which {@link #classify}
	 * reads as a name mismatch. No host at all is refused with
	 * {@link #NO_HOST_MESSAGE} (fail closed).
	 */
	static void checkName(String host, X509Certificate[] chain)
			throws CertificateException {
		if (chain == null || chain.length == 0 || chain[0] == null) {
			throw new CertificateException("vCenter sent no certificate");
		}
		if (normalizeHost(host) == null) {
			throw new CertificateException(NO_HOST_MESSAGE);
		}
		if (!nameMatches(host, chain[0])) {
			throw new CertificateException("No subject alternative name "
					+ "matching " + host + " in the vCenter certificate "
					+ "(subject " + chain[0].getSubjectX500Principal().getName()
					+ ")");
		}
	}

	/**
	 * Whether {@code cert} is issued for {@code host}, by the TLS rules the
	 * JDK applies (RFC 2818 / RFC 6125): an IP address matches only an IP
	 * subject alternative name; a DNS name matches a DNS subject
	 * alternative name, case-insensitive, with a wildcard allowed in the
	 * left-most label only and never directly under a top-level label; the
	 * subject common name is used only when the certificate has no DNS
	 * alternative names.
	 */
	static boolean nameMatches(String host, X509Certificate cert) {
		String h = normalizeHost(host);
		if (h == null || cert == null) return false;
		java.util.Collection<List<?>> sans;
		try {
			sans = cert.getSubjectAlternativeNames();
		} catch (java.security.cert.CertificateParsingException e) {
			return false;
		}
		if (isIpLiteral(h)) {
			InetAddress want = ipLiteral(h);
			if (want == null || sans == null) return false;
			for (List<?> san : sans) {
				if (san != null && san.size() >= 2
						&& Integer.valueOf(7).equals(san.get(0))
						&& san.get(1) instanceof String) {
					InetAddress got = ipLiteral(
							normalizeHost((String) san.get(1)));
					if (want.equals(got)) return true;
				}
			}
			return false;
		}
		boolean anyDns = false;
		if (sans != null) {
			for (List<?> san : sans) {
				if (san != null && san.size() >= 2
						&& Integer.valueOf(2).equals(san.get(0))
						&& san.get(1) instanceof String) {
					anyDns = true;
					if (dnsMatches(h, (String) san.get(1))) return true;
				}
			}
		}
		if (anyDns) return false;
		String cn = mostSpecificCn(cert);
		return cn != null && dnsMatches(h, cn);
	}

	/** Trimmed, unbracketed, no trailing dot, lower case; null when empty. */
	static String normalizeHost(String host) {
		if (host == null) return null;
		String h = host.trim();
		if (h.startsWith("[") && h.endsWith("]") && h.length() > 2) {
			h = h.substring(1, h.length() - 1);
		}
		if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
		if (h.isEmpty()) return null;
		return h.toLowerCase(Locale.ROOT);
	}

	private static final Pattern IPV4 =
			Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

	/**
	 * True for an IPv6 literal (any colon, the bracket already removed by
	 * normalizeHost) or a dotted quad whose four octets are each 0 to 255.
	 * A dotted string with an out-of-range octet (300.1.1.1) is not a
	 * literal, so it is never handed to InetAddress, which would resolve
	 * it through DNS.
	 */
	static boolean isIpLiteral(String h) {
		if (h == null) return false;
		if (h.indexOf(':') >= 0) return true;
		if (!IPV4.matcher(h).matches()) return false;
		for (String octet : h.split("\\.")) {
			if (Integer.parseInt(octet) > 255) return false;
		}
		return true;
	}

	/** The address of an IP literal, never a DNS lookup; null otherwise. */
	private static InetAddress ipLiteral(String h) {
		if (h == null || !isIpLiteral(h)) return null;
		if (h.indexOf(':') >= 0 && !h.matches("^[0-9a-f:.]+$")) return null;
		try {
			return InetAddress.getByName(h);
		} catch (java.net.UnknownHostException e) {
			return null;
		}
	}

	private static boolean dnsMatches(String host, String pattern) {
		String p = normalizeHost(pattern);
		if (p == null) return false;
		if (p.indexOf('*') < 0) return p.equals(host);
		int dot = p.indexOf('.');
		if (dot <= 0) return false;
		String left = p.substring(0, dot);
		String rest = p.substring(dot);   // with its leading dot
		if (rest.indexOf('*') >= 0) return false;
		if (rest.indexOf('.', 1) < 0) return false;   // *.com
		int star = left.indexOf('*');
		if (star != left.lastIndexOf('*')) return false;
		int hdot = host.indexOf('.');
		if (hdot <= 0) return false;
		String hl = host.substring(0, hdot);
		if (!host.substring(hdot).equals(rest)) return false;
		String pre = left.substring(0, star);
		String suf = left.substring(star + 1);
		return hl.length() >= pre.length() + suf.length()
				&& hl.startsWith(pre) && hl.endsWith(suf);
	}

	private static String mostSpecificCn(X509Certificate cert) {
		try {
			javax.naming.ldap.LdapName dn = new javax.naming.ldap.LdapName(
					cert.getSubjectX500Principal().getName(
							javax.security.auth.x500.X500Principal.RFC2253));
			String cn = null;
			// getRdns() runs from the least to the most specific.
			for (javax.naming.ldap.Rdn rdn : dn.getRdns()) {
				if ("CN".equalsIgnoreCase(rdn.getType())
						&& rdn.getValue() instanceof String) {
					cn = (String) rdn.getValue();
				}
			}
			return cn;
		} catch (javax.naming.InvalidNameException e) {
			return null;
		}
	}
}
