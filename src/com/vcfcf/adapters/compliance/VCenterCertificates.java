package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
	 * second endpoint; it is folded into the same root and de-duplicated.
	 *
	 * @return {@code https://<host>:<port>/} (port 443 unless the host names
	 *         one), or an empty list when the host is blank or not a dialable
	 *         host as entered (the tester then reports the real error)
	 */
	public static List<String> checkUrls(String vcenterHost,
			boolean readAppliance) {
		String root = rootUrl(vcenterHost);
		if (root == null) return Collections.emptyList();
		Set<String> urls = new LinkedHashSet<>();
		urls.add(root);
		if (readAppliance) {
			// The VAMI client's base URL is ComplianceConfig.baseUrl(): the
			// same host and port as the root above.
			urls.add(rootUrl(vcenterHost));
		}
		return Collections.unmodifiableList(new ArrayList<>(urls));
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
	 * wrapper that dropped its cause. Name mismatch: the JDK's hostname
	 * checker and {@code HttpsURLConnection} texts. A bare
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
						|| m.contains("HTTPS hostname wrong")) {
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
}
