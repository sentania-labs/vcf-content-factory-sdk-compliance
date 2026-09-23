package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.json.SimpleJson;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * VAMI (vCenter Server Appliance Management) REST reader — build 41.
 *
 * <p>A transport distinct from the vim25 SOAP surface: it talks to the
 * vCenter Appliance Management REST API at {@code /api/appliance/...}. The
 * REST API needs its OWN session — it does NOT ride the SOAP session
 * cookie. We open one with {@code POST /api/session} using HTTP Basic auth
 * (the same raw username/password the adapter already holds to build the
 * SOAP session), and pass the returned token as the
 * {@code vmware-api-session-id} header on every GET. This mirrors
 * {@link VCenterApiClient}, but is kept separate so the VAMI surface (one
 * per vCenter, against the {@code VCenterAdapterInstance} resource) has its
 * own failed-session caching and its own appliance-path response cache.
 *
 * <p><b>BLIND BUILD — schema confidence MEDIUM.</b> The JSON field names
 * extracted here are derived from API documentation, not captured on the
 * wire. They are safe-by-construction: a wrong field name, a non-200, a
 * 404, an auth failure, a timeout, or a JSON parse error ALL fold to the
 * {@link #FAILED} sentinel (→ UNREADABLE upstream), NEVER to a value and
 * NEVER to a "compliant" pass. This is the cardinal trap restated for the
 * REST transport — most dangerous for the "should be disabled" controls
 * (a failed GET of {@code access/ssh} must not become "ssh disabled →
 * compliant"). Only a successful 200 with the field present yields a value.
 *
 * <p><b>Failed-session caching</b> (mirrors {@link EsxcliSoapClient}'s
 * failed-result caching). If the REST session cannot be opened, the failure
 * is cached for the lifetime of this client (one collection cycle) so it is
 * not retried per-control. Likewise each appliance-path GET is cached per
 * cycle — including a FAILED result — so N controls that read different
 * fields of the same endpoint cost exactly one GET.
 */
final class VamiApiClient {

	static final Object FAILED = new Object() {
		@Override public String toString() { return "(vami-failed)"; }
	};

	static final String SELF_LIST = VamiRecipe.SELF_LIST;

	private final HttpClient httpClient;
	private final String baseUrl;
	private final String username;
	private final String password;
	private final java.util.function.Consumer<String> warn;

	private volatile String sessionId;
	private volatile boolean sessionTried;
	// Why the session failed (reason category first, see UnreadableReasons).
	private volatile String sessionFailure;

	// Per-cycle cache: appliance-path -> parsed body, or a failure reason.
	private final Map<String, Object> pathCache = new HashMap<>();
	private final Map<String, String> pathFailure = new HashMap<>();
	// Build 74: each failure is logged once per cycle (this client lives
	// for one cycle), never with credentials.
	private final java.util.Set<String> logged = new java.util.HashSet<>();

	/**
	 * @param sslContext the TLS context to use: the platform context when
	 *        allowInsecure=false (build 74; was the JDK default, which does
	 *        not trust a lab or enterprise CA, so every VAMI read failed on
	 *        such vCenters), the trust-all context when allowInsecure=true.
	 *        Null falls back to the JDK default.
	 * @param warn  receives one line per distinct failure (may be null)
	 */
	VamiApiClient(String baseUrl, String username, String password,
			SSLContext sslContext, java.util.function.Consumer<String> warn) {
		this.baseUrl = baseUrl;
		this.username = username != null ? username : "";
		this.password = password != null ? password : "";
		this.warn = warn;
		HttpClient.Builder builder = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(30));
		if (sslContext != null) {
			builder.sslContext(sslContext);
		}
		this.httpClient = builder.build();
	}

	private void warnOnce(String key, String message) {
		if (warn != null && logged.add(key)) {
			warn.accept(message);
		}
	}

	/** vAPI error_type from an error body, or null. */
	private static String errorType(String body) {
		try {
			SimpleJson j = SimpleJson.parse(body);
			if (j == null || j.isNull() || !j.isObject()) return null;
			return j.get("error_type").asString(null);
		} catch (Exception e) {
			return null;
		}
	}

	private synchronized String ensureSession() {
		if (sessionId != null) return sessionId;
		if (sessionTried) return null;
		sessionTried = true;
		try {
			String credentials = Base64.getEncoder().encodeToString(
					(username + ":" + password).getBytes());
			HttpRequest req = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl + "/api/session"))
					.POST(HttpRequest.BodyPublishers.ofString(""))
					.header("Authorization", "Basic " + credentials)
					.header("Content-Type", "application/json")
					.timeout(Duration.ofSeconds(30))
					.build();
			HttpResponse<String> resp = httpClient.send(req,
					HttpResponse.BodyHandlers.ofString());
			if (resp.statusCode() != 200 && resp.statusCode() != 201) {
				String et = errorType(resp.body());
				sessionFailure = "vami-session: POST /api/session HTTP "
						+ resp.statusCode() + (et != null ? " " + et : "");
				warnOnce("session", "VAMI " + baseUrl + ": " + sessionFailure);
				return null;
			}
			String body = resp.body();
			if (body != null) {
				body = body.trim();
				if (body.startsWith("\"") && body.endsWith("\"")
						&& body.length() >= 2) {
					body = body.substring(1, body.length() - 1);
				}
			}
			if (body == null || body.isEmpty()) {
				sessionFailure = "vami-session: empty session token";
				warnOnce("session", "VAMI " + baseUrl + ": " + sessionFailure);
				return null;
			}
			sessionId = body;
			return sessionId;
		} catch (Exception e) {
			sessionFailure = "vami-session: " + e.getClass().getSimpleName()
					+ ": " + e.getMessage();
			warnOnce("session", "VAMI " + baseUrl + ": " + sessionFailure);
			return null;
		}
	}

	private synchronized SimpleJson getEndpoint(String appliancePath) {
		Object cached = pathCache.get(appliancePath);
		if (cached instanceof SimpleJson) return (SimpleJson) cached;
		if (pathFailure.containsKey(appliancePath)) return null;

		String session = ensureSession();
		if (session == null) {
			pathFailure.put(appliancePath, sessionFailure);
			return null;
		}
		try {
			HttpRequest req = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl + "/api/appliance/" + appliancePath))
					.GET()
					.header("vmware-api-session-id", session)
					.header("Accept", "application/json")
					.timeout(Duration.ofSeconds(30))
					.build();
			HttpResponse<String> resp = httpClient.send(req,
					HttpResponse.BodyHandlers.ofString());
			// Only a 200 yields a value; 401/403/404/5xx fold to UNREADABLE
			// upstream, never "disabled / compliant".
			if (resp.statusCode() != 200) {
				String et = errorType(resp.body());
				String reason = "vami-http-" + resp.statusCode() + ": GET "
						+ appliancePath + (et != null ? " " + et : "");
				pathFailure.put(appliancePath, reason);
				warnOnce("get:" + appliancePath, "VAMI " + baseUrl + ": " + reason);
				return null;
			}
			SimpleJson parsed = SimpleJson.parse(resp.body());
			if (parsed == null) {
				String reason = "vami-parse: GET " + appliancePath
						+ " body is not JSON";
				pathFailure.put(appliancePath, reason);
				warnOnce("get:" + appliancePath, "VAMI " + baseUrl + ": " + reason);
				return null;
			}
			pathCache.put(appliancePath, parsed);
			return parsed;
		} catch (Exception e) {
			String reason = "vami-exception: GET " + appliancePath + " "
					+ e.getClass().getSimpleName() + ": " + e.getMessage();
			pathFailure.put(appliancePath, reason);
			warnOnce("get:" + appliancePath, "VAMI " + baseUrl + ": " + reason);
			return null;
		}
	}

	/**
	 * Read one field. Returns the value (Boolean / String; "" for an empty
	 * list), or {@link #FAILED} when the read failed or the field is absent
	 * ({@link #failureReason} / the returned reason say why).
	 */
	Object readField(String appliancePath, String field) {
		return readField(VamiRecipe.parse("vami:" + appliancePath + ":" + field));
	}

	/**
	 * Build 76: read one recipe, honouring its absent default
	 * ({@link VamiRecipe#absentValue}) for a field missing from a successful
	 * JSON-object body. HTTP / session failures and non-object bodies stay
	 * {@link #FAILED}.
	 */
	Object readField(VamiRecipe recipe) {
		if (recipe == null) return FAILED;
		String appliancePath = recipe.appliancePath;
		String field = recipe.field;
		SimpleJson body = getEndpoint(appliancePath);
		if (body == null) {
			return FAILED;
		}
		if (VamiRecipe.SELF_LIST.equals(field)) {
			if (!body.isList()) {
				absent(appliancePath, field, "body is not a list");
				return FAILED;
			}
			return VamiRecipe.listValue(texts(body));
		}
		SimpleJson node;
		if (VamiRecipe.SELF_VALUE.equals(field)) {
			node = body;
		} else {
			node = body.isObject() ? body.path(field) : null;
		}
		if (node == null || node.isNull()) {
			// Field absent in a successful response: UNREADABLE, never a
			// guessed default, unless the recipe declares the vendor-defined
			// meaning of absence (build 76, `?absent=`).
			Object dflt = recipe.absentValue(body.isObject());
			if (dflt != null) return dflt;
			absent(appliancePath, field, "field '" + field + "' absent");
			return FAILED;
		}
		if (node.isList()) {
			return VamiRecipe.listValue(texts(node));
		}
		Object v = VamiRecipe.scalarValue(node.asString());
		if (v == null) {
			absent(appliancePath, field,
					"field '" + field + "' has no scalar value");
			return FAILED;
		}
		return v;
	}

	private synchronized void absent(String appliancePath, String field,
			String what) {
		String reason = "vami-field-missing: GET " + appliancePath + " " + what;
		pathFailure.put(appliancePath + "#" + field, reason);
		warnOnce("field:" + appliancePath + "#" + field,
				"VAMI " + baseUrl + ": " + reason);
	}

	/** Why a FAILED from {@link #readField}(path, field) happened. */
	synchronized String failureReason(String appliancePath, String field) {
		String r = pathFailure.get(appliancePath);
		return r != null ? r : pathFailure.get(appliancePath + "#" + field);
	}

	private static java.util.List<String> texts(SimpleJson list) {
		java.util.List<String> out = new java.util.ArrayList<>();
		for (SimpleJson item : list.asList()) {
			out.add(item == null ? "" : item.asString());
		}
		return out;
	}

	/**
	 * Build 74: end the appliance session (it used to leak one idle session
	 * per vCenter per cycle). Best effort, never throws.
	 */
	synchronized void close() {
		String sid = sessionId;
		sessionId = null;
		if (sid == null) return;
		try {
			HttpRequest req = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl + "/api/session"))
					.method("DELETE", HttpRequest.BodyPublishers.noBody())
					.header("vmware-api-session-id", sid)
					.timeout(Duration.ofSeconds(10))
					.build();
			httpClient.send(req, HttpResponse.BodyHandlers.discarding());
		} catch (Exception ignored) {
			// idle expiry is the safety net
		}
	}
}
