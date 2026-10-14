package com.vcfcf.adapters.compliance;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Build 95: a minimal vim25 /sdk endpoint on a local plain-HTTP port for
 * the VSphereClient tests (JDK HttpServer, no network, no SDK). It answers
 * the session calls itself and hands everything else to {@link #handler},
 * recording every request (SOAPAction, body, client port, cookie).
 *
 * <p>Sessions: Login issues a fresh cookie; {@link #expireSessions} makes
 * every issued cookie invalid, after which any authenticated call answers
 * a NotAuthenticated fault, as vCenter does when a session lapses. Like
 * vCenter, RetrieveServiceContent already sets a vmware_soap_session cookie,
 * which is not authenticated until Login succeeds (review W3).
 * {@link #loginFails} makes Login answer InvalidLogin (a bad credential).
 */
final class FakeVCenter implements AutoCloseable {

	static {
		// The JDK HttpServer writes response headers and body as separate
		// TCP segments; with Nagle on, a kept-alive client then waits for
		// its delayed ACK (about 40 ms a call). Measured 2026-10-14: 44 ms
		// per call reused vs 2.7 ms per new connection with Nagle, about
		// 4 ms either way with TCP_NODELAY. The stall is this test server's,
		// not the client's, so the fake turns Nagle off like a production
		// proxy would.
		System.setProperty("sun.net.httpserver.nodelay", "true");
	}

	static final class Req {
		final String action;
		final String body;
		final int clientPort;
		final String cookie;

		Req(String action, String body, int clientPort, String cookie) {
			this.action = action;
			this.body = body;
			this.clientPort = clientPort;
			this.cookie = cookie;
		}
	}

	/** A canned answer: HTTP status, the Body's inner XML, close flag. */
	static final class Resp {
		final int status;
		final String inner;
		boolean close;

		Resp(int status, String inner) {
			this.status = status;
			this.inner = inner;
		}

		Resp closing() {
			close = true;
			return this;
		}
	}

	final List<Req> requests = Collections.synchronizedList(new ArrayList<>());
	final Set<String> validCookies = Collections.synchronizedSet(new HashSet<>());
	volatile Function<Req, Resp> handler = r -> fault("NotImplemented", "");
	/** Review W3: Login answers InvalidLogin while true. */
	volatile boolean loginFails;
	/** Review W4: Logout waits this long before answering. */
	volatile long logoutDelayMs;
	private final HttpServer server;
	private int sessions;

	FakeVCenter() throws Exception {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/sdk", this::serve);
		// Review W4: requests are served concurrently, so a handler can
		// make another client call (a disconnect from "another thread")
		// while it is answering one.
		server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(
				r -> {
					Thread t = new Thread(r, "fake-vcenter");
					t.setDaemon(true);
					return t;
				}));
		server.start();
	}

	String url() {
		return "http://127.0.0.1:" + server.getAddress().getPort() + "/sdk";
	}

	VSphereClient client() {
		return new VSphereClient(url(), "user", "pass", null, null, true);
	}

	void expireSessions() {
		validCookies.clear();
	}

	int count(String action) {
		int n = 0;
		synchronized (requests) {
			for (Req r : requests) {
				if (r.action.equals("urn:vim25/" + action)) n++;
			}
		}
		return n;
	}

	List<Req> of(String action) {
		List<Req> out = new ArrayList<>();
		synchronized (requests) {
			for (Req r : requests) {
				if (r.action.equals("urn:vim25/" + action)) out.add(r);
			}
		}
		return out;
	}

	@Override
	public void close() {
		server.stop(0);
		((java.util.concurrent.ExecutorService) server.getExecutor())
				.shutdownNow();
	}

	private void serve(HttpExchange ex) throws java.io.IOException {
		String action = ex.getRequestHeaders().getFirst("SOAPAction");
		String cookie = ex.getRequestHeaders().getFirst("Cookie");
		String body = new String(readAll(ex.getRequestBody()),
				StandardCharsets.UTF_8);
		Req req = new Req(action == null ? "" : action, body,
				ex.getRemoteAddress().getPort(), cookie);
		requests.add(req);
		Resp resp;
		String op = req.action.replace("urn:vim25/", "");
		if (op.equals("RetrieveServiceContent")) {
			resp = ok(op, "<returnval>"
					+ "<rootFolder type=\"Folder\">group-d1</rootFolder>"
					+ "<propertyCollector type=\"PropertyCollector\">"
					+ "propertyCollector</propertyCollector>"
					+ "<viewManager type=\"ViewManager\">ViewManager</viewManager>"
					+ "<setting type=\"OptionManager\">VpxSettings</setting>"
					+ "<sessionManager type=\"SessionManager\">SessionManager"
					+ "</sessionManager>"
					+ "<about><fullName>Fake vCenter</fullName>"
					+ "<version>9.0.0</version>"
					+ "<instanceUuid>uuid-1</instanceUuid></about>"
					+ "</returnval>");
			// vCenter sets the (not yet authenticated) session cookie here.
			ex.getResponseHeaders().add("Set-Cookie",
					"vmware_soap_session=\"anon\"; Path=/; HttpOnly");
		} else if (op.equals("Login") && loginFails) {
			resp = fault("InvalidLogin", "Cannot complete login due to an "
					+ "incorrect user name or password.");
		} else if (op.equals("Login")) {
			String c;
			synchronized (this) {
				c = "vmware_soap_session=\"s" + (++sessions) + "\"";
			}
			validCookies.add(c);
			ex.getResponseHeaders().add("Set-Cookie", c + "; Path=/; HttpOnly");
			resp = ok(op, "<returnval><key>k</key></returnval>");
		} else if (cookie == null || !validCookies.contains(cookie)) {
			resp = fault("NotAuthenticated", "The session is not authenticated.");
		} else if (op.equals("CurrentTime")) {
			resp = ok(op, "<returnval>2026-10-14T00:00:00Z</returnval>");
		} else if (op.equals("CreateContainerView")) {
			resp = ok(op, "<returnval type=\"ContainerView\">session[1]view</returnval>");
		} else if (op.equals("Logout")) {
			// vCenter ends the session: its cookie is no longer valid.
			if (logoutDelayMs > 0) {
				try {
					Thread.sleep(logoutDelayMs);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			validCookies.remove(cookie);
			resp = ok(op, "");
		} else if (op.equals("DestroyView")
				|| op.equals("CancelRetrievePropertiesEx")) {
			resp = ok(op, "");
		} else {
			resp = handler.apply(req);
		}
		byte[] out = envelope(resp.inner).getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().add("Content-Type", "text/xml; charset=utf-8");
		if (resp.close) ex.getResponseHeaders().add("Connection", "close");
		ex.sendResponseHeaders(resp.status, out.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(out);
		}
		if (resp.close) ex.close();
	}

	static Resp ok(String op, String inner) {
		return new Resp(200, "<" + op + "Response xmlns=\"urn:vim25\">" + inner
				+ "</" + op + "Response>");
	}

	static Resp fault(String type, String message) {
		return new Resp(500, "<soapenv:Fault><faultcode>ServerFaultCode"
				+ "</faultcode><faultstring>" + message + "</faultstring>"
				+ "<detail><" + type + "Fault xmlns=\"urn:vim25\" "
				+ "xsi:type=\"" + type + "\"/></detail></soapenv:Fault>");
	}

	static Resp invalidProperty(String path) {
		return new Resp(500, "<soapenv:Fault><faultcode>ServerFaultCode"
				+ "</faultcode><faultstring/><detail><InvalidPropertyFault "
				+ "xmlns=\"urn:vim25\" xsi:type=\"InvalidProperty\"><name>"
				+ path + "</name></InvalidPropertyFault></detail>"
				+ "</soapenv:Fault>");
	}

	static String envelope(String inner) {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org"
				+ "/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/"
				+ "XMLSchema-instance\"><soapenv:Body>" + inner
				+ "</soapenv:Body></soapenv:Envelope>";
	}

	private static final Pattern PATHSET = Pattern.compile(
			"<pathSet>([^<]*)</pathSet>");
	private static final Pattern OBJ = Pattern.compile(
			"<obj type=\"([^\"]*)\">([^<]*)</obj>");
	private static final Pattern TAG = Pattern.compile("<(\\w+)>([^<]*)</\\1>");

	static List<String> pathSets(String body) {
		List<String> out = new ArrayList<>();
		Matcher m = PATHSET.matcher(body);
		while (m.find()) out.add(m.group(1));
		return out;
	}

	/** {type, value} of the request's objectSet obj. */
	static String[] obj(String body) {
		Matcher m = OBJ.matcher(body);
		return m.find() ? new String[] {m.group(1), m.group(2)} : null;
	}

	static String tag(String body, String name) {
		Matcher m = TAG.matcher(body);
		while (m.find()) {
			if (m.group(1).equals(name)) return m.group(2);
		}
		return null;
	}

	/** An ObjectContent: obj plus one propSet per entry (raw val XML). */
	static String objectContent(String elem, String type, String moid,
			Map<String, String> vals) {
		StringBuilder b = new StringBuilder("<" + elem + "><obj type=\"" + type
				+ "\">" + moid + "</obj>");
		for (Map.Entry<String, String> e : vals.entrySet()) {
			b.append("<propSet><name>").append(e.getKey()).append("</name>")
					.append(e.getValue()).append("</propSet>");
		}
		return b.append("</").append(elem).append(">").toString();
	}

	static Map<String, String> vals(String... kv) {
		Map<String, String> m = new LinkedHashMap<>();
		for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
		return m;
	}

	static Map<String, String> map(String... kv) {
		Map<String, String> m = new HashMap<>();
		for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
		return m;
	}

	private static byte[] readAll(InputStream is) throws java.io.IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		byte[] buf = new byte[8192];
		int n;
		while ((n = is.read(buf)) >= 0) b.write(buf, 0, n);
		return b.toByteArray();
	}
}
