package com.vcfcf.adapters.compliance;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Build 85: the esxcli result cache is per cycle, not per vCenter session.
 * Build 86: per-host negative entry within a cycle, and the reviewer's
 * surviving mutations (build 85 review N1).
 *
 * <p>Before build 85 the cache lived as long as the SOAP session, which the
 * per-cycle keepalive can hold open indefinitely, so a host's first esxcli
 * answer (a pass or a failure) could be served cycle after cycle. A stale
 * pass is a false pass. This pins:
 * <ul>
 *   <li>within one cycle, two recipes on the same host and command cost one
 *       call, and a second command on the same host is its own call with its
 *       own value (the cache key carries the command);</li>
 *   <li>the executer lookup is cached for the cycle and done again after
 *       {@code beginCycle};</li>
 *   <li>after {@code beginCycle}, the same read fetches again and sees the
 *       host's current value;</li>
 *   <li>a FAILED read is retried in the next cycle and does not survive;</li>
 *   <li>build 86: after a transport failure (timeout, refused connection)
 *       or a missing executer on a host, its other commands fail at once
 *       with no network call and the first failure as their reason; a fault
 *       the host answered with fails that command only; other hosts are
 *       unaffected; the next cycle tries the host again;</li>
 *   <li>the cycle-start wiring: {@code EsxcliSoapClient.beginCycleOn} is
 *       null-safe and clears, {@code VSphereClient.beginCycle} is exactly
 *       that call, and the adapter's cycle body starts with
 *       {@code ensureConnected()} then {@code beginCycle()}. The last two
 *       are source-level checks, because VSphereClient and ComplianceAdapter
 *       need the VCF Ops SDK jar, which this runner keeps off the
 *       classpath.</li>
 *   <li>build 87 (build 86 review N3 and W1): the reason label a
 *       {@code COMMAND_FAILED} read gets ({@code esxcli-host-unreachable}
 *       for a marked host, {@code esxcli-command-failed} otherwise), that
 *       VSphereClient's esxcli read uses it with the host's entry, and that
 *       a marked host is handed to the adapter's WARN once per cycle.</li>
 * </ul>
 * No network: calls go through the client's transport seam. Run from the
 * repo root.
 */
public final class EsxcliCycleCacheTest {

	private static final String HOST = "host-12";
	private static final String OTHER = "host-13";
	private static final String CMD = "system.syslog.config.get";
	private static final String CMD2 = "system.settings.encryption.get";
	private static final String CMD3 = "system.ssh.server.config.list";

	/** Scripted transport: counts calls, fails on demand. */
	static final class Fake implements EsxcliSoapClient.Transport {
		final AtomicInteger lookups = new AtomicInteger();
		final AtomicInteger executes = new AtomicInteger();
		final Map<String, Map<String, String>> live = new HashMap<>();
		final Map<String, Exception> lookupThrows = new HashMap<>();
		final Map<String, Boolean> noExecuter = new HashMap<>();
		final Map<String, Exception> executeThrows = new HashMap<>();
		final Map<String, Boolean> faultAnswer = new HashMap<>();

		@Override
		public String lookupExecuter(String hostMoid) throws Exception {
			lookups.incrementAndGet();
			Exception e = lookupThrows.get(hostMoid);
			if (e != null) throw e;
			if (Boolean.TRUE.equals(noExecuter.get(hostMoid))) return null;
			return "exec-" + hostMoid;
		}

		@Override
		public EsxcliSoapClient.ParsedResult execute(String executer,
				String cmd) throws Exception {
			executes.incrementAndGet();
			String host = executer.substring("exec-".length());
			Exception e = executeThrows.get(host + "|" + cmd);
			if (e == null) e = executeThrows.get(host + "|*");
			if (e != null) throw e;
			if (Boolean.TRUE.equals(faultAnswer.get(host + "|" + cmd))) {
				return EsxcliSoapClient.ParsedResult.ofFailure();
			}
			Map<String, String> v = live.get(cmd);
			return EsxcliSoapClient.ParsedResult.ofStruct(
					new HashMap<>(v != null ? v : new HashMap<>()));
		}
	}

	public static void main(String[] args) throws Exception {
		cachePerCycle();
		hostNegativeEntry();
		cycleStartWiring();
		unreachableReasonAndReport();
		System.out.println("EsxcliCycleCacheTest: all assertions passed");
	}

	private static void cachePerCycle() {
		Fake t = new Fake();
		Map<String, String> syslog = new HashMap<>();
		syslog.put("LocalLogOutputIsPersistent", "true");
		syslog.put("LogDir", "/scratch/log");
		t.live.put(CMD, syslog);
		Map<String, String> enc = new HashMap<>();
		enc.put("Mode", "TPM");
		t.live.put(CMD2, enc);
		EsxcliSoapClient c = new EsxcliSoapClient(t);

		// ---- cycle 1: two recipes, same host and command, one call
		c.beginCycle();
		T.eq("true", c.readField(HOST, CMD, "LocalLogOutputIsPersistent"),
				"cycle 1 first recipe");
		T.eq("/scratch/log", c.readField(HOST, CMD, "LogDir"),
				"cycle 1 second recipe");
		T.eq(1, t.executes.get(), "same host and command fetched once per cycle");
		T.eq(1, t.lookups.get(), "one executer lookup for the host");
		// A second command on the same host: its own call and its own value
		// (a cache key that ignored the command would serve CMD's struct).
		T.eq("TPM", c.readField(HOST, CMD2, "Mode"),
				"cycle 1 second command reads its own result");
		T.eq(null, c.readField(HOST, CMD2, "LogDir"),
				"second command does not carry the first command's fields");
		T.eq(2, t.executes.get(), "a second command is its own call");
		T.eq(1, t.lookups.get(), "executer cached within the cycle");
		c.readField(OTHER, CMD, "LogDir");
		T.eq(3, t.executes.get(), "another host is its own call");
		T.eq(2, t.lookups.get(), "another host is its own executer lookup");

		// ---- cycle 2: the host drifted; the new value must be read
		syslog.put("LocalLogOutputIsPersistent", "false");
		c.beginCycle();
		T.eq("false", c.readField(HOST, CMD, "LocalLogOutputIsPersistent"),
				"cycle 2 re-reads and sees the drift (no stale pass)");
		T.eq(4, t.executes.get(), "cycle 2 fetched again");
		T.eq(3, t.lookups.get(),
				"cycle 2 looks the executer up again (executer cache cleared)");
		c.readField(HOST, CMD, "LogDir");
		T.eq(4, t.executes.get(), "cycle 2 still dedupes within the cycle");

		// ---- cycle 3: the host answers with a fault for CMD; cached failure
		t.faultAnswer.put(HOST + "|" + CMD, true);
		c.beginCycle();
		T.eq(EsxcliSoapClient.COMMAND_FAILED,
				c.readField(HOST, CMD, "LogDir"), "cycle 3 read failed");
		c.readField(HOST, CMD, "LocalLogOutputIsPersistent");
		T.eq(5, t.executes.get(), "a failed read is not retried within the cycle");

		// ---- cycle 4: the host is back; the cached failure must not survive
		t.faultAnswer.clear();
		c.beginCycle();
		T.eq("false", c.readField(HOST, CMD, "LocalLogOutputIsPersistent"),
				"cycle 4 reads the host again after last cycle's failure");
		T.eq(6, t.executes.get(), "cycle 4 fetched again");

		// ---- without beginCycle the cache holds (the pre-build-85 behavior)
		syslog.put("LocalLogOutputIsPersistent", "true");
		T.eq("false", c.readField(HOST, CMD, "LocalLogOutputIsPersistent"),
				"same cycle still serves the cached value");
		T.eq(6, t.executes.get(), "no fetch without a new cycle");
	}

	private static void hostNegativeEntry() {
		Fake t = new Fake();
		Map<String, String> v = new HashMap<>();
		v.put("Mode", "TPM");
		t.live.put(CMD, v);
		t.live.put(CMD2, v);
		t.live.put(CMD3, v);
		EsxcliSoapClient c = new EsxcliSoapClient(t);

		// ---- a timeout on ExecuteSoap: the host's other commands are skipped
		c.beginCycle();
		t.executeThrows.put(HOST + "|*",
				new java.net.SocketTimeoutException("Read timed out"));
		T.eq(EsxcliSoapClient.COMMAND_FAILED, c.readField(HOST, CMD, "Mode"),
				"timed-out command is unreadable");
		T.eq(1, t.executes.get(), "the timed-out call was made once");
		T.eq(EsxcliSoapClient.COMMAND_FAILED, c.readField(HOST, CMD2, "Mode"),
				"second command on the hung host is unreadable");
		T.eq(EsxcliSoapClient.COMMAND_FAILED,
				c.readRowField(HOST, CMD3, "Key", "ciphers", "Value"),
				"row read on the hung host is unreadable");
		T.eq(1, t.executes.get(),
				"no further calls to a host that timed out this cycle");
		T.eq(1, t.lookups.get(), "no further executer lookups either");
		String why = c.unreachableReason(HOST);
		T.check(why != null && why.contains("SocketTimeoutException")
				&& why.contains("Read timed out"),
				"the first failure is kept as the reason: " + why);
		// Other hosts are unaffected in the same cycle.
		T.eq("TPM", c.readField(OTHER, CMD, "Mode"), "other host still read");
		T.eq(null, c.unreachableReason(OTHER), "other host not marked");

		// ---- next cycle: the host is tried again and read
		t.executeThrows.clear();
		c.beginCycle();
		T.eq(null, c.unreachableReason(HOST), "beginCycle clears the entry");
		T.eq("TPM", c.readField(HOST, CMD2, "Mode"),
				"host read again in the next cycle");

		// ---- a refused connection on the executer lookup marks the host
		c.beginCycle();
		int lookups = t.lookups.get();
		int executes = t.executes.get();
		t.lookupThrows.put(HOST, new java.net.ConnectException(
				"Connection refused"));
		c.readField(HOST, CMD, "Mode");
		c.readField(HOST, CMD2, "Mode");
		T.eq(lookups + 1, t.lookups.get(),
				"one lookup for a host whose connection was refused");
		T.eq(executes, t.executes.get(), "no command was executed");
		T.check(c.unreachableReason(HOST).startsWith("ConnectException"),
				"reason names the connect failure");
		t.lookupThrows.clear();

		// ---- no executer returned (a fault): the host is skipped too
		c.beginCycle();
		lookups = t.lookups.get();
		t.noExecuter.put(HOST, true);
		c.readField(HOST, CMD, "Mode");
		c.readField(HOST, CMD2, "Mode");
		T.eq(lookups + 1, t.lookups.get(),
				"one lookup for a host with no executer");
		T.check(c.unreachableReason(HOST) != null,
				"a missing executer marks the host");
		t.noExecuter.clear();

		// ---- a fault the host answered with fails that command only
		c.beginCycle();
		executes = t.executes.get();
		t.faultAnswer.put(HOST + "|" + CMD, true);
		T.eq(EsxcliSoapClient.COMMAND_FAILED, c.readField(HOST, CMD, "Mode"),
				"faulted command is unreadable");
		T.eq("TPM", c.readField(HOST, CMD2, "Mode"),
				"another command on the same host is still read");
		T.eq(executes + 2, t.executes.get(), "both commands were executed");
		T.eq(null, c.unreachableReason(HOST),
				"an answered fault does not mark the host");
		t.faultAnswer.clear();

		// ---- a non-I/O exception fails that command only
		c.beginCycle();
		executes = t.executes.get();
		t.executeThrows.put(HOST + "|" + CMD,
				new IllegalStateException("parse"));
		c.readField(HOST, CMD, "Mode");
		T.eq("TPM", c.readField(HOST, CMD2, "Mode"),
				"non-I/O failure does not skip the host");
		T.eq(null, c.unreachableReason(HOST), "non-I/O failure not marked");
		t.executeThrows.clear();

		// ---- the reason is one line and capped
		StringBuilder longMsg = new StringBuilder("line one\nline two ");
		for (int i = 0; i < 50; i++) longMsg.append("0123456789");
		String d = EsxcliSoapClient.describe(
				new java.io.IOException(longMsg.toString()));
		T.check(!d.contains("\n"), "reason is one line");
		T.check(d.length() <= "IOException: ".length()
				+ EsxcliSoapClient.REASON_MESSAGE_MAX + 3,
				"reason message is capped: " + d.length());
	}

	private static void cycleStartWiring() throws Exception {
		// The helper the adapter goes through: null-safe, and it clears.
		EsxcliSoapClient.beginCycleOn(null);
		Fake t = new Fake();
		Map<String, String> v = new HashMap<>();
		v.put("Mode", "TPM");
		t.live.put(CMD, v);
		EsxcliSoapClient c = new EsxcliSoapClient(t);
		c.readField(HOST, CMD, "Mode");
		EsxcliSoapClient.beginCycleOn(c);
		c.readField(HOST, CMD, "Mode");
		T.eq(2, t.executes.get(), "beginCycleOn starts a new cycle");

		// VSphereClient.beginCycle is exactly that call (SDK class: source).
		String vs = read("src/com/vcfcf/adapters/compliance/VSphereClient.java");
		T.eq("EsxcliSoapClient.beginCycleOn(esxcli);",
				body(vs, "public void beginCycle()"),
				"VSphereClient.beginCycle delegates to beginCycleOn");

		// The adapter's cycle body starts with ensureConnected, beginCycle.
		String ca = read("src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");
		String cycle = body(ca, "private void collectWorldCycle(");
		String[] stmts = cycle.split(";");
		T.check(stmts.length > 2, "cycle body has statements");
		T.eq("vsphere.ensureConnected()", stmts[0].trim(),
				"cycle body statement 1");
		T.eq("vsphere.beginCycle()", stmts[1].trim(),
				"cycle body statement 2 (before any read)");
		T.check(body(ca, "private void collectWorld(")
				.contains("collectWorldCycle(worldRc, out);"),
				"collectWorld runs the cycle body");
	}

	private static void unreachableReasonAndReport() throws Exception {
		// ---- the label (review N3: VSphereClient chose it, untested)
		String r = EsxcliSoapClient.commandFailedReason(CMD,
				"SocketTimeoutException: Read timed out", "ignored fault");
		T.check(r.startsWith("esxcli-host-unreachable: " + CMD + " "),
				"marked host gets esxcli-host-unreachable: " + r);
		T.check(r.contains("SocketTimeoutException: Read timed out"),
				"the first cause is in the reason: " + r);
		T.check(!r.contains("ignored fault"),
				"a marked host's reason is the first cause, not the fault");
		r = EsxcliSoapClient.commandFailedReason(CMD, null, "ServerFault");
		T.eq("esxcli-command-failed: " + CMD + " (ServerFault)", r,
				"unmarked host gets esxcli-command-failed with the fault");
		r = EsxcliSoapClient.commandFailedReason(CMD, null, null);
		T.eq("esxcli-command-failed: " + CMD, r,
				"no fault text: label and command only");

		// VSphereClient's esxcli read passes the host's entry to the helper
		// (SDK class: source).
		String vs = read("src/com/vcfcf/adapters/compliance/VSphereClient.java");
		String esx = body(vs, "private Object readEsxcliRecipe(");
		T.check(esx.contains("readFailure = EsxcliSoapClient.commandFailedReason("
				+ " namespaceCommand, esxcli.unreachableReason(hostMoid),"
				+ " lastFault);"),
				"VSphereClient labels a failed read through the helper with"
				+ " the host's unreachable entry");

		// ---- the WARN hand-off: once per host per cycle (review W1)
		Fake t = new Fake();
		Map<String, String> v = new HashMap<>();
		v.put("Mode", "TPM");
		t.live.put(CMD, v);
		t.live.put(CMD2, v);
		EsxcliSoapClient c = new EsxcliSoapClient(t);
		c.beginCycle();
		T.eq(null, c.takeUnreachableToReport(HOST),
				"unmarked host: nothing to report");
		t.executeThrows.put(HOST + "|*",
				new java.net.SocketTimeoutException("Read timed out"));
		c.readField(HOST, CMD, "Mode");
		c.readField(HOST, CMD2, "Mode");
		String first = c.takeUnreachableToReport(HOST);
		T.check(first != null && first.contains("SocketTimeoutException"),
				"marked host is reported with its cause: " + first);
		T.eq(null, c.takeUnreachableToReport(HOST),
				"second ask in the same cycle: not reported again");
		T.check(c.unreachableReason(HOST) != null,
				"reporting does not clear the entry");
		T.eq(null, c.takeUnreachableToReport(OTHER),
				"other host not reported");
		c.beginCycle();
		T.eq(null, c.takeUnreachableToReport(HOST),
				"next cycle, host not marked again yet: nothing to report");
		c.readField(HOST, CMD, "Mode");
		T.check(c.takeUnreachableToReport(HOST) != null,
				"marked again next cycle: reported again");

		T.check(body(vs, "public String takeEsxcliUnreachable(")
				.contains("c.takeUnreachableToReport(hostMoid)"),
				"VSphereClient hands the once-per-cycle entry to the adapter");
		String ca = read("src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");
		String hosts = body(ca, "private java.util.Map<String, String> collectHosts(");
		T.check(hosts.contains("vsphere.takeEsxcliUnreachable(hostId)"),
				"the host loop asks for the entry");
		T.check(hosts.contains("if (esxcliUnreachable != null) { logWarn("),
				"the host loop WARNs on it");
		T.check(hosts.contains("ComplianceDecisions.hostScoreLineAtInfo("
				+ " cr.unreadableCount)) { logInfo(line); } else {"
				+ " logDebug(line); }"),
				"the per-host score line level follows hostScoreLineAtInfo");
	}

	private static String read(String path) throws Exception {
		return new String(Files.readAllBytes(Paths.get(path)),
				StandardCharsets.UTF_8);
	}

	/**
	 * The body of the first method whose declaration starts with
	 * {@code signature}, comments removed and whitespace collapsed. Brace
	 * matching ignores braces in strings, which these bodies do not need.
	 */
	private static String body(String src, String signature) {
		int at = src.indexOf(signature);
		T.check(at >= 0, "found " + signature);
		int open = src.indexOf('{', at);
		int depth = 0;
		int i = open;
		for (; i < src.length(); i++) {
			char ch = src.charAt(i);
			if (ch == '{') depth++;
			else if (ch == '}' && --depth == 0) break;
		}
		String b = src.substring(open + 1, i);
		b = b.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("//[^\\n]*", "");
		return b.replaceAll("\\s+", " ").trim();
	}
}
