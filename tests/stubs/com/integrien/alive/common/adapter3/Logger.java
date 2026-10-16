// TEST-ONLY STUB (compliance build 96, issue #27). Never compiled into the
// pak (build-sdk compiles src/ only, against the real SDK and framework
// jars). It declares only the members the adapter source uses, so
// ci/run_java_tests.sh can compile and drive the adapter without the
// Broadcom SDK jar. No vendor code: signatures only. See tests/stubs/README.md.
package com.integrien.alive.common.adapter3;

public final class Logger {
	public static final java.util.List<String> LINES =
			java.util.Collections.synchronizedList(new java.util.ArrayList<>());
	private final String name;
	private volatile boolean debug;

	public Logger(String name) { this.name = name; }

	public static Logger getDefaultLogger(Class<?> c) {
		return new Logger(c.getSimpleName());
	}

	public enum CustomLevel { TRACE, DEBUG, INFO, WARN, ERROR }

	public void setLevel(CustomLevel l) { debug = l == CustomLevel.DEBUG
			|| l == CustomLevel.TRACE; }
	public boolean isDebugEnabled() { return debug; }
	public void debug(Object m) { if (debug) add("DEBUG", m); }
	public void info(Object m) { add("INFO", m); }
	public void warn(Object m) { add("WARN", m); }
	public void warn(Object m, Throwable t) { add("WARN", m); }
	public void error(Object m) { add("ERROR", m); }
	public void error(Object m, Throwable t) { add("ERROR", m); }

	private void add(String level, Object m) {
		LINES.add(level + " " + name + ": " + m);
	}
}
