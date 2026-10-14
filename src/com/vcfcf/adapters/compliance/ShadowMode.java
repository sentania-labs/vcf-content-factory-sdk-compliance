package com.vcfcf.adapters.compliance;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Build 95 (decision 2026-10-14, point 6): whether the bulk-read shadow
 * comparison runs. On in a dev-preview build (version 0.0.0.N), off in a
 * tagged release (1.0.0.N), through this one internal switch. Not a user
 * setting. SDK-free.
 *
 * <p>The build's own version decides it at runtime. Every pak the
 * factory builds writes {@code conf/version.txt} next to describe.xml
 * (sdk_builder {@code _generate_version_txt}, the file the collector reads
 * to log the adapter version): a dev preview stamps Major-Version 0,
 * Minor-Version 0 and Implementation-Version 0.N; a release build (the
 * pak repo's CI on a v* tag) stamps the adapter.yaml version, 1.0.0.N.
 * A runtime read of that file is reliable because it is the same stamp
 * the pak's filename and manifest carry; a build-time flag would need a
 * builder change and could drift from the stamp.
 *
 * <p>Fail safe: anything other than a readable 0.0.0.N stamp (no file, an
 * unreadable file, a missing field, any other version) is OFF, so a
 * release never runs the shadow reads by accident.
 */
public final class ShadowMode {

	/** The version file the factory builder writes beside describe.xml. */
	public static final String VERSION_FILE = "version.txt";

	private ShadowMode() {}

	/** The decision and the version it was taken from, for the log. */
	public static final class Decision {
		public final boolean enabled;
		/** e.g. "0.0.0.95"; null when the stamp could not be read. */
		public final String version;
		/** Why, in words, for the one INFO line per change. */
		public final String why;

		Decision(boolean enabled, String version, String why) {
			this.enabled = enabled;
			this.version = version;
			this.why = why;
		}
	}

	/** The version string of a version.txt text, or null when incomplete. */
	public static String version(String versionTxt) {
		if (versionTxt == null) return null;
		Properties p = new Properties();
		try {
			p.load(new StringReader(versionTxt));
		} catch (IOException | IllegalArgumentException e) {
			return null;
		}
		String major = trim(p.getProperty("Major-Version"));
		String minor = trim(p.getProperty("Minor-Version"));
		String impl = trim(p.getProperty("Implementation-Version"));
		if (major == null || minor == null || impl == null) return null;
		return major + "." + minor + "." + impl;
	}

	/** True only for a dev-preview stamp: 0.0.0.N with N a number. */
	public static boolean isDevPreview(String version) {
		return version != null && version.matches("0\\.0\\.0\\.\\d+");
	}

	/** The decision for one version.txt text (null: no file). */
	public static Decision decide(String versionTxt) {
		if (versionTxt == null) {
			return new Decision(false, null, "no " + VERSION_FILE
					+ " beside describe.xml: treated as a release, off");
		}
		String v = version(versionTxt);
		if (v == null) {
			return new Decision(false, null, VERSION_FILE + " has no "
					+ "complete version stamp: treated as a release, off");
		}
		if (isDevPreview(v)) {
			return new Decision(true, v, "dev-preview build " + v + ": on");
		}
		return new Decision(false, v, "release build " + v + ": off");
	}

	/**
	 * The decision for an installed adapter: reads
	 * {@code <confDir>/version.txt}. Never throws; an unreadable file is
	 * off.
	 */
	public static Decision decide(Path confDir) {
		if (confDir == null) return decide((String) null);
		Path f = confDir.resolve(VERSION_FILE);
		if (!Files.isRegularFile(f)) return decide((String) null);
		try {
			return decide(new String(Files.readAllBytes(f),
					StandardCharsets.UTF_8));
		} catch (IOException | RuntimeException e) {
			return new Decision(false, null, VERSION_FILE + " could not be "
					+ "read (" + e.getClass().getSimpleName() + "): treated "
					+ "as a release, off");
		}
	}

	private static String trim(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}
}
