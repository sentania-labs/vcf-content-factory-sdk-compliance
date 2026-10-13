package com.vcfcf.adapters.compliance;

public final class ComplianceConfig {

	public final String vcenterHost;
	public final String username;
	public final String password;

	/**
	 * Build 93: the retired "Compliance Profile" setting. The identifier is
	 * gone from describe.xml and every instance runs
	 * {@link BenchmarkSelector#AUTO}; an account created earlier may still
	 * carry a stored value, which the adapter reads only to log
	 * {@link #retiredProfileNotice(String)} once per configure.
	 */
	public static final String RETIRED_PROFILE_KEY = "benchmark_profile";

	/**
	 * Build 93: the retired "Allow Insecure SSL" setting. The identifier is
	 * gone from describe.xml and the adapter always validates the vCenter
	 * certificate; a stored value is read only to log
	 * {@link #retiredAllowInsecureNotice(String)} once per configure.
	 */
	public static final String RETIRED_ALLOW_INSECURE_KEY = "allowInsecure";

	/**
	 * HOLD (owner decision pending, build 74): the adapter-instance setting
	 * "Read vCenter appliance settings" (identifier {@link #READ_APPLIANCE_KEY}).
	 * Off: the vCenter appliance (VAMI) controls load as manual review for
	 * this instance (not attempted, no score, no per-control alert). On: they
	 * are read and scored, which needs the collection account in the
	 * vsphere.local SSO group SystemConfiguration.Administrators (that group
	 * also grants appliance WRITE access; there is no read-only appliance
	 * role).
	 *
	 * <p>Changing the answer is a one-line default change here plus the
	 * matching {@code default=} on the describe.xml identifier. An absent or
	 * blank stored value (every instance created before build 74) takes this
	 * default.
	 */
	public static final boolean DEFAULT_READ_APPLIANCE = false;
	public static final String READ_APPLIANCE_KEY = "read_appliance_settings";
	public final boolean readApplianceSettings;

	/**
	 * Build 90: the instance setting "Overrides file" (identifier
	 * {@link #OVERRIDES_FILE_KEY}): the name of the user's copy of
	 * compliance_overrides_template in the VCF Ops configuration-file store,
	 * without path or extension. "" means no overrides and no fetch.
	 */
	public static final String OVERRIDES_FILE_KEY = "overrides_file";
	public final String overridesFile;

	public ComplianceConfig(String vcenterHost, String username, String password,
			String readApplianceSettings, String overridesFile) {
		this.overridesFile = OverridesStore.normaliseName(overridesFile);
		this.readApplianceSettings = parseReadAppliance(readApplianceSettings);
		this.vcenterHost = (vcenterHost != null && !vcenterHost.isEmpty())
				? vcenterHost : "localhost";
		this.username = (username != null) ? username : "";
		this.password = (password != null) ? password : "";
	}

	/** Build 92: the retired Custom choice, as an instance may still store it. */
	static boolean isCustomName(String raw) {
		return raw != null && "Custom".equalsIgnoreCase(raw.trim());
	}

	/**
	 * Build 93: the INFO line for an account that stored a value in the
	 * retired Compliance Profile setting, or null when there is nothing to
	 * say (absent, blank, or the Auto choice, which is what every instance
	 * now runs). Names the stored value and, for a bundled SCG version, the
	 * overrides-file entry that pins the instance to it.
	 */
	static String retiredProfileNotice(String stored) {
		if (stored == null) return null;
		String v = stored.trim();
		if (v.isEmpty() || BenchmarkSelector.AUTO.equalsIgnoreCase(v)) {
			return null;
		}
		String scg = BenchmarkSelector.scgOfProfileName(v);
		String pin = scg != null
				? " To keep scoring every object against SCG " + scg
						+ ", add <Profile version=\"SCG " + scg + "\"/> to the "
						+ "instance's overrides file (docs/overrides.md)."
				: " To pin a guide version for the whole instance, add "
						+ "<Profile version=\"SCG X.Y\"/> to the instance's "
						+ "overrides file (docs/overrides.md).";
		return "The Compliance Profile setting was removed in build 93. This "
				+ "account stored '" + v + "'; it now runs "
				+ BenchmarkSelector.AUTO + "." + pin;
	}

	/**
	 * Build 93: the WARN line for an account that stored
	 * {@code allowInsecure=true} (any case, surrounding whitespace ignored),
	 * or null for any other stored value. Such an account validated nothing
	 * before; it now validates strictly, so the line says how to accept the
	 * certificate.
	 */
	static String retiredAllowInsecureNotice(String stored) {
		if (stored == null || !"true".equalsIgnoreCase(stored.trim())) {
			return null;
		}
		return "The Allow Insecure SSL setting was removed in build 93. This "
				+ "account stored allowInsecure=true; the vCenter certificate "
				+ "is now validated against the VCF Operations trust store. If "
				+ "collection fails with a certificate error, open the account "
				+ "and click Validate Connection to review and accept the "
				+ "certificate, and enter vCenter by the name on its "
				+ "certificate.";
	}

	/** "true" / "false" (case-insensitive); anything else takes the default. */
	static boolean parseReadAppliance(String raw) {
		if (raw == null) return DEFAULT_READ_APPLIANCE;
		String v = raw.trim();
		if ("true".equalsIgnoreCase(v)) return true;
		if ("false".equalsIgnoreCase(v)) return false;
		return DEFAULT_READ_APPLIANCE;
	}

	public String baseUrl() {
		return "https://" + vcenterHost;
	}
}
