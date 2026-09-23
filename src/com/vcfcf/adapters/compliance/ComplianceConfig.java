package com.vcfcf.adapters.compliance;

public final class ComplianceConfig {

	public final String vcenterHost;
	public final String username;
	public final String password;
	public final String benchmarkProfile;
	public final String customProfilePath;
	public final boolean allowInsecure;

	public ComplianceConfig(String vcenterHost, String username, String password,
			String benchmarkProfile, String customProfilePath, String allowInsecure) {
		this.vcenterHost = (vcenterHost != null && !vcenterHost.isEmpty())
				? vcenterHost : "localhost";
		this.username = (username != null) ? username : "";
		this.password = (password != null) ? password : "";
		this.benchmarkProfile = (benchmarkProfile != null && !benchmarkProfile.isEmpty())
				? benchmarkProfile : "VMware_SCG_8.0";
		this.customProfilePath = (customProfilePath != null) ? customProfilePath.trim() : "";
		// Strict-by-default (build 50, review B1): only the explicit literal
		// "true" opts into trust-all. null / blank / absent / any other value
		// parses to false -> platform trust store validation. This makes the
		// secure default actually engage for every existing and freshly-created
		// instance (which have no allowInsecure field), matching describe.xml
		// default="false" and the documented "platform trust by default".
		this.allowInsecure = "true".equalsIgnoreCase(allowInsecure);
	}

	/**
	 * v3: true when the instance selects the benchmark per object by
	 * version ({@link BenchmarkSelector#AUTO}). A blank / absent stored value
	 * stays on the pre-v3 fallback VMware_SCG_8.0 above, NOT Auto: an
	 * existing instance keeps behaving exactly as it did until someone edits
	 * it. New instances get Auto from the describe.xml default.
	 */
	public boolean isAuto() {
		return BenchmarkSelector.AUTO.equals(benchmarkProfile);
	}

	public String baseUrl() {
		return "https://" + vcenterHost;
	}
}
