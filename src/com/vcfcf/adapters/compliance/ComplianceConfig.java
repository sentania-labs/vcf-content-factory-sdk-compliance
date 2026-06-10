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

	public String baseUrl() {
		return "https://" + vcenterHost;
	}
}
