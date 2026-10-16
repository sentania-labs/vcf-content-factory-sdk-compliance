package com.vcfcf.adapters.compliance;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Build 96 (issue #27): fixture tests for the code that could not be
 * compiled in CI before (it needed the SDK Logger or the framework).
 * Response bodies come from tests/fixtures (provenance in its README) and
 * are served through the real clients: the vim25 SOAP parser behind
 * VSphereClient, the esxcli parser behind EsxcliSoapClient (a get struct,
 * a list, an esxcli-level fault), and ComplianceStitcher's resource load
 * and matchResource (moid, exact name, FQDN / short-name tolerance,
 * cross-vCenter scoping). Run from the repo root.
 */
public final class Build96FixtureTest {

	public static void main(String[] args) throws Exception {
		hostQueryOptions();
		vmExtraConfigMissingSet();
		hostListing();
		esxcliGetListFault();
		matchResourceTable();
		System.out.println("Build96FixtureTest: all assertions passed");
	}

	static String fixture(String name) throws Exception {
		return new String(Files.readAllBytes(Paths.get("tests/fixtures", name)),
				StandardCharsets.UTF_8);
	}

	/** QueryOptions: every typed value is its text; a value-less key is absent. */
	static void hostQueryOptions() throws Exception {
		String body = fixture("soap/host-query-options.xml");
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				if (r.action.endsWith("/QueryOptions")) {
					return new FakeVCenter.Resp(200, body);
				}
				// configManager.advancedOption -> the OptionManager MoRef.
				return FakeVCenter.ok("RetrieveProperties",
						FakeVCenter.objectContent("returnval", "HostSystem",
								"host-10", FakeVCenter.vals(
										"configManager.advancedOption",
										"<val type=\"OptionManager\">"
										+ "EsxHostAdvSettings-10</val>")));
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			Map<String, String> s = c.getAdvancedSettings(
					new VSphereClient.MoRef("HostSystem", "host-10"));
			T.eq("900", s.get("UserVars.ESXiShellTimeOut"), "xsd:long");
			T.eq("5", s.get("Security.AccountLockFailures"), "xsd:int");
			T.eq("true", s.get("Net.BlockGuestBPDU"), "xsd:boolean true");
			T.eq("false", s.get("Config.HostAgent.plugins.solo.enableMob"),
					"xsd:boolean false");
			T.eq("", s.get("Syslog.global.logHost"), "empty string kept as set");
			T.check(!s.containsKey("UserVars.SuppressShellWarning"),
					"a key with no value element is not invented");
			T.eq(6, s.size(), "six settings");
			T.check(f.of("QueryOptions").get(0).body.contains(
					">EsxHostAdvSettings-10</_this>"),
					"QueryOptions sent to the host's OptionManager");
		}
	}

	/** A property in missingSet is a read fault naming the vCenter fault, never an empty map. */
	static void vmExtraConfigMissingSet() throws Exception {
		String body = fixture("soap/vm-extraconfig-missingset.xml");
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> new FakeVCenter.Resp(200, body);
			VSphereClient c = f.client();
			c.ensureConnected();
			try {
				c.getVmExtraConfig(new VSphereClient.MoRef("VirtualMachine",
						"vm-42"));
				throw new AssertionError("missingSet read as a value");
			} catch (VimOptions.ReadFault e) {
				T.check(e.getMessage().contains("NoPermission"),
						"fault type named: " + e.getMessage());
				T.check(e.getMessage().contains("config.extraConfig"),
						"property named: " + e.getMessage());
			}
		}
	}

	/** Listing: names from the listing; a row without one is read on its own. */
	static void hostListing() throws Exception {
		String body = fixture("soap/host-listing.xml");
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				String[] o = FakeVCenter.obj(r.body);
				if (o != null && "ContainerView".equals(o[0])) {
					return new FakeVCenter.Resp(200, body);
				}
				return FakeVCenter.ok("RetrieveProperties",
						FakeVCenter.objectContent("returnval", "HostSystem",
								"host-12", FakeVCenter.vals("name",
										"<val>esx03.lab.example</val>")));
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			List<VSphereClient.HostInfo> hosts = c.getHosts();
			T.eq(3, hosts.size(), "three hosts");
			T.eq("esx01.lab.example", hosts.get(0).name, "row 1 name");
			T.eq("host-10", hosts.get(0).moid, "row 1 moid");
			T.eq("esx02.lab.example", hosts.get(1).name, "row 2 name");
			T.eq("esx03.lab.example", hosts.get(2).name,
					"row without a name read on its own");
		}
	}

	/** esxcli: a get struct, a list of rows, an esxcli fault (command failed, never a value). */
	static void esxcliGetListFault() throws Exception {
		String get = fixture("esxcli/syslog-config-get.xml");
		String list = fixture("esxcli/ssh-server-config-list.xml");
		String fault = fixture("esxcli/command-fault.xml");
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				if (r.action.endsWith("/RetrieveManagedMethodExecuter")) {
					return FakeVCenter.ok("RetrieveManagedMethodExecuter",
							"<returnval type=\"ReflectManagedMethodExecuter\">"
							+ "ManagedMethodExecuter-6011</returnval>");
				}
				String method = FakeVCenter.tag(r.body, "method");
				if ("vim.EsxCLI.system.syslog.config.get".equals(method)) {
					return new FakeVCenter.Resp(200, get);
				}
				if ("vim.EsxCLI.system.ssh.server.config.list".equals(method)) {
					return new FakeVCenter.Resp(200, list);
				}
				return new FakeVCenter.Resp(200, fault);
			};
			VSphereClient vs = f.client();
			vs.ensureConnected();
			String cookie = f.of("Login").isEmpty() ? null
					: f.validCookies.iterator().next();
			EsxcliSoapClient e = new EsxcliSoapClient(f.url(), cookie, null);
			T.eq("true", e.readField("host-10", "system.syslog.config.get",
					"LocalLogOutputIsPersistent"), "get struct field");
			T.eq("/scratch/log", e.readField("host-10",
					"system.syslog.config.get", "LocalLogOutput"),
					"get struct string field");
			T.eq("true", e.readField("host-10", "system.syslog.config.get",
					"localLogOutputIsPersistent"),
					"case-insensitive field (build 74)");
			T.eq(null, e.readField("host-10", "system.syslog.config.get",
					"NoSuchField"), "absent field is null (UNREADABLE)");
			T.eq("yes", e.readRowField("host-10",
					"system.ssh.server.config.list", "Key", "ignorerhosts",
					"Value"), "list row selected by key");
			T.eq(null, e.readRowField("host-10",
					"system.ssh.server.config.list", "Key", "nosuchkey",
					"Value"), "no matching row is null (UNREADABLE)");
			T.eq(null, e.readField("host-10", "system.ssh.server.config.list",
					"Value"), "a plain field read on a list is null");
			T.eq(EsxcliSoapClient.COMMAND_FAILED, e.readField("host-10",
					"system.settings.encryption.get", "Mode"),
					"esxcli-level fault is command failed");
			int executes = f.count("ExecuteSoap");
			e.readField("host-10", "system.syslog.config.get", "LogLevel");
			T.eq(executes, f.count("ExecuteSoap"),
					"a second field of a cached command is not re-issued");
			T.eq(1, f.count("RetrieveManagedMethodExecuter"),
					"one executer lookup per host per cycle");
		}
	}

	/**
	 * matchResource, scoped to vCenter uuid-1: moid first, then exact name,
	 * then dot-prefix (FQDN against short name, either way); a row of
	 * another vCenter is skipped; a row with no VMEntityVCID is kept.
	 */
	static void matchResourceTable() throws Exception {
		FakeSuiteApi suite = new FakeSuiteApi();
		suite.bodies.put("resourceKind=HostSystem",
				fixture("suiteapi/resources-hostsystem.json"));
		ComplianceStitcher st = new ComplianceStitcher(suite, null);
		st.setOwningVcUuid("uuid-1");
		st.loadHostResources();
		T.check(!st.loadFailed("HostSystem"), "complete list");
		Object[][] table = {
			// name, moid, expected resource id (null: no match)
			{"anything", "host-10", "r-esx01"},          // moid wins, other vCenter's host-10 skipped
			{"esx02", null, "r-esx02"},                  // exact name
			{"esx02.lab.example", null, "r-esx02"},      // FQDN against a short registered name
			{"esx01", "host-99", "r-esx01"},             // short name against a registered FQDN
			{"x", "host-15", "r-novcid"},                // no VMEntityVCID: kept (degrades to unscoped)
			{"esx09.lab.example", "host-99", null},      // only in another vCenter
			{"esx0", null, null},                        // not a dot prefix
			{null, "host-1", null},                      // moid is exact, never a prefix
			// A row with no identifier is pushed by name (existing behaviour).
			{"esx06.lab.example", null, "esx06.lab.example"},
		};
		for (Object[] row : table) {
			ComplianceStitcher.HostEntry he = st.matchHost((String) row[0],
					(String) row[1]);
			T.eq(row[2], he == null ? null : he.resourceId,
					"match " + Arrays.toString(row));
		}

		// Unscoped (vCenter UUID unknown): the bare moid host-10 resolves to
		// the last row carrying it, another vCenter's host: the MOID trap
		// that setOwningVcUuid exists to close.
		ComplianceStitcher open = new ComplianceStitcher(suite, null);
		open.setOwningVcUuid(null);
		open.loadHostResources();
		T.eq("r-other-vc", open.matchHost("anything", "host-10").resourceId,
				"unscoped bare moid is last-writer-wins");
	}
}
