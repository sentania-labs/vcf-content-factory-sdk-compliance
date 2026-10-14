package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Build 95 (issue #17, bulk-collection design builds A and B): the SOAP
 * client's call pattern against a local fake vCenter ({@link FakeVCenter}),
 * the cycle metrics, and the bulk shadow comparison.
 *
 * <ul>
 *   <li>one CurrentTime keepalive per cycle, not one per public call;</li>
 *   <li>inventory names come from the listing call (a per-object name
 *       read only for an object listed without one);</li>
 *   <li>the longest-prefix fallback never fetches a whole host or VM
 *       {@code config}, and a path it cannot reach is UNREADABLE with a
 *       prefix-cap reason; cluster paths still reach
 *       {@code configurationEx};</li>
 *   <li>a session that lapses mid-cycle logs in again and the call is
 *       retried once; a failed re-login is not tried again until the next
 *       cycle, and a failed login leaves no session behind (review W3);</li>
 *   <li>connections are reused, and a server-closed connection is
 *       replaced cleanly;</li>
 *   <li>bulk reads page with RetrievePropertiesEx /
 *       ContinueRetrievePropertiesEx, fix invalid paths, fail (and cancel)
 *       on a failed page;</li>
 *   <li>bulk evaluation agrees with the per-object path on the same data,
 *       and the comparator reports a disagreement when they differ;</li>
 *   <li>CycleMetrics charges nested phases exclusively.</li>
 * </ul>
 */
public final class Build95CollectionTest {

	static final String PG_DEFAULT = "<val xsi:type=\"VMwareDVSPortSetting\">"
			+ "<securityPolicy xsi:type=\"DVSSecurityPolicy\">"
			+ "<allowPromiscuous><inherited>false</inherited>"
			+ "<value>%s</value></allowPromiscuous></securityPolicy>"
			+ "<vlan xsi:type=\"VmwareDistributedVirtualSwitchVlanIdSpec\">"
			+ "<inherited>false</inherited><vlanId>10</vlanId></vlan></val>";
	static final String BOOL_TRUE = "<val xsi:type=\"xsd:boolean\">true</val>";

	public static void main(String[] args) throws Exception {
		keepaliveOncePerCycle();
		listingNamesReused();
		prefixCap();
		reloginMidCycle();
		failedReloginLatched();
		failedLoginLeavesNoSession();
		esxcliMarksSurviveRelogin();
		connectionReuse();
		bulkPaging();
		bulkPathFixAndFailedPage();
		bulkAgreesWithPerObject();
		comparator();
		shadowSwitchAndPageBytes();
		metrics();
		System.out.println("Build95CollectionTest: all assertions passed");
	}

	static BenchmarkProfile.Control vim(String id, String kind, String param,
			String expected, String recipe) {
		return new BenchmarkProfile.Control(id, "P1", kind, "VMWARE", param,
				"vim_property", "boolean", expected, id, "", "", "", recipe);
	}

	static BenchmarkProfile.Control adv(String id, String kind, String key,
			String expected) {
		return new BenchmarkProfile.Control(id, "P1", kind, "VMWARE", key,
				"advanced_setting", "string", expected, id, "", "", "", "");
	}

	/** Single-object RetrieveProperties from a per-object value table. */
	static FakeVCenter.Resp perObject(FakeVCenter.Req r,
			Map<String, String> table, String invalidPrefix) {
		String path = FakeVCenter.pathSets(r.body).get(0);
		String[] o = FakeVCenter.obj(r.body);
		if (invalidPrefix != null && path.startsWith(invalidPrefix)) {
			return FakeVCenter.invalidProperty(path);
		}
		String val = table.get(o[1] + "|" + path);
		return FakeVCenter.ok("RetrieveProperties", FakeVCenter.objectContent(
				"returnval", o[0], o[1], val == null ? FakeVCenter.vals()
						: FakeVCenter.vals(path, val)));
	}

	// ------------------------------------------------------------------

	static void keepaliveOncePerCycle() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			Map<String, String> table = FakeVCenter.map(
					"host-1|runtime.connectionState",
					"<val xsi:type=\"HostSystemConnectionState\">connected</val>",
					"host-1|config.lockdownMode",
					"<val xsi:type=\"HostLockdownMode\">lockdownNormal</val>");
			f.handler = r -> perObject(r, table, null);
			VSphereClient c = f.client();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem", "host-1");
			List<BenchmarkProfile.Control> ctl = Arrays.asList(
					vim("esx.lockdown", "HostSystem", "lockdown",
							"lockdownNormal", "scalar:config.lockdownMode"));
			for (int cycle = 1; cycle <= 3; cycle++) {
				c.ensureConnected();          // the adapter's one call
				c.beginCycle();
				for (int i = 0; i < 5; i++) {
					T.eq("connected", c.getHostConnectionState(h),
							"connection state read");
					Object v = c.readVimProperties(h, ctl).get("lockdown");
					T.eq("lockdownNormal", v, "lockdown read");
				}
				// Cycle 1 logs in (no keepalive needed); each later cycle
				// makes exactly one keepalive, whatever the number of reads.
				T.eq(cycle - 1, f.count("CurrentTime"),
						"CurrentTime keepalives after cycle " + cycle);
			}
			T.eq(1, f.count("Login"), "one login for three cycles");
		}
	}

	static void listingNamesReused() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> {
				String[] o = FakeVCenter.obj(r.body);
				if ("ContainerView".equals(o[0])) {
					T.eq(Arrays.asList("name"), FakeVCenter.pathSets(r.body),
							"listing asks for name");
					return FakeVCenter.ok("RetrieveProperties",
							FakeVCenter.objectContent("returnval", "HostSystem",
									"host-1", FakeVCenter.vals("name",
											"<val>esx01</val>"))
							+ FakeVCenter.objectContent("returnval",
									"HostSystem", "host-2", FakeVCenter.vals())
							+ FakeVCenter.objectContent("returnval",
									"HostSystem", "host-3", FakeVCenter.vals(
											"name", "<val>esx03</val>")));
				}
				return perObject(r, FakeVCenter.map("host-2|name",
						"<val>esx02</val>"), null);
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			List<VSphereClient.HostInfo> hosts = c.getHosts();
			T.eq(3, hosts.size(), "three hosts");
			T.eq("esx01", hosts.get(0).name, "name from the listing");
			T.eq("esx02", hosts.get(1).name, "missing name read on its own");
			T.eq("esx03", hosts.get(2).name, "name from the listing");
			T.eq(2, f.count("RetrieveProperties"),
					"one listing plus one name read (host-2 only), not one "
					+ "per host");
		}
	}

	static void prefixCap() throws Exception {
		T.eq("[4, 3, 2]", Arrays.toString(
				VSphereClient.prefixLengths("HostSystem", 4, 4)), "host 4");
		T.eq("[2]", Arrays.toString(
				VSphereClient.prefixLengths("VirtualMachine", 3, 2)), "vm list");
		T.eq("[]", Arrays.toString(
				VSphereClient.prefixLengths("HostSystem", 1, 1)),
				"a one-segment host prefix is never fetched by the fallback");
		T.eq("[4, 3, 2, 1]", Arrays.toString(VSphereClient.prefixLengths(
				"ClusterComputeResource", 4, 4)), "cluster reaches 1");
		T.eq("[6, 5, 4, 3]", Arrays.toString(VSphereClient.prefixLengths(
				"DistributedVirtualPortgroup", 6, 6)),
				"at most MAX_PREFIX_ATTEMPTS lengths");
		T.eq("[1]", Arrays.toString(VSphereClient.prefixLengths(
				"VmwareDistributedVirtualSwitch", 2, 1)), "dvs parent");

		try (FakeVCenter f = new FakeVCenter()) {
			// Host: nothing resolves. The fallback stops at two segments.
			f.handler = r -> perObject(r, FakeVCenter.map(), null);
			VSphereClient c = f.client();
			c.ensureConnected();
			BenchmarkProfile.Control fw = vim("esx.fw", "HostSystem", "fw",
					"true", "bool:config.firewall.defaultPolicy.incomingBlocked");
			Map<String, Object> v = c.readVimProperties(
					new VSphereClient.MoRef("HostSystem", "host-1"),
					Arrays.asList(fw));
			T.check(v.get("fw") == VSphereClient.UNREADABLE,
					"unreachable path is UNREADABLE, never a pass");
			List<String> asked = new ArrayList<>();
			for (FakeVCenter.Req r : f.of("RetrieveProperties")) {
				asked.addAll(FakeVCenter.pathSets(r.body));
			}
			T.eq(Arrays.asList("config.firewall.defaultPolicy.incomingBlocked",
					"config.firewall.defaultPolicy", "config.firewall"), asked,
					"host prefixes tried, never the whole config");
			String why = c.lastReadReasons().get("fw");
			T.check(why != null && why.startsWith("prefix-cap: "),
					"prefix-cap reason: " + why);
			T.eq("prefix-cap", UnreadableReasons.category(why),
					"own reason category");
		}
		try (FakeVCenter f = new FakeVCenter()) {
			// Cluster: subtype paths are invalid; configurationEx resolves.
			f.handler = r -> perObject(r, FakeVCenter.map(
					"domain-c1|configurationEx",
					"<val xsi:type=\"ClusterConfigInfoEx\"><vsanConfigInfo>"
					+ "<enabled>true</enabled><defaultConfig>"
					+ "<checksumEnabled>true</checksumEnabled></defaultConfig>"
					+ "</vsanConfigInfo></val>"), "configurationEx.");
			VSphereClient c = f.client();
			c.ensureConnected();
			BenchmarkProfile.Control ck = vim("vsan.checksum",
					"ClusterComputeResource", "ck", "true",
					"bool:configurationEx.vsanConfigInfo.defaultConfig."
					+ "checksumEnabled");
			Map<String, Object> v = c.readVimProperties(
					new VSphereClient.MoRef("ClusterComputeResource",
							"domain-c1"), Arrays.asList(ck));
			T.eq(Boolean.TRUE, v.get("ck"),
					"cluster vSAN path still read through configurationEx");
		}
	}

	static void reloginMidCycle() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> perObject(r, FakeVCenter.map(
					"host-1|runtime.connectionState", "<val>connected</val>"),
					null);
			VSphereClient c = f.client();
			c.ensureConnected();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem", "host-1");
			T.eq("connected", c.getHostConnectionState(h), "before expiry");
			f.expireSessions();   // vCenter drops the session mid-cycle
			T.eq("connected", c.getHostConnectionState(h),
					"after expiry: logged in again and retried");
			T.eq(2, f.count("Login"), "one extra login");
			T.eq(0, f.count("CurrentTime"), "no keepalive involved");
			int rp = f.count("RetrieveProperties");
			T.eq(3, rp, "the failed call was retried once (1 + 2)");
		}
	}

	/**
	 * Review W3: with a bad credential, one cycle sends one failed Login,
	 * not one per SOAP call (SSO lockout), every later read fails
	 * (UNREADABLE, never a default) without touching vCenter, and the next
	 * cycle tries once more.
	 */
	static void failedReloginLatched() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> perObject(r, FakeVCenter.map(
					"host-1|runtime.connectionState", "<val>connected</val>",
					"host-1|config.lockdownMode", "<val>lockdownNormal</val>"),
					null);
			VSphereClient c = f.client();
			c.ensureConnected();
			c.beginCycle();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem", "host-1");
			T.eq("connected", c.getHostConnectionState(h), "before expiry");
			f.loginFails = true;    // the password was changed in SSO
			f.expireSessions();     // and the session lapses mid-cycle
			T.eq(null, c.getHostConnectionState(h),
					"the call whose re-login failed reads nothing");
			T.eq(2, f.count("Login"), "one failed re-login");
			T.check(c.loginFailure() != null, "the failure is remembered");
			int calls = f.requests.size();
			List<BenchmarkProfile.Control> ctl = Arrays.asList(
					vim("esx.lockdown", "HostSystem", "lockdown",
							"lockdownNormal", "scalar:config.lockdownMode"));
			for (int i = 0; i < 20; i++) {
				boolean threw = false;
				try {
					c.getHostConnectionState(h);
				} catch (VimOptions.ReadFault e) {
					threw = e.getMessage().contains("not logging in again");
				}
				T.check(threw, "a later read fails, naming the latch");
				Map<String, Object> v = null;
				try {
					v = c.readVimProperties(h, ctl);
				} catch (VimOptions.ReadFault e) {
					v = null;
				}
				T.check(v == null || v.get("lockdown") == VSphereClient.UNREADABLE,
						"a later recipe read is UNREADABLE, never a value");
			}
			T.eq(2, f.count("Login"), "no further Login this cycle");
			T.eq(calls, f.requests.size(), "no call reached vCenter after the "
					+ "failed re-login");

			// Next cycle: one more attempt; with the credential fixed it
			// works again.
			f.loginFails = false;
			c.ensureConnected();
			c.beginCycle();
			T.check(c.loginFailure() == null, "latch cleared by the new cycle");
			T.eq("connected", c.getHostConnectionState(h), "next cycle reads");
			T.eq(3, f.count("Login"), "one Login in the next cycle");

			// beginCycle alone clears the latch too.
			f.loginFails = true;
			f.expireSessions();
			T.eq(null, c.getHostConnectionState(h), "failed again");
			f.loginFails = false;
			c.beginCycle();
			T.eq("connected", c.getHostConnectionState(h),
					"after beginCycle a read may log in again");
		}
	}

	/**
	 * Review W3: a failed Login leaves no half-made session. vCenter sets
	 * the session cookie on RetrieveServiceContent, before Login; the
	 * client must not take that cookie and the ServiceContent references
	 * for a live session.
	 */
	static void failedLoginLeavesNoSession() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> perObject(r, FakeVCenter.map(
					"host-1|runtime.connectionState", "<val>connected</val>"),
					null);
			f.loginFails = true;
			VSphereClient c = f.client();
			boolean threw = false;
			try {
				c.ensureConnected();
			} catch (Exception e) {
				threw = true;
			}
			T.check(threw, "a failed Login fails the cycle's connect");
			int calls = f.requests.size();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem", "host-1");
			threw = false;
			try {
				c.getHostConnectionState(h);
			} catch (VimOptions.ReadFault e) {
				threw = true;
			}
			T.check(threw, "a read fails at once");
			T.eq(calls, f.requests.size(), "and sends nothing, the "
					+ "pre-login cookie in particular");
			for (FakeVCenter.Req r : f.requests) {
				T.check(!r.action.endsWith("RetrieveProperties"),
						"nothing was read on the unauthenticated cookie");
			}
			T.eq(1, f.count("Login"), "one Login");
		}
	}

	/**
	 * Review N3: a host whose esxcli calls failed in transport this cycle
	 * stays skipped after a mid-cycle re-login (which replaces the esxcli
	 * client), so it does not cost another timeout until the next cycle.
	 */
	static void esxcliMarksSurviveRelogin() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> r.action.endsWith("RetrieveManagedMethodExecuter")
					? FakeVCenter.ABORT
					: perObject(r, FakeVCenter.map(
							"host-1|runtime.connectionState",
							"<val>connected</val>"), null);
			VSphereClient c = f.client();
			c.ensureConnected();
			c.beginCycle();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem", "host-1");
			BenchmarkProfile.Control ssh = new BenchmarkProfile.Control(
					"esx.shell", "P1", "HostSystem", "VMWARE", "shell",
					"esxcli", "string", "false", "esx.shell", "", "", "",
					"esxcli:system.account.list:Shellaccess[UserID=dcui]");
			Map<String, Object> v = c.readVimProperties(h, Arrays.asList(ssh));
			T.check(v.get("shell") == VSphereClient.UNREADABLE,
					"transport failure: UNREADABLE");
			T.check(c.takeEsxcliUnreachable("host-1") != null,
					"host marked and reported");
			int lookups = f.count("RetrieveManagedMethodExecuter");
			T.check(lookups >= 1, "the host was tried");

			f.expireSessions();
			T.eq("connected", c.getHostConnectionState(h), "re-login");
			T.eq(2, f.count("Login"), "re-logged in");
			v = c.readVimProperties(h, Arrays.asList(ssh));
			T.check(v.get("shell") == VSphereClient.UNREADABLE,
					"still UNREADABLE after the re-login");
			String why = c.lastReadReasons().get("shell");
			T.eq("esxcli-host-unreachable", UnreadableReasons.category(why),
					"reason keeps the mark: " + why);
			T.eq(lookups, f.count("RetrieveManagedMethodExecuter"),
					"no new call to the unreachable host");
			T.eq(null, c.takeEsxcliUnreachable("host-1"),
					"not reported twice in the cycle");
		}
	}

	static void connectionReuse() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			final boolean[] closeNext = {false};
			f.handler = r -> {
				FakeVCenter.Resp resp = perObject(r, FakeVCenter.map(
						"host-1|runtime.connectionState", "<val>connected</val>"),
						null);
				if (closeNext[0]) {
					closeNext[0] = false;
					return resp.closing();
				}
				return resp;
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			VSphereClient.MoRef h = new VSphereClient.MoRef("HostSystem", "host-1");
			for (int i = 0; i < 5; i++) c.getHostConnectionState(h);
			Set<Integer> ports = new HashSet<>();
			for (FakeVCenter.Req r : f.requests) ports.add(r.clientPort);
			T.eq(1, ports.size(), "seven calls on one reused connection: "
					+ ports);
			closeNext[0] = true;
			T.eq("connected", c.getHostConnectionState(h), "closing response");
			T.eq("connected", c.getHostConnectionState(h),
					"next call after the server closed the connection");
			ports.clear();
			for (FakeVCenter.Req r : f.requests) ports.add(r.clientPort);
			T.eq(2, ports.size(), "a new connection only after the close");
		}
	}

	/** 5 VMs, pages by maxObjects with tokens. */
	static FakeVCenter.Resp pagedVms(FakeVCenter.Req r, int total) {
		String op = r.action.replace("urn:vim25/", "");
		int max;
		int from;
		if (op.equals("RetrievePropertiesEx")) {
			max = Integer.parseInt(FakeVCenter.tag(r.body, "maxObjects"));
			from = 0;
		} else if (op.equals("ContinueRetrievePropertiesEx")) {
			String[] t = FakeVCenter.tag(r.body, "token").split(":");
			from = Integer.parseInt(t[0]);
			max = Integer.parseInt(t[1]);
		} else {
			return FakeVCenter.fault("NotImplemented", op);
		}
		StringBuilder b = new StringBuilder("<returnval>");
		int to = Math.min(total, from + max);
		if (to < total) b.append("<token>").append(to).append(':').append(max)
				.append("</token>");
		for (int i = from; i < to; i++) {
			b.append(FakeVCenter.objectContent("objects", "VirtualMachine",
					"vm-" + i, FakeVCenter.vals("config.version",
							"<val>vmx-21</val>")));
		}
		return FakeVCenter.ok(op, b.append("</returnval>").toString());
	}

	static void bulkPaging() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> pagedVms(r, 5);
			VSphereClient c = f.client();
			c.ensureConnected();
			List<Integer> sizes = new ArrayList<>();
			List<String> moids = new ArrayList<>();
			VSphereClient.BulkStats st = c.retrieveBulk("VirtualMachine",
					Arrays.asList("config.version"), 2, rows -> {
						sizes.add(rows.size());
						for (VSphereClient.BulkRow row : rows) {
							moids.add(row.ref.value);
							T.check(row.exact("config.version") != null,
									"value present");
						}
					});
			T.eq(Arrays.asList(2, 2, 1), sizes, "pages handed over in order");
			T.eq(Arrays.asList("vm-0", "vm-1", "vm-2", "vm-3", "vm-4"), moids,
					"every object once");
			T.eq(3, st.pages, "three pages");
			T.eq(5, st.objects, "five objects");
			T.eq(1, f.count("RetrievePropertiesEx"), "one first call");
			T.eq(2, f.count("ContinueRetrievePropertiesEx"), "two continues");
			T.eq(1, f.count("DestroyView"), "view destroyed");
			T.check(f.of("RetrievePropertiesEx").get(0).body
					.contains("<maxObjects>2</maxObjects>"), "page size sent");
		}
	}

	static void bulkPathFixAndFailedPage() throws Exception {
		try (FakeVCenter f = new FakeVCenter()) {
			// A subtype path is invalid; a host path that would need the
			// whole config is dropped, never shortened to config.
			f.handler = r -> {
				List<String> ps = FakeVCenter.pathSets(r.body);
				for (String p : ps) {
					if (p.startsWith("config.defaultPortConfig.")
							|| p.equals("config.firewall")) {
						return FakeVCenter.invalidProperty(p);
					}
				}
				return FakeVCenter.ok("RetrievePropertiesEx", "<returnval/>");
			};
			VSphereClient c = f.client();
			c.ensureConnected();
			VSphereClient.BulkStats st = c.retrieveBulk(
					"DistributedVirtualPortgroup", Arrays.asList(
							"config.defaultPortConfig.securityPolicy",
							"config.policy.portConfigResetAtDisconnect"),
					100, rows -> { });
			T.eq(1, st.pathFixes, "one invalid path fixed");
			T.eq(Arrays.asList("config.policy.portConfigResetAtDisconnect",
					"config.defaultPortConfig"), st.pathSet, "shortened set");
			int before = f.count("RetrievePropertiesEx");
			c.retrieveBulk("DistributedVirtualPortgroup", Arrays.asList(
					"config.defaultPortConfig.securityPolicy",
					"config.policy.portConfigResetAtDisconnect"), 100, rows -> { });
			T.eq(before + 1, f.count("RetrievePropertiesEx"),
					"accepted set remembered: no fix calls next cycle");

			VSphereClient.BulkStats hs = c.retrieveBulk("HostSystem",
					Arrays.asList("config.firewall", "config.service"), 10,
					rows -> { });
			T.eq(Arrays.asList("config.firewall"), hs.droppedPaths,
					"host path dropped rather than fetching all of config");
			T.eq(Arrays.asList("config.service"), hs.pathSet, "kept path");
		}
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> r.action.endsWith("ContinueRetrievePropertiesEx")
					? FakeVCenter.fault("SystemError", "page lost")
					: pagedVms(r, 5);
			VSphereClient c = f.client();
			c.ensureConnected();
			List<Integer> sizes = new ArrayList<>();
			boolean threw = false;
			try {
				c.retrieveBulk("VirtualMachine", Arrays.asList("config.version"),
						2, rows -> sizes.add(rows.size()));
			} catch (VimOptions.ReadFault e) {
				threw = e.getMessage().contains("page 2 failed");
			}
			T.check(threw, "a failed page fails the bulk read of the kind");
			T.eq(Arrays.asList(2), sizes, "only the first page was handed over");
			T.eq(1, f.count("CancelRetrievePropertiesEx"),
					"remaining pages cancelled");
			T.eq(1, f.count("DestroyView"), "view destroyed on failure");
		}
		// Review N1: a page handler that throws (Stop, an evaluation error)
		// cancels the retrieval still open: the token for the NEXT page,
		// which vCenter has handed out and nobody will continue.
		for (int failOn = 1; failOn <= 3; failOn++) {
			try (FakeVCenter f = new FakeVCenter()) {
				f.handler = r -> pagedVms(r, 5);
				VSphereClient c = f.client();
				c.ensureConnected();
				int[] seen = {0};
				final int stopAt = failOn;
				boolean threw = false;
				try {
					c.retrieveBulk("VirtualMachine",
							Arrays.asList("config.version"), 2, rows -> {
								if (++seen[0] == stopAt) {
									throw new InterruptedException("stop");
								}
							});
				} catch (InterruptedException e) {
					threw = true;
				}
				T.check(threw, "the handler's exception is rethrown");
				List<FakeVCenter.Req> cancels =
						f.of("CancelRetrievePropertiesEx");
				if (failOn == 3) {
					T.eq(0, cancels.size(), "last page: nothing left open");
				} else {
					T.eq(1, cancels.size(), "page " + failOn + ": one cancel");
					T.eq((failOn * 2) + ":2", FakeVCenter.tag(
							cancels.get(0).body, "token"),
							"page " + failOn + ": the next page's token");
				}
				T.eq(failOn - 1, f.count("ContinueRetrievePropertiesEx"),
						"no page requested after the throw");
				T.eq(1, f.count("DestroyView"), "view destroyed");
			}
		}
	}

	static void bulkAgreesWithPerObject() throws Exception {
		String kind = "DistributedVirtualPortgroup";
		List<BenchmarkProfile.Control> ctl = Arrays.asList(
				vim("pg.promisc", kind, "promisc", "false",
						"bool_policy:config.defaultPortConfig.securityPolicy."
						+ "allowPromiscuous"),
				vim("pg.reset", kind, "reset", "true",
						"bool:config.policy.portConfigResetAtDisconnect"),
				vim("pg.vgt", kind, "vgt", "true",
						"vlan_id_not:config.defaultPortConfig.vlan"));
		T.eq(new java.util.LinkedHashSet<>(Arrays.asList(
				"config.defaultPortConfig.securityPolicy",
				"config.policy.portConfigResetAtDisconnect",
				"config.defaultPortConfig.vlan")),
				VSphereClient.bulkPaths(kind, ctl), "paths from the recipes");
		for (String bulkPromisc : new String[] {"false", "true"}) {
			try (FakeVCenter f = new FakeVCenter()) {
				Map<String, String> table = FakeVCenter.map(
						"dvportgroup-1|config.defaultPortConfig",
						String.format(PG_DEFAULT, "false"),
						"dvportgroup-1|config.policy.portConfigResetAtDisconnect",
						BOOL_TRUE);
				f.handler = r -> {
					if (r.action.endsWith("RetrievePropertiesEx")) {
						for (String p : FakeVCenter.pathSets(r.body)) {
							if (p.startsWith("config.defaultPortConfig.")) {
								return FakeVCenter.invalidProperty(p);
							}
						}
						return FakeVCenter.ok("RetrievePropertiesEx",
								"<returnval>" + FakeVCenter.objectContent(
										"objects", kind, "dvportgroup-1",
										FakeVCenter.vals(
										"config.policy.portConfigResetAtDisconnect",
										BOOL_TRUE, "config.defaultPortConfig",
										String.format(PG_DEFAULT, bulkPromisc)))
								+ "</returnval>");
					}
					return perObject(r, table, "config.defaultPortConfig.");
				};
				VSphereClient c = f.client();
				c.ensureConnected();
				VSphereClient.MoRef pg = new VSphereClient.MoRef(kind,
						"dvportgroup-1");
				ControlEvaluator.ComplianceResult per =
						ControlEvaluator.evaluateVimProperties(ctl,
								c.readVimProperties(pg, ctl), "pg1",
								VSphereClient.UNREADABLE);
				T.eq(3, per.totalCount, "per-object read all three");
				ShadowComparator sc = new ShadowComparator("Portgroup");
				sc.record("dvportgroup-1", "pg1", per.controlResults,
						VSphereClient.bulkComparable(kind, ctl));
				c.retrieveBulk(kind, VSphereClient.bulkPaths(kind, ctl), 100,
						rows -> {
							for (VSphereClient.BulkRow row : rows) {
								sc.compare(row.ref.value,
										c.evaluateBulkRow(row, ctl, "pg1"));
							}
						});
				T.eq(3L, sc.controlsCompared(), "three controls compared");
				if (bulkPromisc.equals("false")) {
					T.eq(0L, sc.disagreements(), "same data: no disagreement");
				} else {
					T.eq(1L, sc.disagreements(), "changed bulk value seen");
					T.check(sc.disagreementLines().get(0).contains(
							"pg.promisc: per-object 'false pass', bulk "
							+ "'true fail'"), sc.disagreementLines().get(0));
				}
			}
		}
		// Advanced settings: a host's config.option evaluated like
		// QueryOptions; a missing value is UNREADABLE, never a pass.
		List<BenchmarkProfile.Control> hostCtl = Arrays.asList(
				adv("esx.shell", "HostSystem", "UserVars.ESXiShellTimeOut",
						"900"));
		T.check(VSphereClient.bulkPaths("HostSystem", hostCtl)
				.contains("config.option"), "hosts read config.option");
		VSphereClient c = new VSphereClient("http://127.0.0.1:9/sdk", "u", "p",
				null, null, true);
		VSphereClient.BulkRow none = new VSphereClient.BulkRow(
				new VSphereClient.MoRef("HostSystem", "host-1"));
		List<ControlEvaluator.ControlResult> r = c.evaluateBulkRow(none,
				hostCtl, "esx01");
		T.eq(1, r.size(), "one result");
		T.check(r.get(0).unreadable, "no config.option: unreadable");
	}

	static void comparator() {
		ShadowComparator sc = new ShadowComparator("VM", 2);
		Set<String> comparable = new HashSet<>(Arrays.asList("a", "b", "c"));
		List<ControlEvaluator.ControlResult> per = Arrays.asList(
				new ControlEvaluator.ControlResult("a", "1", "1", true, ""),
				new ControlEvaluator.ControlResult("b", "x", "y", false, ""),
				new ControlEvaluator.ControlResult("c", "(unreadable)", "z",
						false, "", true),
				new ControlEvaluator.ControlResult("esxcli.x", "v", "v", true, ""));
		sc.record("vm-1", "web01", per, comparable);
		sc.record("vm-2", "web02", per, comparable);
		sc.record("vm-3", "web03", per, comparable);
		T.check(!sc.isRecorded("vm-9"), "unrecorded");
		// vm-1 agrees; vm-2 differs on a and lacks c; vm-3 never returned.
		sc.compare("vm-1", Arrays.asList(
				new ControlEvaluator.ControlResult("a", "1", "1", true, ""),
				new ControlEvaluator.ControlResult("b", "x", "y", false, ""),
				new ControlEvaluator.ControlResult("c", "?", "z", false, "", true)));
		sc.compare("vm-2", Arrays.asList(
				new ControlEvaluator.ControlResult("a", "2", "1", false, ""),
				new ControlEvaluator.ControlResult("b", "x", "y", false, "")));
		sc.compare("vm-9", Arrays.asList());
		sc.compare("vm-1", Arrays.asList());   // second sighting ignored
		T.eq(2L, sc.objectsCompared(), "two objects compared");
		T.eq(6L, sc.controlsCompared(), "esxcli control not compared");
		T.eq(2L, sc.disagreements(), "value change and not produced");
		T.eq(2L, sc.bulkObjectsWithoutRecord(), "vm-9 and repeat vm-1");
		T.eq(1, sc.recordedNotReturned(), "vm-3 not returned");
		List<String> lines = sc.disagreementLines();
		T.eq(2, lines.size(), "two lines, under the cap");
		T.check(lines.get(0).equals("VM web02 (vm-2) a: per-object '1 pass', "
				+ "bulk '2 fail'"), lines.get(0));
		T.check(lines.get(1).contains("c: per-object '(unreadable)', bulk '"
				+ ShadowComparator.NOT_PRODUCED + "'"), lines.get(1));
		String sum = sc.summary(3, 40);
		T.check(sum.startsWith("Bulk shadow VM: 6 control(s) compared on 2 "
				+ "object(s), 2 disagreement(s); 1 scored object(s) not "
				+ "returned"), sum);

		ShadowComparator capped = new ShadowComparator("Host", 1);
		capped.record("h", "esx", per, comparable);
		capped.compare("h", Arrays.asList());
		List<String> cl = capped.disagreementLines();
		T.eq(2, cl.size(), "one line plus the overflow line");
		T.check(cl.get(1).contains("+2 more"), cl.get(1));
		capped.fail("ReadFault: page 2 failed");
		T.check(capped.summary(1, 5).contains("bulk read FAILED (ReadFault: "
				+ "page 2 failed)"), "failure in the summary");
	}

	/**
	 * Review W5: shadow mode off records nothing (no memory, and the
	 * caller skips the bulk read on hasRecords); the bulk read reports
	 * response bytes per page and the largest page, and the summary says
	 * them. The shipped default is unchanged (on) until Scott decides.
	 */
	static void shadowSwitchAndPageBytes() throws Exception {
		List<ControlEvaluator.ControlResult> one = new ArrayList<>(
				ControlEvaluator.evaluateControls(Arrays.asList(adv("vm.a",
						"VirtualMachine", "a.key", "TRUE")),
						FakeVCenter.map("a.key", "TRUE"), "vm-1")
						.controlResults);
		Set<String> comparable = new HashSet<>(Arrays.asList("vm.a"));
		ShadowComparator off = new ShadowComparator("VM", false);
		off.record("vm-1", "vm-1", one, comparable);
		T.check(!off.isEnabled(), "off");
		T.check(!off.hasRecords(), "off records nothing");
		ShadowComparator on = new ShadowComparator("VM", true);
		on.record("vm-1", "vm-1", one, comparable);
		T.check(on.hasRecords(), "on records");

		String ca = OverridesTest.readSrc(
				"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");
		T.check(OverridesTest.stripComments(ca).replaceAll("\\s+", " ")
				.contains("static final boolean BULK_SHADOW = true;"),
				"shipped default unchanged: on (decision pending)");
		T.check(ca.contains("new ShadowComparator(kind, BULK_SHADOW)"),
				"every kind's comparator follows the switch");
		T.check(ca.contains("case \"VirtualMachine\": return 50;"),
				"VM bulk page of 50");

		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> pagedVms(r, 5);
			VSphereClient c = f.client();
			c.ensureConnected();
			VSphereClient.BulkStats st = c.retrieveBulk("VirtualMachine",
					Arrays.asList("config.version"), 2, rows -> { });
			T.eq(3, st.pages, "three pages");
			T.check(st.maxPageBytes > 0, "largest page measured");
			T.check(st.bytes >= st.maxPageBytes * 2, "total over the pages: "
					+ st.bytes + " vs largest " + st.maxPageBytes);
			T.check(st.bytes <= st.maxPageBytes * 3, "three pages at most "
					+ "the largest each");
		}
		String sum = on.summary(3, 40, 123456, 45678);
		T.check(sum.contains("3 page(s), 40 ms, 123456 bytes, largest page "
				+ "45678 bytes (scores still come from the per-object path)"),
				sum);
	}

	static void metrics() {
		long[] now = {0};
		CycleMetrics m = new CycleMetrics(() -> now[0]);
		m.enter(CycleMetrics.Phase.HOSTS);
		now[0] += 100_000_000L;              // 100 ms host reads
		m.soapCall();
		m.enter(CycleMetrics.Phase.ESXCLI);
		now[0] += 30_000_000L;               // 30 ms esxcli inside
		m.soapCall();
		m.soapCall();
		m.exit(CycleMetrics.Phase.ESXCLI);
		try (CycleMetrics.Scope s = m.scope(CycleMetrics.Phase.PUSHES)) {
			now[0] += 20_000_000L;           // 20 ms push inside
			m.suiteCall();
		}
		now[0] += 10_000_000L;               // 10 ms more host reads
		m.exit(CycleMetrics.Phase.HOSTS);
		m.exit(CycleMetrics.Phase.VMS);      // mismatch ignored
		T.eq(110L, m.millis(CycleMetrics.Phase.HOSTS), "hosts exclusive");
		T.eq(30L, m.millis(CycleMetrics.Phase.ESXCLI), "esxcli");
		T.eq(20L, m.millis(CycleMetrics.Phase.PUSHES), "pushes");
		T.eq(1L, m.soapCalls(CycleMetrics.Phase.HOSTS), "host SOAP");
		T.eq(2L, m.soapCalls(CycleMetrics.Phase.ESXCLI), "esxcli SOAP");
		T.eq(3L, m.soapCalls(), "SOAP total");
		T.eq(1L, m.suiteCalls(), "Suite API total");
		String s = m.summary();
		T.check(s.startsWith("timing: inventory 0 ms (0 SOAP, 0 Suite API), "
				+ "host reads 110 ms (1 SOAP, 0 Suite API)"), s);
		T.check(s.endsWith("; SOAP calls 3 (esxcli 2), Suite API calls 1"), s);
		try (CycleMetrics.Scope s2 = CycleMetrics.scope(null,
				CycleMetrics.Phase.HOSTS)) {
			// null metrics: a no-op scope
		}

		// The client counts its own calls into the metrics.
		try (FakeVCenter f = new FakeVCenter()) {
			f.handler = r -> perObject(r, FakeVCenter.map(
					"host-1|runtime.connectionState", "<val>connected</val>"),
					null);
			VSphereClient c = f.client();
			CycleMetrics cm = new CycleMetrics();
			c.setMetrics(cm);
			c.ensureConnected();             // RetrieveServiceContent + Login
			cm.enter(CycleMetrics.Phase.HOSTS);
			c.getHostConnectionState(new VSphereClient.MoRef("HostSystem",
					"host-1"));
			cm.exit(CycleMetrics.Phase.HOSTS);
			T.eq(2L, cm.soapCalls(CycleMetrics.Phase.OTHER), "session calls");
			T.eq(1L, cm.soapCalls(CycleMetrics.Phase.HOSTS), "host read");
			if (Boolean.getBoolean("metrics.print")) {
				System.out.println("CycleMetrics sample: " + cm.summary());
			}
		} catch (Exception e) {
			throw new AssertionError(e);
		}
	}
}
