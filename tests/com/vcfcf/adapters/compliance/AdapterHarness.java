package com.vcfcf.adapters.compliance;

import com.integrien.alive.common.adapter3.MetricData;
import com.integrien.alive.common.adapter3.ResourceKey;
import com.integrien.alive.common.adapter3.config.ResourceConfig;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Build 96 (issue #27): runs the real {@link ComplianceAdapter} collection
 * cycle (collectWorld) in ci/run_java_tests.sh, compiled against
 * tests/stubs. The vCenter is a {@link FakeVCenter} serving a small
 * inventory (hosts, no VMs, switches, portgroups or clusters unless a test
 * adds them), the Suite API a {@link FakeSuiteApi} that lists the matching
 * VMWARE resources and records every push. A test can replace any vCenter
 * answer through {@link #override} (return null to fall through to the
 * default inventory).
 *
 * <p>The configured holder is installed directly (configureAdapter builds
 * an HTTPS client and needs the platform trust manager), so the cycle runs
 * exactly as after a configure, on the fake.
 */
final class AdapterHarness implements AutoCloseable {

	static final String VC_RESOURCE = "r-vc";
	static final String VC_UUID = "uuid-1";

	final FakeVCenter vc;
	final FakeSuiteApi suite = new FakeSuiteApi();
	final ComplianceAdapter adapter = new ComplianceAdapter();
	final VSphereClient client;
	final ComplianceStitcher stitcher;
	final Configured<SuiteApiStitcher, ComplianceStitcher> holder;

	/** host moid -> name; every host is ESX 9.0.0 and connected. */
	final Map<String, String> hosts = new LinkedHashMap<>();
	/** Build 96 (review B1-r2): VM moid -> {name, host moid}; none by default. */
	final Map<String, String[]> vms = new LinkedHashMap<>();

	/**
	 * Build 104 (PR #69 Codex P1): vim objects of the switch, portgroup and
	 * cluster kinds, vim type -> (moid -> name); none by default.
	 */
	final Map<String, Map<String, String>> vimObjects = new LinkedHashMap<>();

	/**
	 * Add a {@code type} object (VmwareDistributedVirtualSwitch,
	 * DistributedVirtualPortgroup or ClusterComputeResource) and list it
	 * in VCF Ops too.
	 */
	AdapterHarness vim(String type, String moid, String name) {
		vimObjects.computeIfAbsent(type, k -> new LinkedHashMap<>())
				.put(moid, name);
		listResources();
		return this;
	}

	/** Add a VM on {@code hostMoid} and list it in VCF Ops too. */
	AdapterHarness vm(String moid, String name, String hostMoid) {
		vms.put(moid, new String[] {name, hostMoid});
		listResources();
		return this;
	}
	/**
	 * Build 103: (MOID, path) pairs the fake vCenter does not have a value
	 * for, in a bulk read and a per-object read alike (an unset property).
	 */
	volatile java.util.function.BiPredicate<String, String> hidden =
			(moid, path) -> false;

	/** A test's answer first; null falls through to the inventory. */
	volatile Function<FakeVCenter.Req, FakeVCenter.Resp> override;

	AdapterHarness(String... hostMoidNamePairs) throws Exception {
		for (int i = 0; i + 1 < hostMoidNamePairs.length; i += 2) {
			hosts.put(hostMoidNamePairs[i], hostMoidNamePairs[i + 1]);
		}
		vc = new FakeVCenter();
		vc.handler = this::answer;
		client = vc.client();
		stitcher = new ComplianceStitcher(suite, null);
		ComplianceConfig account = new ComplianceConfig("vc.lab.example",
				"user", "pass", "false", "");
		holder = new Configured<>(account, client, new BenchmarkLoader(), null,
				stitcher, false);
		Field f = ComplianceAdapter.class.getDeclaredField("configured");
		f.setAccessible(true);
		f.set(adapter, holder);
		listResources();
	}

	/** The VCF Ops resource lists the stitcher loads, from {@link #hosts}. */
	void listResources() {
		List<String> rows = new ArrayList<>();
		for (Map.Entry<String, String> h : hosts.entrySet()) {
			rows.add(FakeSuiteApi.row("r-" + h.getKey(), h.getValue(),
					h.getKey(), VC_UUID));
		}
		suite.bodies.put("resourceKind=HostSystem&", FakeSuiteApi.page(
				rows.size(), rows.toArray(new String[0])));
		List<String> vmRows = new ArrayList<>();
		for (Map.Entry<String, String[]> v : vms.entrySet()) {
			vmRows.add(FakeSuiteApi.row("r-" + v.getKey(), v.getValue()[0],
					v.getKey(), VC_UUID));
		}
		suite.bodies.put("resourceKind=VirtualMachine&", FakeSuiteApi.page(
				vmRows.size(), vmRows.toArray(new String[0])));
		for (Map.Entry<String, Map<String, String>> k : vimObjects.entrySet()) {
			List<String> kRows = new ArrayList<>();
			for (Map.Entry<String, String> o : k.getValue().entrySet()) {
				kRows.add(FakeSuiteApi.row("r-" + o.getKey(), o.getValue(),
						o.getKey(), VC_UUID));
			}
			suite.bodies.put("resourceKind=" + k.getKey() + "&",
					FakeSuiteApi.page(kRows.size(),
							kRows.toArray(new String[0])));
		}
		suite.bodies.put("resourceKind=VMwareAdapter+Instance&",
				"{\"pageInfo\":{\"totalCount\":1},\"resourceList\":[{"
				+ "\"identifier\":\"" + VC_RESOURCE + "\",\"resourceKey\":{"
				+ "\"name\":\"vc\",\"resourceIdentifiers\":["
				+ "{\"identifierType\":{\"name\":\"VCURL\"},\"value\":"
				+ "\"vc.lab.example\"},"
				+ "{\"identifierType\":{\"name\":\"VMEntityVCID\"},\"value\":\""
				+ VC_UUID + "\"}]}}]}");
	}

	/** One collection cycle; rethrows what the cycle threw. */
	List<MetricData> cycle() throws Exception {
		List<MetricData> out = new ArrayList<>();
		ResourceConfig world = new ResourceConfig(new ResourceKey(
				"Compliance World", "ComplianceWorld", "vcfcf_compliance"));
		Method m = ComplianceAdapter.class.getDeclaredMethod("collectWorld",
				ResourceConfig.class, List.class);
		m.setAccessible(true);
		try {
			m.invoke(adapter, world, out);
		} catch (InvocationTargetException e) {
			Throwable t = e.getCause();
			if (t instanceof Exception) throw (Exception) t;
			throw new RuntimeException(t);
		}
		return out;
	}

	/** The rollup stats pushed to the vCenter object (all cycles, merged). */
	Map<String, Double> rollup() {
		return suite.statsFor(VC_RESOURCE);
	}

	/** The rollup stats of the LAST push to the vCenter object only. */
	Map<String, Double> lastRollup() {
		Map<String, Double> last = null;
		synchronized (suite.pushes) {
			for (FakeSuiteApi.Push p : suite.pushes) {
				if (p.stats != null && p.resourceId.equals(VC_RESOURCE)
						&& p.stats.containsKey(ComplianceRollup.INCOMPLETE_KEY)) {
					last = p.stats;
				}
			}
		}
		return last;
	}

	boolean logged(String fragment) {
		synchronized (adapter.testLog) {
			for (String l : adapter.testLog) {
				if (l.contains(fragment)) return true;
			}
		}
		return false;
	}

	private FakeVCenter.Resp answer(FakeVCenter.Req r) {
		Function<FakeVCenter.Req, FakeVCenter.Resp> o = override;
		if (o != null) {
			FakeVCenter.Resp resp = o.apply(r);
			if (resp != null) return resp;
		}
		String op = r.action.replace("urn:vim25/", "");
		if (op.equals("RetrieveProperties")) {
			String[] obj = FakeVCenter.obj(r.body);
			if (obj != null && "ContainerView".equals(obj[0])) {
				return listing(FakeVCenter.tag(r.body, "type"));
			}
			// Build 103: one ObjectContent per requested object with every
			// requested path it has, as vCenter answers a bulk read (an
			// unset path is simply absent); a single-object, single-path
			// read is the same thing with one of each.
			StringBuilder b = new StringBuilder();
			for (String[] ob : FakeVCenter.objs(r.body)) {
				Map<String, String> v = new LinkedHashMap<>();
				for (String path : FakeVCenter.pathSets(r.body)) {
					if (!hidden.test(ob[1], path)) v.putAll(property(ob, path));
				}
				b.append(FakeVCenter.objectContent("returnval", ob[0], ob[1],
						v));
			}
			return FakeVCenter.ok("RetrieveProperties", b.toString());
		}
		if (op.equals("QueryOptions")) {
			if (r.body.contains(">VpxSettings<")) {
				return FakeVCenter.ok(op, "");
			}
			return FakeVCenter.ok(op, HOST_OPTIONS.replace("<item>",
					"<returnval>").replace("</item>", "</returnval>"));
		}
		// esxcli and anything else: a fault (those reads are UNREADABLE).
		return FakeVCenter.fault("NotSupported", "not in the fake");
	}

	private FakeVCenter.Resp listing(String type) {
		StringBuilder b = new StringBuilder();
		if ("HostSystem".equals(type)) {
			for (Map.Entry<String, String> h : hosts.entrySet()) {
				b.append(FakeVCenter.objectContent("returnval", "HostSystem",
						h.getKey(), FakeVCenter.vals("name",
								"<val>" + h.getValue() + "</val>")));
			}
		}
		if ("VirtualMachine".equals(type)) {
			for (Map.Entry<String, String[]> v : vms.entrySet()) {
				b.append(FakeVCenter.objectContent("returnval",
						"VirtualMachine", v.getKey(), FakeVCenter.vals(
								"name", "<val>" + v.getValue()[0] + "</val>",
								"runtime.host", "<val type=\"HostSystem\">"
										+ v.getValue()[1] + "</val>",
								"config.guestId", "<val>otherGuest64</val>")));
			}
		}
		Map<String, String> objs = vimObjects.get(type);
		if (objs != null) {
			for (Map.Entry<String, String> o : objs.entrySet()) {
				b.append(FakeVCenter.objectContent("returnval", type,
						o.getKey(), FakeVCenter.vals("name",
								"<val>" + o.getValue() + "</val>")));
			}
		}
		return FakeVCenter.ok("RetrieveProperties", b.toString());
	}

	/**
	 * Every host's advanced options: QueryOptions returns them as
	 * returnvals, {@code config.option} (build 103's bulk read) as the
	 * items of one ArrayOfOptionValue, the same keys and values.
	 */
	static final String HOST_OPTIONS =
			"<item><key>UserVars.ESXiShellTimeOut</key>"
			+ "<value xsi:type=\"xsd:long\">900</value></item>"
			+ "<item><key>Security.AccountLockFailures</key>"
			+ "<value xsi:type=\"xsd:int\">5</value></item>";

	/**
	 * Build 103: the SCG 9.0 host vim_property values (the service list
	 * for the four service_state controls, the firewall default policy).
	 */
	static final Map<String, String> HOST_PROPS = FakeVCenter.map(
			"config.service", "<val xsi:type=\"HostServiceInfo\">"
					+ service("TSM", false) + service("snmpd", false)
					+ service("TSM-SSH", true) + service("ntpd", true)
					+ "</val>",
			"config.firewall.defaultPolicy.incomingBlocked",
			"<val xsi:type=\"xsd:boolean\">true</val>");

	/** Build 103: the SCG 9.0 VM vim_property values. */
	static final Map<String, String> VM_PROPS = FakeVCenter.map(
			"config.ftEncryptionMode", "<val xsi:type=\"xsd:string\">"
					+ "ftEncryptionOpportunistic</val>",
			"config.flags.enableLogging", "<val xsi:type=\"xsd:boolean\">"
					+ "true</val>",
			"config.hardware", "<val xsi:type=\"VirtualHardware\">"
					+ "<numCPU>2</numCPU><device xsi:type=\"VirtualDisk\">"
					+ "<key>2000</key></device></val>",
			"config.bootOptions.efiSecureBootEnabled",
			"<val xsi:type=\"xsd:boolean\">false</val>",
			"config.version", "<val xsi:type=\"xsd:string\">vmx-21</val>",
			"config.migrateEncryption", "<val xsi:type=\"xsd:string\">"
					+ "opportunistic</val>");

	private static String service(String key, boolean running) {
		return "<service><key>" + key + "</key><label>" + key + "</label>"
				+ "<required>false</required><uninstallable>false</uninstallable>"
				+ "<running>" + running + "</running><policy>off</policy>"
				+ "</service>";
	}

	/** The value of {@code path} on {@code obj}: one entry, or none. */
	private Map<String, String> property(String[] obj, String path) {
		String moid = obj == null ? "" : obj[1];
		Map<String, String> v = FakeVCenter.vals();
		if (vms.containsKey(moid) && path.equals("config.extraConfig")) {
			v = FakeVCenter.vals(path, "<val xsi:type=\"ArrayOfOptionValue\">"
					+ "</val>");
		}
		// Build 103: a value for every SCG 9.0 VM vim_property recipe, so
		// a fixture cycle reads what a vCenter would (some pass, some
		// fail), per object and in bulk alike.
		String vmVal = vms.containsKey(moid) ? VM_PROPS.get(path) : null;
		if (vmVal != null) v = FakeVCenter.vals(path, vmVal);
		if (hosts.containsKey(moid)) {
			switch (path) {
				case "summary.config.product.version":
					v = FakeVCenter.vals(path, "<val>9.0.0</val>");
					break;
				case "runtime.connectionState":
					v = FakeVCenter.vals(path, "<val xsi:type="
							+ "\"HostSystemConnectionState\">connected</val>");
					break;
				case "config.lockdownMode":
					// Build 96 (peer review item 1): a property vCenter
					// answers from its inventory, read for esx.lockdown-mode.
					v = FakeVCenter.vals(path, "<val xsi:type="
							+ "\"HostLockdownMode\">lockdownNormal</val>");
					break;
				case "configManager.advancedOption":
					v = FakeVCenter.vals(path, "<val type=\"OptionManager\">"
							+ "EsxHostAdvSettings-" + moid + "</val>");
					break;
				case "config.service":
				case "config.firewall.defaultPolicy.incomingBlocked":
					// Build 103: the SCG 9.0 host vim_property values.
					v = FakeVCenter.vals(path, HOST_PROPS.get(path));
					break;
				case "config.option":
					v = FakeVCenter.vals(path, "<val xsi:type="
							+ "\"ArrayOfOptionValue\">" + HOST_OPTIONS
							.replace("<item>", "<OptionValue>")
							.replace("</item>", "</OptionValue>") + "</val>");
					break;
				default:
					break;
			}
		}
		return v;
	}

	@Override
	public void close() {
		vc.close();
	}
}
