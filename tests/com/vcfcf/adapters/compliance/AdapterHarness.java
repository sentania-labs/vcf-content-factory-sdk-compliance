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

	/** Add a VM on {@code hostMoid} and list it in VCF Ops too. */
	AdapterHarness vm(String moid, String name, String hostMoid) {
		vms.put(moid, new String[] {name, hostMoid});
		listResources();
		return this;
	}
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
			return property(obj, FakeVCenter.pathSets(r.body).get(0));
		}
		if (op.equals("QueryOptions")) {
			if (r.body.contains(">VpxSettings<")) {
				return FakeVCenter.ok(op, "");
			}
			return FakeVCenter.ok(op,
					"<returnval><key>UserVars.ESXiShellTimeOut</key>"
					+ "<value xsi:type=\"xsd:long\">900</value></returnval>"
					+ "<returnval><key>Security.AccountLockFailures</key>"
					+ "<value xsi:type=\"xsd:int\">5</value></returnval>");
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
		return FakeVCenter.ok("RetrieveProperties", b.toString());
	}

	private FakeVCenter.Resp property(String[] obj, String path) {
		String moid = obj == null ? "" : obj[1];
		Map<String, String> v = FakeVCenter.vals();
		if (vms.containsKey(moid) && path.equals("config.extraConfig")) {
			v = FakeVCenter.vals(path, "<val xsi:type=\"ArrayOfOptionValue\">"
					+ "</val>");
		}
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
				default:
					break;
			}
		}
		return FakeVCenter.ok("RetrieveProperties", FakeVCenter.objectContent(
				"returnval", obj == null ? "ManagedEntity" : obj[0], moid, v));
	}

	@Override
	public void close() {
		vc.close();
	}
}
