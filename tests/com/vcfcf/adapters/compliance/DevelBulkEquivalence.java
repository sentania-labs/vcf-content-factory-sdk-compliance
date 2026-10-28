package com.vcfcf.adapters.compliance;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;
import javax.net.ssl.*;

/**
 * Build 103 (issue #17 build 2) evidence tool, not a test: CI compiles it
 * (so it keeps up with the client) but never runs it (the name does not
 * end in Test).
 *
 * <p>Read-only: per vCenter, runs the build 102 per-object reads (OLD) and
 * the build 103 bulk-first reads (NEW, twice) over every host, VM, vDS,
 * portgroup and cluster, with the benchmark the adapter would choose, and
 * compares every control outcome (actual value + pass/fail, or
 * unreadable), each host's version, connection state and advanced-option
 * map (size and hash: QueryOptions against {@code config.option}), each
 * VM's extraConfig map, and each cluster's vSAN state. Counts SOAP calls
 * for each. Prints the account, its effective role on the root folder and
 * on each host, and each host's ESXi build, so the comparison says what it
 * ran on. Paging reimplements the adapter's page sizes ({@code i % page})
 * rather than calling BulkPager. Makes no change on vCenter; logs in and
 * out once per vCenter.
 *
 * <p>Credentials come from the environment only (VCENTER_CREDENTIAL,
 * VCENTER_PASSWORD) and are never printed. vCenter certificates are
 * checked against the system CA bundle. Run from the repo root:
 * <pre>
 *   javac -d /tmp/dbe -sourcepath src:tests:tests/stubs \
 *       tests/com/vcfcf/adapters/compliance/DevelBulkEquivalence.java
 *   java -cp /tmp/dbe com.vcfcf.adapters.compliance.DevelBulkEquivalence \
 *       vcenter1.example.com [vcenter2.example.com ...]
 * </pre>
 * Results of the 2026-10-28 run: factory
 * knowledge/context/investigations/2026-10-28-compliance-103-bulk-equivalence.md.
 */
public final class DevelBulkEquivalence {

	static SSLSocketFactory systemTrust() throws Exception {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null, null);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		int i = 0;
		try (FileInputStream in = new FileInputStream("/etc/ssl/certs/ca-certificates.crt")) {
			for (Certificate c : cf.generateCertificates(in)) ks.setCertificateEntry("c" + (i++), c);
		}
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, tmf.getTrustManagers(), null);
		return ctx.getSocketFactory();
	}

	static final VSphereClient.Log LOG = new VSphereClient.Log() {
		public void info(String m) {}
		public void debug(String m) {}
		public void warn(String m) { System.err.println("  WARN " + m); }
		public boolean isDebugEnabled() { return false; }
	};

	static int page(String type) {
		switch (type) {
			case "HostSystem": return 10;
			case "VirtualMachine": return 50;
			case "ClusterComputeResource": return 50;
			default: return 100;
		}
	}

	// moid|control -> outcome
	static Map<String, String> outcomes(String moid, List<ControlEvaluator.ControlResult> rs, Map<String, String> into) {
		for (ControlEvaluator.ControlResult r : rs) into.put(moid + "|" + r.scgId, ShadowComparator.outcome(r));
		return into;
	}

	static List<ControlEvaluator.ControlResult> merge(ControlEvaluator.ComplianceResult a, ControlEvaluator.ComplianceResult b) {
		List<ControlEvaluator.ControlResult> l = new ArrayList<>(a.controlResults);
		l.addAll(b.controlResults);
		return l;
	}

	static ControlEvaluator.ComplianceResult adv(List<BenchmarkProfile.Control> slice, Map<String, String> m, String name) {
		return m == null ? ControlEvaluator.evaluateControlsUnreadable(slice, name)
				: ControlEvaluator.evaluateControls(slice, m, name);
	}

	static ControlEvaluator.ComplianceResult vim(VSphereClient c, VSphereClient.MoRef ref, List<BenchmarkProfile.Control> slice, String name, VSphereClient.BulkRow row) throws Exception {
		Map<String, Object> v = c.readVimProperties(ref, slice, row);
		return ControlEvaluator.evaluateVimProperties(slice, v, name, VSphereClient.UNREADABLE);
	}

	static boolean hasEval(List<BenchmarkProfile.Control> s, String kind) {
		for (BenchmarkProfile.Control c : s) if (kind.equals(c.parameterKind) && c.isEvaluable()) return true;
		return false;
	}


	static String ln(org.w3c.dom.Node n) {
		String l = n.getLocalName();
		if (l == null) { l = n.getNodeName(); int c = l.indexOf(':'); if (c >= 0) l = l.substring(c + 1); }
		return l;
	}

	static List<org.w3c.dom.Element> desc(org.w3c.dom.Element e, String local) {
		List<org.w3c.dom.Element> out = new ArrayList<>();
		org.w3c.dom.NodeList nl = e.getElementsByTagName("*");
		for (int i = 0; i < nl.getLength(); i++) if (local.equals(ln(nl.item(i)))) out.add((org.w3c.dom.Element) nl.item(i));
		return out;
	}

	static List<String> texts(VSphereClient.BulkRow row, String path, String local) {
		List<String> out = new ArrayList<>();
		if (row == null) return out;
		org.w3c.dom.Element v = row.values.get(path);
		if (v == null) return out;
		for (org.w3c.dom.Element x : desc(v, local)) out.add(x.getTextContent().trim());
		if (out.isEmpty() && !v.getTextContent().trim().isEmpty()) out.add(v.getTextContent().trim());
		return out;
	}

	/** Read-only identity block: session user, effective role names, ESXi builds. */
	static void identity(VSphereClient c, List<VSphereClient.HostInfo> hosts) throws Exception {
		VSphereClient.MoRef sm = new VSphereClient.MoRef("SessionManager", "SessionManager");
		VSphereClient.BulkRow sr = c.retrieveObjects("SessionManager", Collections.singletonList(sm), Collections.singleton("currentSession"), null).get("SessionManager");
		List<String> user = texts(sr, "currentSession", "userName");
		VSphereClient.MoRef am = new VSphereClient.MoRef("AuthorizationManager", "AuthorizationManager");
		VSphereClient.BulkRow ar = c.retrieveObjects("AuthorizationManager", Collections.singletonList(am), Collections.singleton("roleList"), null).get("AuthorizationManager");
		Map<String, String> roles = new HashMap<>();
		if (ar != null && ar.values.get("roleList") != null) {
			for (org.w3c.dom.Element idn : desc(ar.values.get("roleList"), "roleId")) {
				List<org.w3c.dom.Element> names = desc((org.w3c.dom.Element) idn.getParentNode(), "name");
				if (!names.isEmpty()) roles.put(idn.getTextContent().trim(), names.get(0).getTextContent().trim());
			}
		}
		VSphereClient.MoRef root = new VSphereClient.MoRef("Folder", "group-d1");
		VSphereClient.BulkRow rr = c.retrieveObjects("Folder", Collections.singletonList(root), Collections.singleton("effectiveRole"), null).get("group-d1");
		List<String> eff = new ArrayList<>();
		for (String id : texts(rr, "effectiveRole", "int")) eff.add(id + "=" + roles.getOrDefault(id, "?"));
		System.out.println("account " + user + " (session row " + (sr == null ? "absent" : sr.values.keySet() + " missing " + sr.missing) + ", roles known " + roles.size() + ")" + ", effective role on the root folder " + eff);
		List<VSphereClient.MoRef> refs = new ArrayList<>();
		for (VSphereClient.HostInfo h : hosts) refs.add(h.moRef);
		Set<String> paths = new LinkedHashSet<>(Arrays.asList("name", "config.product.fullName", "config.product.build", "effectiveRole"));
		Map<String, VSphereClient.BulkRow> rows = refs.isEmpty() ? new HashMap<>() : c.retrieveObjects("HostSystem", refs, paths, null);
		for (VSphereClient.HostInfo h : hosts) {
			VSphereClient.BulkRow r = rows.get(h.moid);
			List<String> he = new ArrayList<>();
			for (String id : texts(r, "effectiveRole", "int")) he.add(id + "=" + roles.getOrDefault(id, "?"));
			System.out.println("  host " + h.moid + " " + VSphereClient.textOf(r, "name") + ": " + VSphereClient.textOf(r, "config.product.fullName") + " (build " + VSphereClient.textOf(r, "config.product.build") + "), effective role " + he);
		}
	}

	public static void main(String[] a) throws Exception {
		String user = System.getenv("VCENTER_CREDENTIAL");
		String pass = System.getenv("VCENTER_PASSWORD");
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkSelector sel = BenchmarkSelector.auto(all);
		SSLSocketFactory sf = systemTrust();
		for (String host : a) {
			System.out.println("=== " + host);
			VSphereClient c = new VSphereClient("https://" + host + "/sdk", user, pass, sf, LOG, true);
			CycleMetrics m = new CycleMetrics();
			c.setMetrics(m);
			try {
				c.ensureConnected();
				String vcVer = c.getVCenterVersion();
				long l0 = m.soapCalls();
				List<VSphereClient.HostInfo> hosts = c.getHosts();
				List<VSphereClient.VmInfo> vms = c.getVms();
				List<VSphereClient.DvsInfo> dvs = c.getDvSwitches();
				List<VSphereClient.DvpgInfo> pgs = c.getDvPortgroups();
				List<VSphereClient.ClusterInfo> cls = c.getClusters();
				long listing = m.soapCalls() - l0;
				identity(c, hosts);
				List<VSphereClient.VmInfo> realVms = new ArrayList<>();
				for (VSphereClient.VmInfo v : vms) if (!ComplianceDecisions.isPodGuestId(v.guestId)) realVms.add(v);
				System.out.println("vCenter " + vcVer + ": " + hosts.size() + " hosts, " + realVms.size() + " VMs, " + dvs.size() + " vDS, " + pgs.size() + " DVPG, " + cls.size() + " clusters; listing " + listing + " calls");

				Map<String, String> oldO = new TreeMap<>(), newO = new TreeMap<>();
				long[] oldCalls = new long[5], newCalls = new long[5];
				long oldEsx = 0, newEsx = 0;
				String[] kinds = {"Host", "VM", "vDS", "Portgroup", "Cluster"};
				int[] fbAdv = new int[5];
				int[] fbOther = new int[5];
				int[] fbCtl = new int[5];
				int[] bulkFailed = new int[5];

				Map<String, String> new2O = new TreeMap<>();
				long[] new2Calls = new long[5];
				long new2Esx = 0;
				for (int pass2 = 0; pass2 < 3; pass2++) {
					boolean bulk = pass2 >= 1;
					c.beginCycle();
					if (pass2 == 2) { new2Esx = newEsx; newEsx = 0; }
					Map<String, String> out = pass2 == 0 ? oldO : pass2 == 1 ? newO : new2O;
					long[] calls = pass2 == 0 ? oldCalls : pass2 == 1 ? newCalls : new2Calls;
					Map<String, String> hostVersions = new HashMap<>();
					// ---- hosts
					{
						long s0 = m.soapCalls(); long e0 = m.soapCalls(CycleMetrics.Phase.ESXCLI);
						Map<String, VSphereClient.BulkRow> rows = new HashMap<>();
						List<List<BenchmarkProfile.Control>> slices = new ArrayList<>();
						for (BenchmarkProfile p : all.values()) slices.add(p.hostControls());
						Set<String> paths = VSphereClient.primaryPaths("HostSystem", slices);
						int fbBefore = c.bulkFallbackReads();
						for (int i = 0; i < hosts.size(); i++) {
							VSphereClient.HostInfo h = hosts.get(i);
							VSphereClient.BulkRow row = null;
							if (bulk) {
								if (!rows.containsKey(h.moid) && i % page("HostSystem") == 0) {
									List<VSphereClient.MoRef> refs = new ArrayList<>();
									for (int j = i; j < Math.min(i + page("HostSystem"), hosts.size()); j++) refs.add(hosts.get(j).moRef);
									try { rows = c.retrieveObjects("HostSystem", refs, paths, null); } catch (Exception e) { rows = new HashMap<>(); bulkFailed[0] += refs.size(); System.err.println("  host bulk failed: " + e); }
								}
								row = rows.get(h.moid);
							}
							String ver = bulk ? VSphereClient.hostVersionOf(row) : null;
							if (ver == null) { if (bulk) fbOther[0]++; ver = c.getHostProductVersion(h.moRef); }
							hostVersions.put(h.moid, ver);
							out.put(h.moid + "|~version", String.valueOf(ver));
							BenchmarkSelector.Selection s = sel.select(BenchmarkSelector.Kind.HOST, BenchmarkSelector.governingVersion(BenchmarkSelector.Kind.HOST, null, ver));
							if (s.profile == null) { out.put(h.moid + "|~profile", s.profileName); continue; }
							List<BenchmarkProfile.Control> slice = s.profile.hostControls();
							String cs = bulk ? VSphereClient.textOf(row, "runtime.connectionState") : null;
							if (cs == null) { if (bulk) fbOther[0]++; try { cs = c.getHostConnectionState(h.moRef); } catch (Exception e) { cs = null; } }
							out.put(h.moid + "|~conn", String.valueOf(cs));
							if ("disconnected".equalsIgnoreCase(cs) || "notResponding".equalsIgnoreCase(cs)) continue;
							Map<String, String> am = bulk ? VSphereClient.advancedOf(row) : null;
							if (am == null) { if (bulk) fbAdv[0]++; try { am = c.getAdvancedSettings(h.moRef); } catch (Exception e) { am = null; } }
							if (am != null) out.put(h.moid + "|~advsize", String.valueOf(am.size()));
							if (am != null) out.put(h.moid + "|~advhash", String.valueOf(new TreeMap<>(am).hashCode()));
							outcomes(h.moid, merge(adv(slice, am, h.name), vim(c, h.moRef, slice, h.name, row)), out);
						}
						if (bulk) fbCtl[0] += c.bulkFallbackReads() - fbBefore;
						calls[0] = m.soapCalls() - s0 - (m.soapCalls(CycleMetrics.Phase.ESXCLI) - e0);
						if (bulk) newEsx += m.soapCalls(CycleMetrics.Phase.ESXCLI) - e0; else oldEsx += m.soapCalls(CycleMetrics.Phase.ESXCLI) - e0;
					}
					// ---- VMs
					{
						long s0 = m.soapCalls();
						Map<String, VSphereClient.BulkRow> rows = new HashMap<>();
						List<List<BenchmarkProfile.Control>> slices = new ArrayList<>();
						for (BenchmarkProfile p : all.values()) slices.add(p.vmControls());
						Set<String> paths = VSphereClient.primaryPaths("VirtualMachine", slices);
						int fbBefore = c.bulkFallbackReads();
						for (int i = 0; i < realVms.size(); i++) {
							VSphereClient.VmInfo v = realVms.get(i);
							VSphereClient.BulkRow row = null;
							if (bulk) {
								if (i % page("VirtualMachine") == 0) {
									List<VSphereClient.MoRef> refs = new ArrayList<>();
									for (int j = i; j < Math.min(i + page("VirtualMachine"), realVms.size()); j++) refs.add(realVms.get(j).moRef);
									try { rows = c.retrieveObjects("VirtualMachine", refs, paths, null); } catch (Exception e) { rows = new HashMap<>(); bulkFailed[1] += refs.size(); System.err.println("  vm bulk failed: " + e); }
								}
								row = rows.get(v.moid);
							}
							String hv = hostVersions.get(v.hostMoid);
							BenchmarkSelector.Selection s = sel.select(BenchmarkSelector.Kind.VM, BenchmarkSelector.governingVersion(BenchmarkSelector.Kind.VM, null, hv));
							if (s.profile == null) { out.put(v.moid + "|~profile", s.profileName); continue; }
							List<BenchmarkProfile.Control> slice = s.profile.vmControls();
							Map<String, String> am = bulk ? VSphereClient.advancedOf(row) : null;
							if (am == null) { if (bulk) fbAdv[1]++; try { am = c.getVmExtraConfig(v.moRef); } catch (Exception e) { am = null; } }
							if (am != null) out.put(v.moid + "|~advhash", String.valueOf(new TreeMap<>(am).hashCode()));
							outcomes(v.moid, merge(adv(slice, am, v.name), vim(c, v.moRef, slice, v.name, row)), out);
						}
						if (bulk) fbCtl[1] += c.bulkFallbackReads() - fbBefore;
						calls[1] = m.soapCalls() - s0;
					}
					// ---- vDS, DVPG, clusters
					for (int k = 2; k < 5; k++) {
						long s0 = m.soapCalls();
						List<VSphereClient.MoRef> refsAll = new ArrayList<>();
						List<String> names = new ArrayList<>();
						if (k == 2) for (VSphereClient.DvsInfo d : dvs) { refsAll.add(d.moRef); names.add(d.name); }
						if (k == 3) for (VSphereClient.DvpgInfo d : pgs) { refsAll.add(d.moRef); names.add(d.name); }
						if (k == 4) for (VSphereClient.ClusterInfo d : cls) { refsAll.add(d.moRef); names.add(d.name); }
						if (refsAll.isEmpty()) continue;
						BenchmarkSelector.Kind kind = k == 2 ? BenchmarkSelector.Kind.VDS : k == 3 ? BenchmarkSelector.Kind.PORTGROUP : BenchmarkSelector.Kind.CLUSTER;
						String type = refsAll.get(0).type;
						List<List<BenchmarkProfile.Control>> slices = new ArrayList<>();
						for (BenchmarkProfile p : all.values()) slices.add(ComplianceDecisions.sliceFor(p, kind));
						Set<String> paths = VSphereClient.primaryPaths(type, slices);
						BenchmarkSelector.Selection s = sel.select(kind, BenchmarkSelector.governingVersion(kind, vcVer, null));
						if (s.profile == null) continue;
						List<BenchmarkProfile.Control> slice = ComplianceDecisions.sliceFor(s.profile, kind);
						if (!hasEval(slice, "vim_property") && !hasEval(slice, "esxcli")) continue;
						Map<String, VSphereClient.BulkRow> rows = new HashMap<>();
						int fbBefore = c.bulkFallbackReads();
						for (int i = 0; i < refsAll.size(); i++) {
							VSphereClient.MoRef r = refsAll.get(i);
							VSphereClient.BulkRow row = null;
							if (bulk) {
								if (i % page(type) == 0) {
									try { rows = c.retrieveObjects(type, refsAll.subList(i, Math.min(i + page(type), refsAll.size())), paths, null); } catch (Exception e) { rows = new HashMap<>(); bulkFailed[k] += 1; System.err.println("  " + kinds[k] + " bulk failed: " + e); }
								}
								row = rows.get(r.value);
							}
							if (k == 4) {
								Boolean vs = bulk ? VSphereClient.vsanOf(row) : null;
								if (vs == null) { if (bulk) fbOther[k]++; try { vs = c.hasVsanConfig(r); } catch (Exception e) { vs = null; } }
								out.put(r.value + "|~vsan", String.valueOf(vs));
								if (vs == null || !vs) continue;
							}
							outcomes(r.value, vim(c, r, slice, names.get(i), row).controlResults, out);
						}
						if (bulk) fbCtl[k] += c.bulkFallbackReads() - fbBefore;
						calls[k] = m.soapCalls() - s0;
					}
				}
				// ---- compare
				int agree = 0, dis = 0;
				Set<String> keys = new TreeSet<>(oldO.keySet()); keys.addAll(newO.keySet());
				Map<String, Integer> perKindCtl = new TreeMap<>();
				for (String k : keys) {
					String o = oldO.get(k), n = newO.get(k);
					if (Objects.equals(o, n)) { agree++; if (!k.contains("|~")) perKindCtl.merge(k.replaceAll("-\\d+\\|.*", ""), 1, Integer::sum); }
					else { dis++; if (dis <= 40) System.out.println("  DISAGREE " + k + ": old '" + o + "' new '" + n + "'"); }
				}
				System.out.println("compared " + keys.size() + " outcome(s) (controls + version/conn/adv-map/vsan checks): " + agree + " agree, " + dis + " disagree; control outcomes by moid prefix " + perKindCtl);
				for (int k = 0; k < 5; k++) {
					System.out.println("  " + kinds[k] + ": OLD " + oldCalls[k] + " calls, NEW " + newCalls[k] + " calls (fallbacks: adv " + fbAdv[k] + ", version/conn/vsan " + fbOther[k] + ", controls " + fbCtl[k] + ", objects in failed bulk " + bulkFailed[k] + ")");
				}
				System.out.println("  second bulk cycle equal to first: " + new2O.equals(newO) + "; steady-state calls per kind " + Arrays.toString(new2Calls));
				System.out.println("  esxcli (unchanged path): OLD " + oldEsx + ", NEW " + newEsx);
				long oldTot = listing + oldEsx; long newTot = listing + newEsx;
				long new2Tot = listing + newEsx;
				for (int k = 0; k < 5; k++) { oldTot += oldCalls[k]; newTot += newCalls[k]; new2Tot += new2Calls[k]; }
				newTot = newTot - newEsx + new2Esx;
				System.out.println("  TOTAL incl. listing " + listing + " and esxcli: OLD " + oldTot + ", NEW first cycle " + newTot + ", NEW steady state " + new2Tot);
			} catch (Exception e) {
				System.out.println("  FAILED: " + e.getClass().getSimpleName() + ": " + e.getMessage());
			} finally {
				c.disconnect();
			}
		}
	}
}
