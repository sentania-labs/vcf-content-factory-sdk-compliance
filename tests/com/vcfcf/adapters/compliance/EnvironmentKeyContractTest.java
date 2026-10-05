package com.vcfcf.adapters.compliance;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Build 83 (review of build 82, N3): pins the cross-artifact key contract
 * behind the ComplianceWorld environment totals. A rename on either side
 * would otherwise be silent (no data, no error).
 *
 * <ul>
 *   <li>(a) every ComputedMetric key on ComplianceWorld is a declared
 *       attribute under the Rollup &gt; Environment group nesting, and every
 *       declared Rollup|Environment attribute has a ComputedMetric (no
 *       adapter pushes those keys, so an uncomputed one is always empty).</li>
 *   <li>(b) every metric key the expressions read from
 *       VMWARE / VMwareAdapter Instance is a key {@link ComplianceRollup#toStats}
 *       actually produces. The {@code VCF-CF Compliance|Rollup|} prefix is
 *       {@link ComplianceRollup#PREFIX}, applied inside toStats; the push
 *       path (ComplianceStitcher.pushStats) sends the keys unchanged.</li>
 *   <li>(c) build 85 (review of build 84, N2): which source keys feed which
 *       environment key, in order, and the expression shape around them.
 *       (a) and (b) catch renames only; a swapped source key, a
 *       {@code Host|} reference in place of {@code All|}, an inverted
 *       avg_score division or a constant expression all passed them, and
 *       each is a silent wrong number.</li>
 *   <li>(d) build 86 (review of build 85, N3): each reference has exactly
 *       the parameters adapterkind, resourcekind, metric, in that order,
 *       separated by ", " as in VMWARE's describe.xml; an extra parameter
 *       such as {@code depth=2} or spacing the engine is not known to
 *       accept fails.</li>
 * </ul>
 * Run from the repo root.
 */
public final class EnvironmentKeyContractTest {

	private static final Pattern REF = Pattern.compile("\\$\\{([^}]*)\\}");

	public static void main(String[] args) throws Exception {
		DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
		f.setNamespaceAware(true);
		Document doc = f.newDocumentBuilder().parse(new File("describe.xml"));

		Element world = null;
		NodeList kinds = doc.getElementsByTagNameNS("*", "ResourceKind");
		for (int i = 0; i < kinds.getLength(); i++) {
			Element k = (Element) kinds.item(i);
			if ("ComplianceWorld".equals(k.getAttribute("key"))) world = k;
		}
		T.check(world != null, "describe.xml declares ComplianceWorld");

		// ---- (a) computed keys resolve to declared attributes
		Set<String> declared = new HashSet<>();
		collectAttributes(world, "", declared);
		Set<String> envDeclared = new LinkedHashSet<>();
		for (String k : declared) {
			if (k.startsWith("Rollup|Environment|")) envDeclared.add(k);
		}
		T.check(!envDeclared.isEmpty(),
				"Rollup > Environment attributes declared on ComplianceWorld");

		Set<String> computed = new LinkedHashSet<>();
		Map<String, String> expressionByKey = new LinkedHashMap<>();
		NodeList cms = world.getElementsByTagNameNS("*", "ComputedMetric");
		for (int i = 0; i < cms.getLength(); i++) {
			Element cm = (Element) cms.item(i);
			String key = cm.getAttribute("key");
			T.check(key.startsWith("Rollup|Environment|"),
					"ComputedMetric key under Rollup|Environment: " + key);
			T.check(declared.contains(key),
					"ComputedMetric key is a declared attribute: " + key);
			T.check(computed.add(key), "ComputedMetric key unique: " + key);
			expressionByKey.put(key, cm.getAttribute("expression"));
		}
		T.eq(envDeclared, computed,
				"every Rollup|Environment attribute has a ComputedMetric");

		// ---- (b) referenced metric keys are produced by toStats
		ComplianceRollup r = new ComplianceRollup();
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_8.0", 10, 1, 0,
				ControlEvaluator.score(9, 1, 0));
		r.recordNoBenchmark(BenchmarkSelector.Kind.VM);
		Map<String, Double> stats = r.toStats();

		int refs = 0;
		Map<String, List<String>> refsByKey = new LinkedHashMap<>();
		for (Map.Entry<String, String> ce : expressionByKey.entrySet()) {
			String expr = ce.getValue();
			List<String> keyRefs = new ArrayList<>();
			refsByKey.put(ce.getKey(), keyRefs);
			Matcher m = REF.matcher(expr);
			while (m.find()) {
				// Build 86 (review of build 85, N3): exactly the three
				// parameters, in the form VMWARE's own describe.xml ships
				// and the engine is known to evaluate:
				// "adapterkind=V, resourcekind=R, metric=M". Any extra
				// parameter (depth=2 changes what is summed) fails, and so
				// does spacing the engine has not been seen to accept
				// (around '=', after '${', before '}', a bare ',').
				String inner = m.group(1);
				String[] parts = inner.split(", ", -1);
				T.eq(3, parts.length,
						"reference has exactly three ', '-separated "
						+ "parameters: ${" + inner + "}");
				String[] names = {"adapterkind", "resourcekind", "metric"};
				String[] values = new String[3];
				for (int p = 0; p < 3; p++) {
					String part = parts[p];
					T.check(part.indexOf(',') < 0,
							"no bare ',' in a reference: ${" + inner + "}");
					int eq = part.indexOf('=');
					T.check(eq > 0, "parameter is name=value: " + part);
					T.eq(names[p], part.substring(0, eq),
							"parameter " + (p + 1) + " name (exact, no "
							+ "spacing) in ${" + inner + "}");
					String value = part.substring(eq + 1);
					T.check(!value.isEmpty() && value.equals(value.trim())
							&& value.indexOf('=') < 0,
							"parameter value has no surrounding spacing: '"
							+ value + "' in ${" + inner + "}");
					values[p] = value;
				}
				String adapterKind = values[0];
				String resourceKind = values[1];
				String metric = values[2];
				T.eq("VMWARE", adapterKind, "reference adapterkind in " + expr);
				T.eq("VMwareAdapter Instance", resourceKind,
						"reference resourcekind in " + expr);
				T.check(metric != null, "reference names a metric: " + expr);
				T.check(metric.startsWith(ComplianceRollup.PREFIX),
						"referenced key carries ComplianceRollup.PREFIX: "
						+ metric);
				T.check(stats.containsKey(metric),
						"referenced key is produced by toStats: " + metric);
				keyRefs.add(metric);
				refs++;
			}
			T.check(!keyRefs.isEmpty(),
					"ComputedMetric expression references a metric: "
					+ ce.getKey());
		}

		// ---- (c) pinned source keys per environment key, in order
		String all = ComplianceRollup.PREFIX + "All|";
		String sumOne = "sum(R)";
		String sumRatio = "sum(R)/sum(R)";
		Map<String, List<String>> wantRefs = new LinkedHashMap<>();
		Map<String, String> wantShape = new LinkedHashMap<>();
		wantRefs.put("Rollup|Environment|scored", List.of(all + "scored"));
		wantShape.put("Rollup|Environment|scored", sumOne);
		wantRefs.put("Rollup|Environment|non_compliant",
				List.of(all + "non_compliant"));
		wantShape.put("Rollup|Environment|non_compliant", sumOne);
		wantRefs.put("Rollup|Environment|no_benchmark",
				List.of(all + "no_benchmark"));
		wantShape.put("Rollup|Environment|no_benchmark", sumOne);
		// Weighted: summed score_sum over summed scored, in that order.
		wantRefs.put("Rollup|Environment|avg_score",
				List.of(all + "score_sum", all + "scored"));
		wantShape.put("Rollup|Environment|avg_score", sumRatio);

		T.eq(wantRefs.keySet(), computed,
				"pinned environment keys match the declared ComputedMetrics");
		for (Map.Entry<String, List<String>> w : wantRefs.entrySet()) {
			String key = w.getKey();
			for (String src : w.getValue()) {
				T.check(stats.containsKey(src),
						"pinned source key is produced by toStats: " + src);
			}
			T.eq(w.getValue(), refsByKey.get(key),
					"source keys (in order) feeding " + key);
			String shape = REF.matcher(expressionByKey.get(key))
					.replaceAll("R").replaceAll("\\s+", "");
			T.eq(wantShape.get(key), shape, "expression shape of " + key);
		}

		System.out.println("EnvironmentKeyContractTest: all assertions passed ("
				+ computed.size() + " computed keys, " + refs
				+ " metric references)");
	}

	/** Attribute paths ("Group|Sub|attr") under {@code parent}'s groups. */
	private static void collectAttributes(Element parent, String prefix,
			Set<String> out) {
		for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (!(n instanceof Element)) continue;
			Element e = (Element) n;
			String name = e.getLocalName();
			if ("ResourceGroup".equals(name)) {
				collectAttributes(e, prefix + e.getAttribute("key") + "|", out);
			} else if ("ResourceAttribute".equals(name)) {
				out.add(prefix + e.getAttribute("key"));
			}
		}
	}
}
