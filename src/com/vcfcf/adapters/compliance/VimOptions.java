package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Build 77 (review of build 76, BLOCKING): turn a vim25 SOAP response into
 * an option map, and refuse to do so when the call FAILED. SDK-free (JDK
 * DOM only) so the fault handling is unit-tested.
 *
 * <p>Before build 77 a SOAP fault on {@code QueryOptions} (host advanced
 * settings, vCenter settings) or on the VM {@code config.extraConfig}
 * read produced an EMPTY map, which the evaluator reads as "read OK,
 * nothing set": VM "X or Undefined" controls passed and host
 * advanced-setting controls silently dropped out of the score (a false
 * pass), and the build-76 cleanup then retired the object's real values.
 * Now a failed call throws {@link ReadFault}; the callers' existing error
 * handlers push the affected controls as UNREADABLE (-1), and an empty
 * map means only "the read succeeded and the key is not set".
 */
public final class VimOptions {

	private VimOptions() {}

	/** A vim25 read that failed (SOAP fault, missing service, no object). */
	public static final class ReadFault extends Exception {
		private static final long serialVersionUID = 1L;

		public ReadFault(String message) {
			super(message);
		}
	}

	/** The response, or a ReadFault naming what failed and why. */
	public static Document require(Document resp, String what, String lastFault)
			throws ReadFault {
		if (resp == null) {
			throw new ReadFault(what + " failed"
					+ (lastFault != null ? ": " + lastFault : ""));
		}
		return resp;
	}

	/**
	 * {@code QueryOptions} response -> key/value map. Each {@code returnval}
	 * is an OptionValue with {@code key} and {@code value}. Throws when the
	 * call failed ({@code resp == null}); an empty result is a genuinely
	 * empty option list.
	 */
	public static Map<String, String> fromQueryOptions(Document resp,
			String what, String lastFault) throws ReadFault {
		require(resp, what, lastFault);
		Map<String, String> out = new HashMap<>();
		for (Element rv : descendants(resp.getDocumentElement(), "returnval")) {
			String key = childText(rv, "key");
			String value = childText(rv, "value");
			if (key != null && value != null) out.put(key, value);
		}
		return out;
	}

	/**
	 * {@code RetrieveProperties} response for one object and one array-of-
	 * OptionValue property (VM {@code config.extraConfig}) -> key/value map.
	 * Throws when the call failed or returned no object ({@code returnval}
	 * absent: the object could not be confirmed). A present object whose
	 * property is not in the result means the property is unset: empty map.
	 */
	public static Map<String, String> fromPropertyOptions(Document resp,
			String propPath, String what, String lastFault) throws ReadFault {
		require(resp, what, lastFault);
		Element rv = first(resp.getDocumentElement(), "returnval");
		if (rv == null) {
			throw new ReadFault(what + ": no object in the response");
		}
		Map<String, String> out = new HashMap<>();
		for (Element propSet : children(rv, "propSet")) {
			if (!propPath.equals(childText(propSet, "name"))) continue;
			Element val = firstChild(propSet, "val");
			if (val == null) return out;
			for (Element item : children(val, null)) {
				String key = childText(item, "key");
				String value = childText(item, "value");
				if (key != null && value != null) out.put(key, value);
			}
			return out;
		}
		return out;   // property unset on the object: read OK, nothing set
	}

	// ----- tiny DOM helpers (local-name based, namespace tolerant) ---------

	static String localName(Node n) {
		String ln = n.getLocalName() != null ? n.getLocalName() : n.getNodeName();
		int c = ln.indexOf(':');
		return c >= 0 ? ln.substring(c + 1) : ln;
	}

	static List<Element> children(Element parent, String name) {
		List<Element> out = new ArrayList<>();
		for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (n.getNodeType() == Node.ELEMENT_NODE
					&& (name == null || name.equals(localName(n)))) {
				out.add((Element) n);
			}
		}
		return out;
	}

	static Element firstChild(Element parent, String name) {
		List<Element> c = children(parent, name);
		return c.isEmpty() ? null : c.get(0);
	}

	static String childText(Element parent, String name) {
		Element c = firstChild(parent, name);
		return c == null ? null : c.getTextContent();
	}

	static List<Element> descendants(Element root, String name) {
		List<Element> out = new ArrayList<>();
		collect(root, name, out);
		return out;
	}

	private static void collect(Element e, String name, List<Element> out) {
		for (Element c : children(e, null)) {
			if (name.equals(localName(c))) out.add(c);
			collect(c, name, out);
		}
	}

	static Element first(Element root, String name) {
		List<Element> d = descendants(root, name);
		return d.isEmpty() ? null : d.get(0);
	}
}
