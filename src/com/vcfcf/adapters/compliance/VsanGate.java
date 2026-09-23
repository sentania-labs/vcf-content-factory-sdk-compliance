package com.vcfcf.adapters.compliance;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Build 74: is vSAN enabled on a cluster? SDK-free (JDK DOM only) so it is
 * unit-tested.
 *
 * <p>vCenter 9.x serialises {@code configurationEx.vsanConfigInfo} for EVERY
 * cluster, with {@code enabled=false} when vSAN is off
 * (knowledge/context/api-surface/compliance_config_encryption_and_vsan_checksum_reads.md,
 * section 4). The pre-74 gate tested only that the element exists, so
 * non-vSAN clusters were scored on vSAN controls and
 * {@code cluster.managed-disk-claim} recorded a false pass on them. vSAN is
 * enabled only when {@code vsanConfigInfo/enabled} reads {@code true};
 * {@code false}, an absent {@code enabled}, or no {@code vsanConfigInfo}
 * means not enabled, so the vSAN controls are not applicable (no score, no
 * unreadable). A FAILED read of {@code configurationEx} is the caller's
 * business (unreadable), never "not enabled".
 */
public final class VsanGate {

	private VsanGate() {}

	/**
	 * @param configurationEx the {@code <val>} element of the cluster's
	 *        {@code configurationEx} property (non-null: the read succeeded)
	 */
	public static boolean vsanEnabled(Element configurationEx) {
		if (configurationEx == null) return false;
		Element vsan = child(configurationEx, "vsanConfigInfo");
		if (vsan == null) return false;
		Element enabled = child(vsan, "enabled");
		if (enabled == null) return false;
		String t = enabled.getTextContent();
		return t != null && "true".equalsIgnoreCase(t.trim());
	}

	private static Element child(Element parent, String localName) {
		for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (n.getNodeType() != Node.ELEMENT_NODE) continue;
			String ln = n.getLocalName() != null ? n.getLocalName()
					: n.getNodeName();
			int colon = ln.indexOf(':');
			if (colon >= 0) ln = ln.substring(colon + 1);
			if (localName.equals(ln)) return (Element) n;
		}
		return null;
	}
}
