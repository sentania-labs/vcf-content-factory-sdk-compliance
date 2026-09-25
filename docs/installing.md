# Installing & Configuring — VCF Content Factory Compliance

## Prerequisites

- VCF Operations 8.x or 9.x (collect-path discovery is validated on
  9.0.2).
- Network reachability from the VCF Operations collector to your vCenter
  on **TCP 443** (vSphere SOAP / vim25 and the vCenter VAMI REST
  endpoints).
- A **vCenter account** for the adapter to authenticate with (vCenter SSO
  credentials). The account needs **read-only** access — the adapter only
  reads configuration; it performs no writes or remediation.
- One or more **compliance benchmark profiles**. The pack bundles the
  VMware Security Configuration Guide (SCG) 6.7, 7.0, 8.0, 9.0, and 9.1
  and by default (`Auto (by version)`) picks one per object by version;
  a custom profile is supplied as a canonical-schema CSV staged on the
  collector appliance.

## Permissions Required

The vCenter account needs read access sufficient to enumerate the
inventory and read host/vCenter configuration:

- Browse the inventory (hosts, clusters, datastores, distributed
  switches/portgroups, VMs).
- Read host configuration: advanced settings (`OptionManager`), services,
  firewall, and account/security settings (esxcli over the vCenter
  session).
- Read the vCenter appliance configuration via the VAMI REST endpoints
  (SSH, NTP, syslog, TLS profile, root password expiry, FIPS), only
  when **Read vCenter appliance settings** is turned on.

What the vCenter account needs depends on that one setting:

| Read vCenter appliance settings | vCenter account needs |
|---|---|
| Off (default) | The built-in **Read-only** role at the vCenter root, propagated to children. This covers the inventory and every host, VM, cluster and switch read. The appliance controls are reported for manual review. |
| On | The above, **plus** membership of the vsphere.local SSO group `SystemConfiguration.Administrators`. vCenter has no read-only role for the appliance API, and this group can also change appliance settings. The pack itself only reads. |

No remediation privileges are ever required: the pack writes nothing to
vCenter.

### On the VCF Operations side

The pack writes its results onto the existing vSphere objects through
the local VCF Operations Suite API. It does not use the vCenter account
for that, and you do not configure a credential for it. It uses, in
order:

1. The per-adapter-instance Suite API credential that VCF Operations
   issues to each adapter instance, when the platform provides one.
2. Otherwise the node's `automationAdmin` service account
   (`automationuser.properties`).
3. Otherwise the node's `maintenanceAdmin` account
   (`maintenanceuser.properties`), which works on a primary node only.

The collector log says which one is in use when the adapter starts.

## Network Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 443  | HTTPS    | Collector → vCenter | vSphere SOAP (vim25) inventory + host configuration reads, and vCenter VAMI REST policy reads |

The Suite API push to VCF Operations is **ambient** (local, on the
collector) and requires no additional outbound network configuration.

## TLS to vCenter — certificate trust

Since build 50 the adapter **validates the vCenter certificate against the
platform trust store by default** (strict TLS). You have two options:

1. **Recommended — import the vCenter certificate** into the VCF
   Operations platform trust store so the default strict-TLS path
   succeeds. Leave `allowInsecure` unset (or `false`).
2. **Opt out — set `allowInsecure=true`** on the adapter instance to
   disable certificate validation (trust-all). Only the literal string
   `true` opts in; any other value, blank, or absent keeps strict
   validation. The adapter logs a WARN at configure time when
   `allowInsecure=true`.

> **Upgrade note:** an instance pointed at a vCenter whose certificate is
> not in the platform trust store must either import the certificate or
> explicitly set `allowInsecure=true`, or vCenter SOAP collection will fail
> TLS validation. The failure is loud and names the remedy in the collector
> log.

## Configuration Fields

When adding a new adapter instance in VCF Operations, you will be prompted
for:

| Field | Key | Required | Default | Notes |
|-------|-----|----------|---------|-------|
| vCenter Host / IP | `vcenter_host` | Yes | — | FQDN or IP of the target vCenter. |
| Compliance Profile | `benchmark_profile` | Yes | Auto (by version) | `Auto (by version)` picks the SCG per object by version. Or force a bundled SCG (6.7 / 7.0 / 8.0 / 9.0 / 9.1) for every object, or `Custom`. Existing instances keep their stored choice on upgrade. |
| Custom Profile CSV Path (required if profile is Custom) | `custom_profile_path` | No | — | Filesystem path on the collector to an SCG-format CSV. Required only when the profile is `Custom`. |
| Read vCenter appliance settings | `read_appliance_settings` | No | false | Off: the vCenter appliance (VAMI) controls are manual review. On: they are read and scored; the account must be in the vsphere.local SSO group `SystemConfiguration.Administrators`, which also grants appliance write access (there is no read-only appliance role). Instances created before build 74 have no stored value and use the default. |
| Allow Insecure SSL (true to disable cert validation; default false = validate against platform trust store) | `allowInsecure` | No | false | `true` disables vCenter certificate validation. See TLS section above. |
| Username | `username` | Yes | — | vCenter account (SSO). Read-only access. |
| Password | `password` | Yes | — | vCenter account password (masked). |

## Step-by-Step Installation

1. Install the `.pak` file via **Administration > Solutions > Add**.
2. After installation, navigate to **Data Sources > Integrations > Accounts**.
3. Click **Add Account** and select **VCF Content Factory Compliance**.
4. Fill in the configuration fields above. Choose a bundled profile, or
   `Custom` with a CSV path staged on the collector.
5. Resolve TLS: import the vCenter certificate (recommended) or set
   `allowInsecure=true`.
6. Click **Validate Connection**, then **Add**.
7. On the first collection cycle the adapter discovers its Compliance
   World and begins pushing results onto the existing VMWARE hosts, VMs,
   vCenter, clusters, distributed switches and portgroups.
8. **Enable the four compliance super metrics.** Edit the policy active on
   `vSphere World` (in the policy editor, Metrics and Properties, filter
   on "Compliance") and enable
   Compliance Objects Scored, Compliance Non-Compliant Objects, Compliance
   Objects Without Benchmark and Compliance Average Score. Without this
   the Environment Overview's score tiles and trend stay empty. Whether
   the pak import already enables them is unconfirmed (to be checked at
   the devel install); check and enable if needed.
9. Open **[VCF Content Factory] Compliance Environment Overview**. The
   four bundled dashboards:

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment score, non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks. |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |

## Troubleshooting

- **vCenter SOAP fails with a TLS validation error** — the vCenter
  certificate is not trusted. Import it into the platform trust store, or
  set `allowInsecure=true`. See the TLS section.
- **"Compliance data not collected" alert, or a host scoring 0** (build
  63): the adapter could not read some or all of the object's settings,
  and unreadable settings count as failing. A disconnected or
  not-responding host scores 0. Check the object's connection state in
  vCenter, the adapter account's read permissions, and the adapter log for
  read errors naming the object; `unreadable_count` and the controls whose
  `Compliant` is -1 with Actual "(unreadable)" show which settings. The
  alert clears on the first cycle in which everything is read.
- **An object shows no compliance score / "no data"**: nothing was
  attempted on it (its version has no bundled SCG, `no_benchmark` = 1, or
  a non-vSAN cluster with no evaluable controls).
