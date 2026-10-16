# Installing & Configuring — VCF Content Factory Compliance

## Prerequisites

- **Allow Unsigned PAK Installation** on for every install or upgrade of this unsigned pak on VCF Operations 9.0 and 9.1 (8.x is unverified); see [Installing: allow unsigned paks first](../README.md#installing-allow-unsigned-paks-first).
- VCF Operations 8.x or 9.x (collect-path discovery is validated on
  9.0.2).
- Network reachability from the VCF Operations collector to your vCenter
  on **TCP 443** (vSphere SOAP / vim25 and the vCenter VAMI REST
  endpoints).
- A **vCenter account** for the adapter to authenticate with (vCenter SSO
  credentials). With **Read vCenter appliance settings** off (the
  default) it needs read access only; see Permissions Required. The adapter only
  reads configuration; it performs no writes or remediation.
- One or more **compliance benchmark profiles**. The pack bundles the
  VMware Security Configuration Guide (SCG) 6.7, 7.0, 8.0, 9.0, and 9.1
  and by default (`Auto (by version)`) picks one per object by version.
  To tune controls and thresholds for your site, use an overrides file in
  the VCF Operations configuration-file store (see
  [overrides.md](overrides.md)); nothing is staged on the collector.

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
| Off (default) | The built-in **Read-only** role at the vCenter root, propagated to children, for the inventory and the VM, cluster and switch reads. The host checks that run esxcli through vCenter (SSH, shell, secure boot, TPM, log settings) most likely also need **Host > CIM > CIM interaction** on the hosts (or a folder or cluster above them): this is the privilege VMware documents for esxcli over vCenter, but it has only been proven with a full administrator account so far. Without it those controls read as unreadable, never as passing. The appliance controls are reported for manual review. |
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

## TLS to vCenter: certificate trust

The adapter always validates the vCenter certificate. There is no
setting to turn validation off (build 93 removed Allow Insecure SSL).
Two things are checked on every connection the adapter opens to vCenter
(the vSphere SOAP session, esxcli, the vCenter REST API and the
appliance API):

- **The chain:** the certificate must be issued by a CA in the VCF
  Operations trust store, or be a certificate you accepted for this
  account in the Validate Connection dialog.
- **The name:** the certificate must carry the host you entered for
  vCenter. Since build 93 the adapter checks this itself on every
  connection, because the VCF Operations trust manager checks the chain
  only.

**Enter vCenter by the name on its certificate.** Use the FQDN (or the
address) the vCenter certificate lists, not an IP or short name the
certificate does not carry. Accepting a certificate does not fix a name
mismatch: the error says the certificate was issued for a different
name and tells you to re-enter the host.

When you click **Validate Connection**:

1. **The certificate is already trusted** (issued by a CA the VCF
   Operations trust store holds): validation goes straight on to the
   connection test. No dialog.
2. **The certificate is not trusted** (self-signed, or a private CA VCF
   Operations does not know): VCF Operations shows its **Review and
   Accept Certificate** dialog with the vCenter certificate. Check the
   details (issuer, validity, thumbprint against what vCenter shows) and
   accept it. Validation then runs the connection test. The accepted
   certificate is stored on this account and trusted on every collection
   cycle; nothing is copied to the collector.
3. **The connection test** logs in to the vCenter REST API and checks
   the chain and the name. A vCenter entered by an IP or a name the
   certificate does not list fails here with the name message, even
   after you accept its certificate in step 2: edit the host and
   validate again.

If vCenter's certificate changes later (renewed, or replaced by a new
CA), collection fails with a certificate error naming the vCenter. Open
the account, click **Validate Connection**, and accept the new
certificate. A renewed certificate that no longer lists the host you
entered fails with the name message instead.

A collection cycle that cannot reach vCenter (connection, login or
certificate failure) collects nothing. Since build 93 it sets
`VCF-CF Compliance|Rollup|incomplete` to 1 on the vCenter object, which
raises **Compliance data not collected** on that vCenter, so the scores
on the dashboards (which are from the last completed cycle) are not
mistaken for current ones. The adapter finds the vCenter object without
vCenter only when the host you entered equals that vCenter's address in
VCF Operations (its VCURL), or when an earlier cycle since the account
was last edited found it; otherwise the collector log says the marker
was not pushed. The next completed cycle sets it back to 0.

> **Upgrade note (build 93):** see the build 93 steps under Upgrading:
> record the settings before you upgrade, then Validate Connection each
> account that ran with Allow Insecure SSL `true`, and each account that
> names vCenter by an IP or a name not on its certificate (those stop
> collecting after the upgrade, even if they collected before, because
> the name is now checked).

## Configuration Fields

When adding a new adapter instance in VCF Operations, you will be prompted
for the vCenter host, the credential and the collector. **Overrides file**
and **Read vCenter appliance settings** are under **Advanced Settings** in
the same dialog. The pack has no profile choice: every object is scored
against the SCG for its own version (`Auto (by version)`); to pin a
version, use the overrides file ([overrides.md](overrides.md)).

| Field | Key | Required | Default | Notes |
|-------|-----|----------|---------|-------|
| vCenter Host / IP | `vcenter_host` | Yes | - | The target vCenter, by the name on its certificate (see the TLS section). |
| Overrides file (name of your copy in Management Packs Configuration, without .xml) | `overrides_file` | No | - | The name of your copy of `compliance_overrides_template` in Infrastructure Operations > Configurations > Management Packs Configuration, without `.xml`. Empty: no overrides. See [overrides.md](overrides.md). |
| Read vCenter appliance settings | `read_appliance_settings` | No | false | Off: the vCenter appliance (VAMI) controls are manual review. On: they are read and scored; the account must be in the vsphere.local SSO group `SystemConfiguration.Administrators`, which also grants appliance write access (there is no read-only appliance role). Instances created before build 74 have no stored value and use the default. |
| Username | `username` | Yes | — | vCenter account (SSO). Privileges depend on Read vCenter appliance settings; see Permissions Required. |
| Password | `password` | Yes | — | vCenter account password (masked). |

## Step-by-Step Installation

1. Install the `.pak` file via **Administration > Integrations > Repository > Add**.
2. After installation, open **Administration > Integrations > Accounts**.
3. Click **Add Account** and select **VCF Content Factory Compliance**.
4. Fill in the configuration fields above, entering vCenter by the name
   on its certificate. To tune controls or pin a guide version, set
   **Overrides file** under Advanced Settings later (see
   [overrides.md](overrides.md)).
5. Click **Validate Connection**. For a self-signed or private-CA
   vCenter, VCF Operations shows the vCenter certificate for review:
   accept it (see the TLS section).
6. Click **Add**.
7. On the first collection cycle the adapter discovers its Compliance
   World and begins pushing results onto the existing VMWARE hosts, VMs,
   vCenter, clusters, distributed switches and portgroups.
8. Open **[VCF Content Factory] Compliance Environment Overview**. Nothing
   needs enabling in a policy: its score tiles and trend read environment
   totals that VCF Operations computes on the pack's Compliance World
   (they appear one collection interval after the per-vCenter numbers).
   The four bundled dashboards, and the Summary tab on the Compliance
   World object:

| Dashboard | What it is for |
|---|---|
| [VCF Content Factory] Compliance Environment Overview | The landing page: environment score, non-compliant objects and objects without a benchmark, compliance by vCenter and object type, objects per SCG version, the score trend, and open compliance alerts. |
| [VCF Content Factory] Compliance ESX Hosts | Pick a scope (vSphere World or one vCenter), see its hosts worst first with score and applied SCG, select a host to see its failing controls and their runbooks (that panel is currently empty, issue #30). The Host Score Heatmap colors by score alone, so a host that could not be read keeps its last color; Not Read in the host list and the host details marks it (build 95). |
| [VCF Content Factory] Compliance VMs | The same flow for VMs, built for thousands of objects (sorted list and totals, no heatmap). |
| [VCF Content Factory] Compliance vCenter & Networking | One page for the low-count kinds: vCenter, cluster, distributed switch and distributed portgroup lists, worst first, with the selected object's failing controls. |
| [VCF Content Factory] Compliance World Summary | Not in the dashboard menu: it is the **Summary tab** of the pack's Compliance World object (build 88; find Compliance World in the inventory and open it). The Environment Overview re-cut for that tab: the four environment tiles, the last scan time, compliance by vCenter and object type, the score trend, objects per SCG version, and the open compliance alerts of the vCenter selected in the table. |

## Upgrading

- **Collection interval: edit each existing instance.** Since build 85 the
  pack's default collection interval is 5 minutes (it was 60). The default
  applies to new adapter instances only: an existing instance keeps the
  interval stored on it when the pak is upgraded (seen on a lab upgrade,
  where instances at 60 stayed at 60). After upgrading, edit each
  compliance adapter instance under **Administration > Integrations >
  Accounts** and set its collection interval to 5 minutes, or the value
  you want.
- **Setting the interval through the Suite API.** To script the edit, `GET
  /api/adapters/{id}`, set `monitoringInterval` to 5 in that full body,
  and `PUT /api/adapters` with it. Remove `collectorId` from the body
  first when it also carries `collectorGroupId`: the API takes one or the
  other, and a body with both is rejected with a 422 whose message
  ends "Either 'collectorId' or 'collectorGroupId' should be specified
  but not both.".
- **Retired super metrics are removed by the upgrade.** Builds 61 to 85
  shipped four super metrics on `vSphere World` for the Environment
  Overview's tiles ("[VCF Content Factory] Compliance Average Score",
  "... Non-Compliant Objects", "... Objects Scored", "... Objects Without
  Benchmark"). Build 86 no longer ships or uses them, and the Overview no
  longer needs any policy enablement. The pak upgrade removes the four
  super metrics from the instance (seen on a lab upgrade from build 85),
  so there is nothing to clean up by hand. The Environment Overview
  dashboard that read them is re-imported by the same upgrade and reads
  ComplianceWorld instead.
- **Alerts are renamed in place.** Build 86 prefixes every compliance
  alert name with `VCF Content Factory Compliance Alert: `. The alert
  definition ids do not change, so the upgrade renames the existing
  definitions rather than adding new ones. Alerts already open when you
  upgrade stay open under the new name with their alert ids and start
  times kept (seen on a lab upgrade: every active alert carried over).
- **Definitions take the new cycles.** Existing symptom and alert
  definitions pick up the build 86 wait and cancel cycles on the upgrade
  (per-control and score ones wait 1 and cancel after 3; the collection
  ones stay 1 and 1). Nothing to edit by hand.

- **The Custom profile CSV is removed (build 92).** The Custom Profile
  CSV Path setting is gone. Site changes go in an overrides file
  ([overrides.md](overrides.md)).
- **Build 93: before you upgrade, record each account's settings.**
  Build 93 removes the Compliance Profile and Allow Insecure SSL
  settings, and VCF Operations drops the stored value of a removed
  setting on upgrade (seen on a lab upgrade to build 92: the removed
  Custom Profile CSV Path was no longer stored on the three lab accounts
  afterwards). Before installing build 93, write down each compliance
  account's **Compliance Profile** and **Allow Insecure SSL** values,
  from the account's edit dialog or from `GET /api/adapters/{id}`
  (`resourceIdentifiers`, keys `benchmark_profile` and `allowInsecure`).
  After the upgrade that record is the only reliable source.
- **The Compliance Profile setting is removed (build 93).** Every
  account runs `Auto (by version)` from the first cycle after the
  upgrade, so the scores of an account that used a fixed SCG can move.
  To keep scoring every object of an account against one SCG, add
  `<Profile version="SCG 9.0"/>` (the version you recorded) to the
  account's overrides file ([overrides.md](overrides.md)). An account
  whose recorded profile is **blank** (accounts created before the pack
  chose a guide by version) was scored against SCG 8.0 and now runs
  Auto too; add `<Profile version="SCG 8.0"/>` to keep it on SCG 8.0. If
  the platform still hands the adapter the stored value, it logs one
  INFO line at configure time naming it and the entry to add; do not
  count on that line, use your record. The account keeps its id and
  history.
- **Allow Insecure SSL is removed (build 93).** Right after the upgrade,
  open each account that ran with Allow Insecure SSL `true`, click
  **Validate Connection**, accept the vCenter certificate if VCF
  Operations shows it, and check that the account's status is green.
  Until you do, an untrusted certificate fails every collection (with
  the "Compliance data not collected" alert on the vCenter where the
  vCenter object can be found; see the TLS section). If the platform
  still hands the adapter the stored value, it logs one WARN at
  configure time; do not count on it, use your record.
- **The certificate name is checked (build 93).** An account that names
  vCenter by an IP or a name the certificate does not list stops
  collecting after the upgrade, even if it collected before, and fails
  with "presented a certificate issued for a different name". Edit the
  host to the name on the certificate and click Validate Connection.

## Troubleshooting

- **All of one host's esxcli-backed controls are unreadable for a cycle**
  (the INFO line "Unreadable controls this cycle by reason" shows
  `esxcli-host-unreachable`): the first esxcli request of the cycle for
  that host timed out, could not connect, or got no esxcli executer back,
  so the adapter skipped the host's other esxcli commands for that cycle
  instead of waiting up to 120 s on each (build 86). Every esxcli request
  goes to vCenter's `/sdk`, which relays it to the host, so the failure
  may be vCenter's rather than the host's: if every host shows it, check
  vCenter first. A WARN line names the host and the first failure (build
  87), and the host's score line is logged at INFO because it has
  unreadable controls. The host is tried again on the next cycle.

- **"The certificate presented by vCenter ... is not trusted"** (on
  Validate Connection or in the collector log): open the account, click
  **Validate Connection** and accept the certificate when VCF Operations
  shows it. See the TLS section.
- **"vCenter ... presented a certificate issued for a different name"**
  (on Validate Connection or in the collector log; since build 93 also on
  accounts that collected before the upgrade): the account names vCenter
  by an IP or name the certificate does not list. Edit the account, enter the name on the certificate, and click
  Validate Connection. Accepting the certificate does not fix this.
- **"Compliance data not collected" alert, or an object on the Objects
  with Unreadable Controls list** (build 95): the adapter could not read
  some or all of the object's settings for two cycles in a row. Those
  settings are not pushed (their last values stay) and the object's score
  counts only what was read, so a partial outage can move it either way
  and raise or cancel Host Compliance Score Degraded. A disconnected or
  not-responding host keeps its last score, shown with Not Read = 1
  beside it in the per-kind views and the ESX Hosts host details. The
  object's
  `unreadable_reason` property says why in plain words (for example "host
  not responding" or "permission refused") with the logged detail, and
  `unreadable_controls` lists the settings. Check the object's connection
  state in vCenter, the adapter account's read permissions, and the
  adapter log for read errors naming the object. The alert clears on the
  first cycle in which everything is read. On a
  vCenter, the same alert with `VCF-CF Compliance|Rollup|incomplete` = 1
  and the account in error means the last cycle could not reach vCenter
  at all (build 93): the collector log and the account status give the
  reason, and the scores shown are from the last completed cycle.
- **"Compliance overrides file not loaded" alert** (build 90): the
  account's Overrides file names a file that does not exist in
  Infrastructure Operations > Configurations > Management Packs
  Configuration,
  or the file is not valid XML. The vCenter object's
  `VCF-CF Compliance|Summary|overrides_status` says which, and the
  adapter log names the problem. See [overrides.md](overrides.md).
- **An object shows no compliance score / "no data"**: nothing was
  attempted on it (its version has no bundled SCG, `no_benchmark` = 1, or
  a non-vSAN cluster with no evaluable controls).
