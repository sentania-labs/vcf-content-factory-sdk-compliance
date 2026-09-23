# Controls We Do Not Audit

This document ships **inside the pak** (bundled at
`vcfcf_compliance/conf/profiles/UNAUDITED_CONTROLS.md`). It is the honest
coverage statement for the VCF Content Factory Compliance adapter against
the VMware Security Configuration Guide (SCG) 8.0 / 9.0 profiles.

> **SCG 9.1 (build 56):** the 9.1 profile was added after this document
> was reconciled. Canonical `control_id`s are *mostly* version-stable,
> so the 9.0 entries below carry over to the 9.1 rows that share a
> control_id — but not perfectly: an upstream Setting-Location text
> change migrated `vds.network-reset-port` to `dvpg.network-reset-port`
> in 9.1 (recipe re-attached under the new id in build 56, review W1),
> so id equality alone is not proof of parity. The 9.1-only additions
> (new `esx.*`/`vm.*` controls plus the `automation.*` / `pnr.*`
> sub-products) load as `manual_audit` / `powercli_only` unless a read
> recipe matched, and are therefore in bucket 1/3 by construction —
> never scored, never a pass. A full 9.1 reconciliation pass of this
> document is **pending as of 2026-08-25 (build 56)**; if a later
> build's changelog does not record it done, treat 9.1 coverage claims
> in this file as unverified.

The adapter machine-audits every control it *can* assess from the vCenter
vim25 SOAP surface (advanced settings + `vim_property` read recipes) and
the esxcli-over-vCenter-session surface (esxcli `read_recipe` recipes,
builds 36/37). The controls below it does **not** fully audit. They fall
into three buckets, matching how an operator should think about them:

1. **Cannot** — there is no machine-readable signal the adapter can reach.
   These require human review, off-box inspection, or a separate product's
   API. They will never be auto-scored by this adapter.
2. **Wired — pending live field-name verification** — a `read_recipe`
   *is* in place and these controls *are* scored, but the recipe's row /
   field names were *derived from documentation, not captured on the wire*.
   They are safe-by-construction (a wrong field name reads as
   `unreadable`, never a false `pass`), but coverage is **unproven** until
   a live run confirms the field names. Audited, but flagged.
3. **Haven't fully explored yet** — the state *is* reachable via an API,
   but needs a reader (a new `read_recipe` style, or a non-vim25 reader)
   the adapter has not built. These are backlog, not dead ends.

A control being absent here means it is (or is intended to be) audited.
A control under "Cannot" or "Haven't yet" is **never** reported as a
`pass` — it ships as `manual_audit` / informational, excluded from every
compliance score. The "Wired — pending verification" controls ARE scored
(they are not in the unaudited set); they are listed here only as a
coverage-honesty flag that the recipe is not yet wire-confirmed. (Where a
recipe is declared but the live read returns nothing, the adapter raises
an explicit `unreadable_count` signal — that is a distinct coverage
warning, not a pass.)

Source of record: `context/investigations/scg89-audit-coverage-recon.md`.

---

## Manual review: prose expected values (build 57)

Some controls the adapter CAN read carry prose instead of a value as the
SCG expected result ("Site-Specific Log Server", "Consult your
organization's legal advisors for text ..."). No real setting can equal
that text, so scoring them failed every object (false fails, never false
passes). Since build 57 they are listed in `profiles/manual_review.csv`
and load as `manual_audit`: not scored, no per-control keys, no alert.
The overlay is per profile (a control is demoted only in the profiles
that list it) and applies to bundled profiles only, never to a Custom
profile. Site values for these controls are the job of the planned
per-connection control overrides.

| Profile | control_ids |
|---|---|
| 6.7 | `esx.logs-remote`, `esx.lockdown-dcui-access`, `esx.account-password-policies`, `vm.transparentpagesharing-inter-vm-enabled` |
| 7.0 | `esx.annotations-welcomemessage`, `esx.etc-issue`, `esx.logs-remote`, `vc.etc-issue` |
| 8.0 | `esx.annotations-welcomemessage`, `esx.etc-issue`, `esx.logs-remote`, `vc.etc-issue` |
| 9.0 | `esx.etc-issue`, `esx.log-forwarding`, `esx.login-message`, `vc.etc-issue`, `esx.ad-admin-group-name` |
| 9.1 | `esx.ad-admin-group-name`, `esx.etc-issue`, `esx.log-forwarding`, `esx.login-message`, `vc.etc-issue` |

The coverage tables below count these controls as scored (they are
scored rows in the canonical CSV); subtract the overlay rows for the
effective count.

## SCG 6.7 and 7.0 profiles (added 2026-09-23, selectable since build 57)

The SCG 6.7 and 7.0 canonical profiles (`scg_6.7.csv`, `scg_7.0.csv`)
are selectable since build 57, as fixed profiles and through
`Auto (by version)` (ESXi 6.7 / 7.0 hosts and their VMs, vCenter 6.7 /
7.0 objects). The same three buckets apply, and the sections
further down that name a control_id apply to the 6.7 / 7.0 row carrying
that id, because matched controls share the id, the read recipe, and
therefore the coverage of their 8.0 row.

**Coverage at a glance** (scored = evaluable advanced_setting, or a
vim_property / esxcli / vami_api row with a read recipe):

| Profile | Controls | Scored | Unscored (informational) |
|---|---|---|---|
| SCG 7.0 | 122 | 82 | 40 (30 powercli_only, 7 manual_audit, 3 esxcli with no recipe) |
| SCG 6.7 | 51 | 36 | 15 (13 powercli_only, 1 manual_audit, 1 esxcli with no recipe) |

**SCG 7.0 unscored controls.** Every 7.0 control_id also exists in 8.0
and is unscored there for the same reason. (`vm.virtual-hardware` was
the one 7.0-only exception until build 57: its baseline
`vmx-13 or newer` is now compared as a minimum and the row is scored.)

Other 7.0 unscored ids (same bucket as their 8.0 entries below):
`dvpg.network-vgt` (ESX standard-switch row only; the distributed-switch
row is scored), `esx.ad-auth-proxy`, `esx.firewall-restrict-access`,
`esx.iscsi-mutual-chap`, `esx.lockdown-exception-users`,
`esx.secureboot`, `esx.supported`, `esx.updates`,
`esx.vib-acceptance-level-supported`, `esx.vmk-management`,
`vc.administration-client-session-timeout`,
`vc.administration-failed-login-interval`,
`vc.administration-login-message-details`,
`vc.administration-login-message-enable`,
`vc.administration-login-message-text`, `vc.administration-sso-groups`,
`vc.administration-sso-lockout-policy-max-attempts`,
`vc.administration-sso-lockout-policy-unlock-time`,
`vc.administration-sso-password-lifetime`,
`vc.administration-sso-password-policy`,
`vc.administration-sso-password-reuse`, `vc.events-database-retention`,
`vc.supported`, `vc.vami-backup`, `vc.vami-updates`,
`vm.remove-unnecessary-devices`, the 14 `vm.tools-*` controls.

**SCG 6.7 unscored controls.**

- Unmatched 6.7 controls (no newer control means the same thing, so
  they keep 6.7-native ids and have no read recipe):
  `esx.config-snmp` (6.7 passes SNMP that is off OR properly
  configured), `esx.enable-ad-auth`, `esx.enable-strict-lockdown-mode`
  (newer guides baseline normal lockdown), `vm.disable-independent-nonpersistent`,
  `vm.disconnect-devices-floppy`, `vm.disconnect-devices-parallel`,
  `vm.disconnect-devices-serial` (newer guides fold all three into
  `vm.remove-unnecessary-devices`; kept separate here). All Cannot or
  Haven't-yet; none is ever a pass.
- `vm.dvfilter`: the 6.7 key is written as a pattern
  (`ethernetX.filterX.name = filtername`), not a real key, so it is
  manual_audit.
- Matched, unscored for the same reason as their newer row:
  `esx.ad-auth-proxy`, `esx.firewall-restrict-access`,
  `esx.iscsi-mutual-chap`, `esx.lockdown-exception-users`,
  `esx.updates`, `esx.vib-acceptance-level-supported`,
  `vds.vds-health-check-disable`.
- One unmatched 6.7 control IS scored: `vm.minimize-console-vnc-use`
  reads the VM advanced setting `RemoteDisplay.vnc.enabled` (expected
  FALSE). It has no newer counterpart, but the read is the ordinary VM
  advanced-setting path.

**Recipes inherited from the 8.0 lineage are not verified on 6.7 / 7.0
hosts.** The vim25 paths, esxcli namespaces, service keys, and VAMI
endpoints were wire-checked (where they were checked at all) against
8.x / 9.x. On a 6.7 or 7.0 host or vCenter a path that does not exist
reads as UNREADABLE, never a pass (for example `config.encryptionState`
for `esx.tpm-configuration`, or the `/api/appliance/*` VAMI endpoints
that older 7.0 vCenter builds serve under `/rest/`), so the risk is
coverage, not correctness. Treat 6.7 / 7.0 coverage as claimed, not
proven, until a live 6.7 / 7.0 run.

**Known false fails carried into the new profiles (not fixed here).**
Scored controls whose expected value is prose that no real value can
equal: 7.0 `esx.annotations-welcomemessage`, `esx.logs-remote`,
`vc.etc-issue` (the same rows as 8.0), 6.7 `esx.logs-remote`,
`esx.lockdown-dcui-access`, `esx.account-password-policies`,
`vm.transparentpagesharing-inter-vm-enabled`. A host that has the
setting fails; a host without it skips. These are false fails, never
false passes; scheduled for the engine change that makes the profiles
selectable. (7.0 `esx.etc-issue` carries the key as `Config.Etc.Issue`;
8.0 has `Config.Etc.issue` and the settings lookup is case-sensitive, so
the 7.0 row is expected to skip rather than fail. Not live-verified.)

---

## Partial-coverage controls (audited, but read the caveat)

Several reclassified controls are audited with **less than full fidelity**.
A `pass` does NOT mean the whole SCG control is satisfied. These caveats are
also embedded in each control's description in the profile CSV.

| control_id | What is checked | What is NOT checked |
|---|---|---|
| `dvpg.network-restrict-port-level-overrides` | `config.policy.securityPolicyOverrideAllowed` is disabled (1 of ~7 override flags) | block / teaming / vlan / shaping / vendorConfig / ipfix / trafficFilter per-port overrides |
| `vm.virtual-hardware` (8.0, 9.0) | `config.version` equals the SCG baseline string exactly (`vmx-21` / `vmx-19`) | "version N **or newer**": a higher-than-baseline VM reads as non-compliant. (7.0 and 9.1 phrase the baseline as a floor, `vmx-13 or newer` / `vmx-17 or higher`, and since build 57 are compared as a minimum: `vmx-M` passes iff M >= N.) |
| `esx.timekeeping-services` (8.0) | ntpd service is **running** (`service_state:ntpd:running`, build 38) | ntpd **start policy** = `on` (start-with-host); PTP as an alternative time source |
| `esx.time` (9.0) | ntpd service is **running** — the NTP daemon-running half only (`service_state:ntpd:running`, build 38) | the NTP **source-list** half (`config.dateTimeInfo.ntpConfig.server` non-empty); ntpd start policy = `on`; PTP. This control row already carries the daemon-running recipe and a CSV row holds one recipe, so the source-list half **cannot** be added to this row — it stays documented-partial here, NOT separately scored. (Its distinct 8.0 sibling `esx.timekeeping-sources` IS fully audited via `(non-empty)`, build 39.) |
| `esx.snmp` (9.0) | snmpd service is **not running** (`service_state:snmpd:running`, build 38) | per-version SNMP config (the title also names disabling SNMP v1/v2 specifically); the running-flag check enforces the broader "SNMP deactivated" intent |

> **NTP source-list controls.** The NTP server list is readable
> (`config.dateTimeInfo.ntpConfig.server`), but the SCG baseline value is
> the sentinel "Site-Specific", which no real server list can
> string-equal — string-equality would manufacture a permanent false
> "fail". Build 39 added a **presence / non-empty** comparison mode
> (`expected_value=(non-empty)`; see `CANONICAL_SCHEMA.md`) that passes the
> control as soon as ≥1 NTP server is configured.
>
> - **`esx.timekeeping-sources` (8.0)** is a **distinct control row** and
>   is now **fully reclassified to `vim_property`** with
>   `read_recipe=string_list_join:config.dateTimeInfo.ntpConfig.server`,
>   `expected_value=(non-empty)` (build 39). It has left the backlog — it
>   is audited. A host with zero NTP servers reads as UNREADABLE (an empty
>   list resolves to null upstream), never a false pass.
> - **`esx.time` (9.0)** bundles the NTP daemon-running half AND the NTP
>   source-list half into **one** control row, and that row already carries
>   `service_state:ntpd:running` (build 38, daemon-running half). A CSV row
>   carries exactly one `read_recipe`, so the source-list half **cannot**
>   be added to the same row. The 9.0 NTP **source-list half therefore
>   stays documented-partial** here — it is NOT separately scored and NOT
>   double-counted against the 8.0 `esx.timekeeping-sources` coverage.

---

## Cannot (genuinely manual — no machine-readable signal)

### In-guest state (not on the vCenter SOAP surface)

VMware Tools `tools.conf` settings live inside the guest OS filesystem;
they are not reachable via PropertyCollector, `extraConfig`, or any
vCenter SOAP/REST endpoint. (14 controls in 8.0, 14 in 9.0.)

`vm.tools-add-feature`, `vm.tools-allow-transforms`,
`vm.tools-deactivate-appinfo`, `vm.tools-deactivate-containerinfo`,
`vm.tools-deactivate-guestoperations`, `vm.tools-deactivate-gueststoreupgrade`,
`vm.tools-deactivate-servicediscovery`, `vm.tools-enable-logging`,
`vm.tools-enable-syslog`, `vm.tools-globalconf`,
`vm.tools-prevent-recustomization`, `vm.tools-remove-feature`,
`vm.tools-upgrade`. (`vm.tools-updates` needs a lifecycle DB, also manual.)

### ESXi SSH daemon (`sshd_config`) — the FIPS-enable flag only

The SSH daemon's *config parameters* (ciphers, gateway-ports, idle
timeouts, banner, rhosts, forwarding, tunnels, user-environment) are now
read via `esxcli system ssh server config list` over the vCenter session
(build 37) — see the "Wired — pending verification" section below. The
one SSH control that remains genuinely unaudited is the FIPS-enable flag,
which has no list/get read recipe wired:

`esx.ssh-fips` (`system security fips140 ssh get` — no recipe wired yet).

### ESXi host — no PropertyCollector path / per-account / kernel boot

`esx.entropy` (kernel boot param),
`esx.firewall-restrict-access` (per-ruleset IP allowlist — env-specific),
`esx.iscsi-mutual-chap` (per-HBA credential check),
`esx.lockdown-exception-users` (managed-object method, not a property),
`esx.vmk-management` / `esx.vmk-storage` / `esx.vmk-vmotion`
(environment-specific network design), `esx.nfs-encryption` (AD/Kerberos
design decision).

> Per-account shell flags and key persistence that previously sat in this
> bucket are now read via esxcli (build 37) — see "Wired — pending
> verification" below.

### Physical / firmware / off-box hardware (9.0 hardware-* family)

Not exposed via vim25 — system firmware, BMC/iDRAC, physical media:
`esx.secureboot` / `esx.hardware-secureboot` (UEFI firmware),
`esx.hardware-boot` (boot media type), `esx.hardware-cpu-amd-cc`,
`esx.hardware-cpu-intel-cc`, `esx.hardware-cpu-intel-txt`,
`esx.hardware-firmware-updates`, `esx.hardware-management-authentication`,
`esx.hardware-management-log-forwarding`, `esx.hardware-management-security`,
`esx.hardware-management-time`, `esx.hardware-ports`, `esx.hardware-tpm`.

### Lifecycle / patch baseline (no "unsupported/unpatched" API signal)

`esx.supported`, `esx.updates`, `vc.supported`, `vc.vami-updates`.

### vCenter — no confirmed public API / org-policy / banner shell

`vc.administration-client-session-timeout`, `vc.events-database-retention`
("no public API"), `vc.administration-login-message-enable` / `-text` /
`-details` / `vc.login-message` (sso-config.sh shell, no REST),
`vc.administration-sso-groups`, `vc.administration-sso-password-policy` /
`vc.password-complexity`, `vc.administration-client-plugins`,
`vc.bashshelladministrators`, `vc.disable-accounts`, `vc.account-alert`,
`vc.log-level`, `vc.native-key-provider-backup`, `vc.smtp` (credential
fields), `vc.snmp` / `vc.snmp3` (no confirmed endpoint),
`vc.vami-backup`, `vc.vami-firewall-restrict-access`,
`vc.drs` / `vc.service-resilience-ha` / `-evc` / `-vmotion` (config
decisions requiring operator judgment).

### vSAN — vSAN Management SDK classpath gap

The bulk of `ClusterComputeResource` controls live on the vSAN Management
SDK (`com.vmware.vim.vsan.binding`), which is NOT on this adapter's
classpath (per-pak classloader isolation; see
`context/investigations/2026-05-29-vsan-management-sdk-gap.md`). Two vSAN
controls ARE audited today via plain vim25 (`cluster.managed-disk-claim`,
`cluster.object-checksum`). The rest cannot be read:

`cluster.encryption-rest` / `cluster.data-at-rest`,
`cluster.encryption-transit-esa` / `-osa` / `cluster.data-in-transit`,
`cluster.force-provisioning`, `cluster.iscsi-mutual-chap`,
`cluster.file-services-access-control-nfs`,
`cluster.file-services-authentication-smb`, `cluster.operations-reserve`,
`cluster.automatic-rebalance`, `cluster.auto-policy-management`,
`cluster.network-isolation-vsan-iscsi-target`,
`cluster.network-isolation-vsan-max`.

### vCenter SSO lockout / password policy — SSO admin SDK + WS-Trust classpath gap

The SSO lockout and password-policy controls (the PowerCLI
`Get-SsoLockoutPolicy` / `Get-SsoPasswordPolicy` surface) are readable only
via the vCenter SSO admin SOAP service, which requires first acquiring a
Holder-of-Key SAML token from the STS (`/sts/STSService/vsphere.local`) via
a WS-Trust `RequestSecurityToken` exchange, signing the RST with the
caller's credential, then calling the SSO admin endpoint with that
assertion. **None of that machinery is on this adapter's classpath**
(build-42 feasibility recon, 2026-06-03):

- No SSO admin client bindings (`com.vmware.vim.sso*` — absent).
- No STS / `SecurityTokenService` / WS-Trust `RequestSecurityToken`
  bindings (absent).
- No SAML token-issuance / Holder-of-Key / XML-DSig / WSS security-header
  machinery to construct and sign the RST (`vim-vmodl-bindings` only ships
  `SAMLTokenAuthentication`, a *consumer* struct for passing an
  already-issued token *into* vim — not a client to obtain one). `lib/`
  carries `vim25.jar`, `vim-vmodl-bindings-8.0.2.jar`, and the generic
  JAX-WS runtime (`jaxws-rt`, `jaxws-api`, `javax.xml.soap-api`) — nothing
  that speaks STS/WS-Trust.

Acquiring a Holder-of-Key SAML token is not a small JAX-WS dispatch: it
needs the STS WSDL bindings, an XML-DSig signer over the RST body and
timestamp, and the SSO admin WSDL bindings — i.e. the `ssoclient` /
`vmware-sts` libraries shipped with the vSphere SSO Client SDK. Those would
have to be added to `lib/` (heavyweight new dependencies), and per-pak
classloader isolation makes hand-rolling a partial WS-Trust client a
fragility trap. Hand-rolling it without real token signing **cannot
actually authenticate** — and a failed read must never fold to a pass
(cardinal rule), so a fake transport is not an option. These 10 controls
therefore stay **manual**, mirroring the vSAN SDK classpath gap above:

`vc.administration-sso-lockout-policy-max-attempts`,
`vc.administration-sso-lockout-policy-unlock-time`,
`vc.administration-failed-login-interval`,
`vc.administration-sso-password-lifetime`,
`vc.administration-sso-password-reuse` (8.0);
`vc.account-lockout-duration`, `vc.account-lockout-max-attempts`,
`vc.account-lockout-reset`, `vc.password-history`,
`vc.password-max-age` (9.0).

> These are the vCenter-level SSO policy controls. The ESXi-host equivalents
> (`esx.account-lockout`, `esx.account-password-history`,
> `esx.account-lockout-duration`, `esx.account-lockout-max-attempts`,
> `esx.password-max-age`, etc.) are `Security.*` advanced settings and ARE
> audited — they do not need the SSO SDK.

### Separate products (no API reach from this adapter)

NSX, VCF Operations, VCF Operations for Logs, VCF Operations for Networks,
SDDC Manager, and VCF-umbrella controls are separate systems with separate
management APIs the compliance adapter does not connect to. All `nsx.*`,
`ops.*`, `logs.*`, `networks.*`, `sddc.*`, `installer.*`, `vcf.*`, and
`fleet.*` controls fall here (40+ controls in 9.0). Examples:
`nsx.ssh`, `nsx.tls-ciphers`, `ops.fips`, `ops.session-timeout`,
`logs.tls-ciphers`, `networks.session-timeout`, `sddc.api-admin`,
`vcf.mfa`, `vcf.perimeter-firewall`, `fleet.log-forwarding`.

### Organizational / design / meta controls

`vm.remove-unnecessary-devices` ("unnecessary" is env-specific),
`vcf.permissions-roles`, `vcf.secure-baseline` (this guide IS the
baseline), `vcf.time` (fleet policy statement).

> **Total "Cannot": ~150 controls** across both profiles (~13 fewer than
> before build 37, which wired the SSH-daemon-config / account-shell /
> key-persistence controls — now listed below as wired-but-unverified, not
> unaudited; +10 at build 42, the vCenter SSO lockout/password-policy
> cluster, moved from backlog to a confirmed SSO-admin-SDK/WS-Trust
> classpath gap).

---

## Wired — pending live field-name verification

These controls **are scored** by the adapter (they have a non-empty
`read_recipe` in the canonical CSV and are NOT in the unaudited set). They
are flagged here for one reason: the esxcli row/field names in their
recipes were **derived from documentation, not captured on the wire**. The
build-36 spike only empirically proved ONE esxcli response shape on the
wire — `system.syslog.config.get` (the `LocalLogOutputIsPersistent`
field). Everything below reuses that reader but with field names that have
not yet been confirmed against a live host.

Safe-by-construction: if a derived field/row name is wrong, the read
returns `null` → the `UNREADABLE` sentinel (counted in `unreadable_count`,
excluded from every score). A wrong field name can therefore produce a
coverage gap, **never a false `pass`**. But until a live run confirms
them, treat the coverage here as *claimed, not proven*. A live ESXi 8.0
run is exactly what promotes these to proven coverage.

### List-command row selectors (highest uncertainty)

The `list`-command row-selector grammar (`<Field>[<Selector>=<value>]`)
assumes both the row-element field names AND the selector field names. The
spike's own recipe sketch used a *different* row model than what shipped,
so these are the least-confirmed:

| control_id(s) | recipe | derived assumption |
|---|---|---|
| `esx.ssh-fips-ciphers`, `esx.ssh-gateway-ports`, `esx.ssh-host-based-auth`, `esx.ssh-idle-timeout-count`, `esx.ssh-idle-timeout-interval`, `esx.ssh-login-banner`, `esx.ssh-rhosts`, `esx.ssh-stream-local-forwarding`, `esx.ssh-tcp-forwarding`, `esx.ssh-tunnels`, `esx.ssh-user-environment` (8.0 — 11 controls) | `esxcli:system.ssh.server.config.list:Value[Key=…]` | row keyed `Key`, value field `Value` |
| `esx.account-dcui`, `esx.account-vpxuser` (8.0); `esx.disable-accounts-dcui` (9.0) | `esxcli:system.account.list:Shellaccess[UserID=…]` | row keyed `UserID`, value field `Shellaccess` (one indirect data point: devel saw `Shellaccess=true` for dcui — supports this shape only) |

### Get-struct single fields (lower uncertainty — same reader shape as the proven `syslog.config.get` slice)

These reuse the exact `get`-struct reader that WAS wire-proven for
`syslog.config.get`; only the specific field name is derived:

| control_id(s) | recipe | derived field |
|---|---|---|
| `esx.key-persistence` (8.0 + 9.0) | `esxcli:system.security.keypersistence.get:Enabled` | `Enabled` |
| `esx.logs-filter` (8.0) / `esx.log-filter` (9.0) | `esxcli:system.syslog.config.logfilter.get:LogFilteringEnabled` | `LogFilteringEnabled` |
| `esx.tls-profile` (8.0) / `esx.tls-ciphers` (9.0) | `esxcli:system.tls.server.get:Profile` | `Profile` |

### Advanced-setting key presence (build 39 — vCenter OptionManager)

Read via the same vCenter advanced-settings (`OptionManager.QueryOptions`)
surface the adapter already scores; the *key name* is documentation-
derived and unconfirmed on the live vCenter surface. If the key is absent
at runtime the control is **skipped** (excluded from the score), never a
false `pass` — so it is safe-by-construction, just unproven.

| control_id | parameter (advanced-setting key) | expected | note |
|---|---|---|---|
| `vc.vpxuser-length` (9.0) | `config.vpxd.hostPasswordLength` | `32` (integer) | recon flags this as likely present in the vCenter advanced-settings surface but it has not been seen on the wire. Tier-B blind build: confirm on the live 8.0/9.0 vCenter that `config.vpxd.hostPasswordLength` appears in `QueryOptions`. Absent → skipped (coverage gap), never a pass. |

### vim_property path/type unconfirmed (build 40 — vim25 PropertyCollector)

These two controls are **scored** (non-empty `read_recipe`, `vim_property`
kind) but the vim25 path or the runtime spec type was **derived from the
API reference / documentation, not observed on a live object**. Safe-by-
construction: a wrong path or an unrecognized spec type resolves to
UNREADABLE (counted in `unreadable_count`, excluded from every score) —
**never** a false `pass`. A live 8.0 (and 9.0) DVS/DVPG run promotes these
to proven coverage.

| control_id | recipe | derived assumption |
|---|---|---|
| `vds.network-restrict-port-mirroring` (8.0, 9.0) | `list_empty:config.vspanSession` | The mirror-session list lives at `config.vspanSession` (newer `VMwareDVSConfigInfo.getVspanSession()`, confirmed present in the bundled `vim25.jar`) rather than the older `config.mirrorPortConfigs`. If a live vSphere 8 DVS exposes the sessions under a different path, the read resolves to a failed fetch → UNREADABLE (coverage gap), never an "empty list → compliant" pass. |
| `dvpg.network-vgt` (8.0, 9.0 — distributed-switch rows only) | `vlan_id_not:config.defaultPortConfig.vlan` | Assumes VGT presents as `VmwareDistributedVirtualSwitchTrunkVlanSpec` (matched by `"Trunk"` in the runtime type name) — a plain `vlanId == 4095` is also treated as VGT. Needs live confirmation that real VGT DVPGs deserialize to a `Trunk…` spec rather than some other type. An unrecognized spec type → UNREADABLE, never a guess-pass. (The standard-switch `esxi-8.network-vgt` / `esx-9.network-vgt` rows stay `powercli_only` — standard vSwitch port groups are not reachable through the DVPG collector.) |

> **To verify (build 40):** on a live DVS with a port-mirror session, confirm
> the session list is at `config.vspanSession`. On a DVPG configured for VGT,
> confirm `config.defaultPortConfig.vlan` deserializes to a `Trunk…` spec (or
> a `vlanId == 4095` id spec). Once confirmed, delete these two rows.

### VAMI REST field names unconfirmed (build 41 — vCenter Appliance REST)

These 12 controls (6 per profile) are **scored** (non-empty `read_recipe`,
new `vami_api` kind) but the **entire transport is a BLIND build**: the
`/api/appliance/...` JSON response field names were derived from API
documentation, **not captured on the wire**. Schema confidence is MEDIUM.
The reader (`VamiApiClient`) opens its own vCenter Appliance REST session
(`POST /api/session`, distinct from the vim25 SOAP cookie) and extracts one
JSON field per endpoint.

Safe-by-construction (the cardinal trap, restated for REST): any auth
failure, non-200, 404, timeout, JSON parse error, **absent field**, or
**empty list** folds to `UNREADABLE` (counted in `unreadable_count`,
excluded from every score) — **never** a false `pass`. This matters most
for the "should be disabled" controls: a failed GET of `access/ssh` does
**not** become "ssh disabled → compliant". A wrong documentation-derived
field name therefore produces a coverage gap, never a false pass. The
imminent live 8.0 run is exactly what promotes these to proven coverage.

| control_id (8.0 / 9.0) | endpoint | field | compliant when | derived assumption |
|---|---|---|---|---|
| `vc.vami-access-ssh` / `vc.ssh` | `access/ssh` | `enabled` | `false` (SSH off) | response object with boolean `enabled` |
| `vc.vami-syslog` / `vc.log-forwarding` | `logging/forwarding` | `(list)` | `(non-empty)` (≥1 target) | response body is itself a JSON array of forwarding targets; empty array → UNREADABLE under `(non-empty)`, never a pass |
| `vc.vami-time` / `vc.time` | `ntp` | `(list)` | `(non-empty)` (≥1 server) | response body is itself a JSON array of NTP server strings |
| `vc.fips-enable` (8.0 + 9.0) | `system/security/global-fips` | `enabled` | `true` (FIPS on) | response object with boolean `enabled` |
| `vc.tls-profile` / `vc.tls-ciphers` | `tls/profiles/global` | `profile` | `NIST_2024` (string equality) | response object with string `profile`; the exact NIST profile token (`NIST_2024`) is the CSV baseline and may differ by patch level |
| `vc.vami-administration-password-expiration` / `vc.vami-password-max-age` | `local-accounts/policy` | `max_days` | `-1` (never expires; numeric equality) | response object with integer `max_days`; SCG hardened state is no expiry (`max_days=-1`) |

> **To verify (build 41):** on a live 8.0 (and 9.0) vCenter, wire-capture
> one GET of each of the six endpoints above (vSphere Client → Developer
> Center → API Explorer → "appliance", or `curl` with a
> `vmware-api-session-id`). Confirm: the boolean field on `access/ssh` and
> `global-fips` is named `enabled`; `logging/forwarding` and `ntp` return a
> top-level JSON array (not an object wrapping one); `tls/profiles/global`
> exposes `profile` and the live profile token; `local-accounts/policy`
> exposes `max_days`. Once confirmed, delete this section. Where the live
> body wraps the list/value in an object instead, change the recipe's
> `<json-field>` (dotted path supported) — no Java change needed.

> **To verify:** on a live 8.0 (and 9.0) host, wire-capture one
> `system ssh server config list`, one `system account list`, and one each
> of the get-struct commands above (e.g. `govc host.esxcli … -dump`, or the
> trace command in the esxcli spike §0.7). Confirm the row element and the
> `Key`/`Value`/`UserID`/`Shellaccess` field names, and the get-struct
> field names. Once confirmed, delete this section.
>
> Caveat compounding: the 8.0 SSH cluster has never been directly
> exercised. As of 2026-09-23 the devel instances are configured fixed
> `VMware_SCG_9.1` and every devel host runs ESXi 9.1.1, so no 8.0 run
> exists yet; a live 8.0 host (fixed `VMware_SCG_8.0`, or Auto against an
> 8.0 host) is the confirmation.

---

## Haven't fully explored yet (API-reachable, reader not built)

These are backlog. The state is reachable; the adapter needs a new reader.
Ranked roughly by value (most controls unlocked per unit of Java).

### New `read_recipe` styles (vim25 — same SOAP session)

| style | unlocks | controls |
|---|---|---|
| ~~`service_state` (HostServiceInfo list filter — running/policy)~~ **BUILT — build 38 (running field)** | — | The **running**-field service controls are now audited (moved out of this backlog; see below). |
| ~~`vm_hardware_device_absent` (config.hardware.device[] filter)~~ **BUILT — build 40** | 1 audited | `vm.pci-passthrough` (8.0, 9.0) now audited (type-absence of `VirtualPCIPassthrough`). `vm.persistent-disk` (9.0) **stays backlog** — see note. |
| ~~`list_empty` (list-has-zero-elements)~~ **BUILT — build 40** | — | `vds.network-restrict-port-mirroring` (8.0, 9.0) now **scored** but path-unconfirmed — moved to "Wired — pending live field-name verification" below. |
| ~~`vlan_id_not` (VLAN type-aware: VGT vs vlanId 4095)~~ **BUILT — build 40** | — | `dvpg.network-vgt` (distributed-switch rows, 8.0 + 9.0) now **scored** but type-unconfirmed — moved to "Wired — pending live field-name verification" below. |
| ~~presence / non-empty compare~~ **BUILT — build 39** | — | `esx.timekeeping-sources` (8.0) is now audited (`string_list_join` + `(non-empty)`). The 9.0 `esx.time` **NTP-source half** stays documented-partial (its row already carries the build-38 daemon-running recipe; one recipe per row), NOT separately scored. |

> **`service_state` (build 38) — now audited (running field).** The
> `service_state:<key>:running` reader (config.service.service list filter,
> reflection-tolerant: `HostService.isRunning()` / `getKey()`) wired these
> controls out of this backlog and into the scored set:
> `esx.deactivate-shell` (TSM), `esx.deactivate-ssh` (TSM-SSH),
> `esx.deactivate-cim` (sfcbd-watchdog), `esx.deactivate-slp` (slpd),
> `esx.deactivate-snmp` (snmpd), `esx.timekeeping-services` (ntpd) in 8.0;
> `esx.deactivate-shell` (TSM), `esx.ssh` (TSM-SSH), `esx.snmp` (snmpd),
> `esx.time` (ntpd, **daemon-running half only**) in 9.0. A missing service
> entry or an unreadable list folds to UNREADABLE (never a sentinel
> "stopped/compliant"). **Still backlog for these controls:** the
> **`policy`** dimension (start-with-host `on`/`off`) — the reader supports
> `service_state:<key>:policy` but no control wires it yet, because the CSV
> row model is one recipe per control; the running check is the primary
> intent. See the partial-coverage table for `esx.timekeeping-services`,
> `esx.time`, and `esx.snmp`. The `esx.time` (9.0) **NTP source-list half**
> stays in the presence/non-empty row above — not double-counted here.

> **`vm_hardware_device_absent` / `list_empty` / `vlan_id_not` (build 40)
> — now wired.** Three reflection-tolerant vim25 read-recipe styles over
> the existing SOAP session. All three return a `Boolean` (or fold to
> UNREADABLE); the evaluator's boolean compare path scores `expected=true`.
>
> - **`vm_hardware_device_absent`** wires `vm.pci-passthrough` (8.0 + 9.0)
>   into the **audited set** (HIGH confidence — `config.hardware.device` is
>   a well-known vim25 path; device type matched by runtime
>   `getClass().getSimpleName()`, never `instanceof`). Compliant = no
>   `VirtualPCIPassthrough` device present.
> - **`list_empty`** and **`vlan_id_not`** are wired but **path-/type-
>   unconfirmed** — see the next section.
>
> **Cardinal-trap separation (build 40).** For the two "empty == compliant"
> styles (`vm_hardware_device_absent`, `list_empty`) a **failed read of the
> list** is UNREADABLE, never "empty → compliant". The `readListConfirmed`
> helper walks to the list's **container node** and confirms it is non-null
> (positive proof the read reached the owning object) before reading the
> list off it; only a `List` obtained off a non-null container is a
> confirmed reading (empty or not). A null container / absent accessor /
> non-`List` return folds to UNREADABLE. For `vlan_id_not`, an unreadable
> spec node OR an unrecognized runtime spec type folds to UNREADABLE — VGT
> is never guess-passed.
>
> **`vm.persistent-disk` (9.0) — left in backlog (build-40 design call).**
> The control requires a **type + sub-property** filter (`VirtualDisk`
> whose `backing.diskMode == independentNonpersistent`), which the
> `vm_hardware_device_absent` grammar (plain device-type-name absence)
> cannot cleanly express. Per the build brief, wiring the simple
> type-absence control (`pci-passthrough`) now and leaving
> `persistent-disk` documented in backlog is preferred over a
> half-implemented sub-property filter. It remains `manual_audit` until a
> backing-aware device-filter style is built.

The ~40 remaining new-style controls are unlocked by building the styles
still listed above.

### Other vCenter APIs (not vim25 — separate readers)

| reader | unlocks | controls |
|---|---|---|
| ~~vCenter SSO STS SOAP (lockout / password policy)~~ **CLASSPATH GAP — build 42 feasibility recon** | 0 (not buildable) | The SSO admin SDK + WS-Trust/STS client are NOT on the adapter classpath; these 10 controls are now documented under "Cannot → vCenter SSO lockout / password policy" above, not backlog: `vc.administration-sso-lockout-policy-max-attempts` / `-unlock-time`, `vc.administration-failed-login-interval`, `vc.administration-sso-password-lifetime` / `-reuse` (8.0); `vc.account-lockout-duration` / `-max-attempts` / `-reset`, `vc.password-history` / `-max-age` (9.0) |
| ~~vCenter Appliance REST (VAMI, `/api/appliance/...`)~~ **BUILT — build 41** | 12 scored | `vc.vami-access-ssh` / `vc.ssh`, `vc.vami-syslog` / `vc.log-forwarding`, `vc.vami-time` / `vc.time`, `vc.fips-enable`, `vc.tls-profile` / `vc.tls-ciphers`, `vc.vami-administration-password-expiration` / `vc.vami-password-max-age` now **scored** via the `vami:` reader, but field-name-unconfirmed — moved to "Wired — pending live verification" above. |

The SSO STS cluster is NOT backlog — build-42 feasibility recon confirmed
the SSO admin SDK + WS-Trust client are absent from the classpath, so those
10 controls are reclassified to "Cannot" above. The VAMI cluster is wired
(build 41, blind — pending live verification).

### Uncertain — needs a live-instance check before committing a recipe

| control_id | what's needed |
|---|---|
| ~~`dvpg.network-vgt`~~ **WIRED — build 40** | `vlan_id_not:config.defaultPortConfig.vlan` is now scored; the `TrunkVlanSpec` assumption is unconfirmed — see "Wired — pending live field-name verification" above. |
| ~~`vds.network-restrict-port-mirroring`~~ **WIRED — build 40** | `list_empty:config.vspanSession` is now scored; the path-vs-`config.mirrorPortConfigs` assumption is unconfirmed — see "Wired — pending live field-name verification" above. |
| `esx.lockdown-exception-users` | `HostAccessManager.retrieveLockdownExceptions()` is a managed-object method call, not a property — needs an `access_manager` style. |
| `esx.hardware-tpm` (9.0) | TPM physical presence is not in vim25; only TPM *in use* is inferable from `config.encryptionState.mode` (partial). |
| `vc.drs` (9.0) | `drsConfig.enabled` is readable, but the control wants DRS config *quality*, not just on/off (partial). |

> **Total "Haven't yet": ~46 new-style + ~16 other-API + ~24 uncertain.**

---

*Generated for the build 35 coverage expansion; reconciled against the
canonical CSVs at build 38 (esxcli SSH/account/key-persistence/log-filter/
TLS controls moved out of "Cannot") and build 39 — the
presence/non-empty (`(non-empty)`) and not-equal (`not:<value>`)
comparison modes moved `esx.timekeeping-sources` (8.0, NTP source list),
`esx.logs-audit-persistent` (8.0) and `esx.log-audit-persistent` (9.0)
(`ScratchConfig.CurrentScratchLocation != /tmp/scratch`) out of the
backlog/uncertain set and into the audited set; `vc.vpxuser-length` (9.0)
was reclassified to `advanced_setting` and listed under "Wired — pending
live field-name verification". When a "Haven't yet" reader is built,
move its controls out of this doc and into the audited set via the
canonical CSV + normalizer. When a "Wired — pending verification" control's
field names are confirmed on a live host, delete it from that section. The
framework gets more honest, and more complete, one reader at a time.*
