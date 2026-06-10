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
- One or more **compliance benchmark profiles**. The pack bundles SCG ESXi
  8.x / 9.x and the CIS vSphere Foundations Benchmark; a custom profile is
  supplied as an SCG-format CSV staged on the collector appliance.

## Permissions Required

The vCenter account needs read access sufficient to enumerate the
inventory and read host/vCenter configuration:

- Browse the inventory (hosts, clusters, datastores, distributed
  switches/portgroups, VMs).
- Read host configuration: advanced settings (`OptionManager`), services,
  firewall, and account/security settings (esxcli over the vCenter
  session).
- Read the vCenter appliance configuration via the VAMI REST endpoints
  (for SSH / password-policy controls).

A standard built-in **Read-only** role at the vCenter root, propagated to
children, covers the inventory and host reads. No write, no
administrative, and no remediation privileges are required.

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
| Compliance Profile | `benchmark_profile` | Yes | — | Select a bundled SCG/CIS profile, or `Custom`. |
| Custom Profile CSV Path (required if profile is Custom) | `custom_profile_path` | No | — | Filesystem path on the collector to an SCG-format CSV. Required only when the profile is `Custom`. |
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
   World and begins pushing per-host results onto the existing VMWARE
   HostSystem and vCenter resources.

## Troubleshooting

- **vCenter SOAP fails with a TLS validation error** — the vCenter
  certificate is not trusted. Import it into the platform trust store, or
  set `allowInsecure=true`. See the TLS section.
- **A host shows no compliance score / "no data"** — the host was
  unreadable this cycle (e.g. disconnected or not responding). This is the
  honest no-data state, not a failure to push; the adapter never
  publishes a sentinel score for an unreadable host. Check host
  connection state in vCenter.
- **Fleet `hosts_scored_stale` is non-zero** — some hosts in the fleet
  average were scored from a last-known cached value rather than a live
  read this cycle. Expected transiently after a collector restart (the
  cache re-warms) or while hosts are intermittently unreachable.
