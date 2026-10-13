# Tuning controls and thresholds

You tune the compliance pack from one XML file in VCF Operations. You
can turn a control off, score a control against your own value, or pin
the guide version. Nothing is copied to a collector. Every collector
reads the file from VCF Operations at the start of each collection.

The bundled guides, Auto (by version), and the manual-review list keep
working underneath. The file only adjusts them.

## What the file can and cannot do

You can:

- **Turn a control off (Skip).** It gets no metric, raises no alert, and
  no longer counts in the score.
- **Use your own expected value (Override).** For example, allow 5
  failed logon attempts instead of the guide's value.
- **Pin the guide version (Profile).** For every object of the account,
  or for one object kind, instead of Auto (by version).

You cannot:

- **Add a new control.** Alerts ship with the pack, one per bundled
  control. A control the pack does not already check cannot be added
  from the file.
- **Score a control the pack does not check automatically.** Controls
  listed for manual review, and controls the pack has no way to read,
  stay that way. An entry naming one is rejected.
- **Change an alert's name, severity or recommendation.** Those ship
  with the pack.

## Step 1: Copy the template

1. In VCF Operations, open **Administration > Configuration Files >
   Management Packs Configuration**.
2. Find `compliance_overrides_template`. The pack installs it.
3. Copy it and give the copy a name, for example
   `compliance_overrides_vc01`.

Do not edit the template itself. An upgrade of the pack can replace the
template. Your copy has a name the pack never uses, so no upgrade
touches it.

## Step 2: Point the account at your copy

1. Open **Administration > Integrations > Accounts** and edit the
   compliance account.
2. Set **Overrides file** to the name of your copy, without `.xml`. For
   example `compliance_overrides_vc01`.
3. Save.

Leave **Overrides file** empty to run with no overrides. An empty
setting means the file is never fetched.

## Step 3: Add entries

Open your copy. Every example in the template is inside a comment
(`<!--` and `-->`). Move the entries you want outside the comments and
change the values. Each entry names a control by its control id, for
example `esx.account-lockout-max-attempts`. Control ids are in
[REFERENCE.md](../REFERENCE.md) and in the bundled profiles. On an
object, each control id is the middle part of its metric name under
VCF-CF Compliance.

A file with all three entry types:

```xml
<ComplianceOverrides>
  <Skip control="esx.account-lockout-duration"/>
  <Override control="esx.account-lockout-max-attempts" expected="5"/>
  <Profile version="SCG 9.0"/>
  <Profile kind="VirtualMachine" version="SCG 8.0"/>
</ComplianceOverrides>
```

### Skip: turn a control off

```xml
<Skip control="esx.account-lockout-duration"/>
```

The control is not checked and not pushed. It leaves the score. What
happens to its existing metric is under
[What happens to a skipped control](#what-happens-to-a-skipped-control).

### Override: score against your value

```xml
<Override control="esx.account-lockout-max-attempts" expected="5"/>
```

This example allows 5 failed logon attempts before an ESX account
locks. A host set to 5 passes. A host set to anything else fails.

The value must suit the control:

- A number control takes a whole number, such as `5` or `900`.
- A true/false control takes `true` or `false`.
- A text control takes any text.

These forms also work:

| Value | Compliant when |
|---|---|
| `(non-empty)` | the setting has any value |
| `not:X` | the setting has a value other than X |
| `X or Undefined` | the setting is X or is not set (advanced settings only) |
| `Not Present` | the setting is not set (advanced settings only) |

The override applies under every guide version that has the control.
On the object, the control's Expected property reads
`5 (site override)`, and its Actual property reads, for example,
`3, expected 5 (site override)`. The alert keeps the name and
recommendation it shipped with, and the recommendation may still quote
the guide's value. Check the object's Expected property to see the value
it was scored against.

A setting the pack could not read is never a pass, with or without an
override.

### Profile: pin the guide version

```xml
<Profile version="SCG 9.0"/>
<Profile kind="VirtualMachine" version="SCG 8.0"/>
```

Without `kind`, the pin applies to every object of the account. With
`kind`, it applies to that object kind only, and wins over a pin
without `kind`. Objects of other kinds keep the account's own choice
(Auto (by version) or a fixed guide). A pin also replaces a fixed guide
for the kinds it names.

Versions: `SCG 6.7`, `SCG 7.0`, `SCG 8.0`, `SCG 9.0`, `SCG 9.1`.

Kinds: `HostSystem`, `VirtualMachine`, `vCenter`,
`ClusterComputeResource`, `DistributedVirtualSwitch`,
`DistributedVirtualPortgroup`.

A pinned object's `VCF-CF Compliance|profile_name` property reads the
pinned guide, for example `VMware_SCG_8.0`.

## Step 4: Confirm it loaded

Changes take effect on the next collection. You do not need to edit or
restart the account.

**On the vCenter object.** Open the vCenter in VCF Operations and look
under VCF-CF Compliance, Summary:

| Key | What it shows |
|---|---|
| `VCF-CF Compliance\|Summary\|overrides_file` | the file name the account is set to |
| `VCF-CF Compliance\|Summary\|overrides_status` | whether it loaded (below) |
| `VCF-CF Compliance\|Summary\|overrides_skipped` | how many Skip entries are in force |
| `VCF-CF Compliance\|Summary\|overrides_overridden` | how many Override entries are in force |

`overrides_status` reads one of:

| Status | Meaning |
|---|---|
| `none` | Overrides file is empty. No overrides. |
| `OK` | The file loaded and every entry applied. |
| `N rejected` | The file loaded. N entries were rejected; the rest applied. |
| `absent` | No file with that name exists. The account runs with no overrides. |
| `parse failed, last good from <time>` | The file is not valid XML. The copy read at that time stays in force. |
| `parse failed, no previous copy` | The file is not valid XML and was never read. No overrides. |
| `fetch failed, last good from <time>` | VCF Operations did not answer this cycle. The copy read at that time stays in force. |
| `fetch failed` | VCF Operations did not answer and the file was never read. No overrides. |

The time is the collector's local time.

The pack's Compliance World object shows the same keys under Summary.
Every account shares that object, so it shows the last account to
collect. Use the vCenter object to check a specific account.

**In the adapter log.** Each collection writes one line that lists what
applied:

```
Overrides file 'compliance_overrides_vc01': 3 entries applied: skip esx.account-lockout-duration; override esx.account-lockout-max-attempts expected 5; profile VMware_SCG_8.0 for VM
```

## When an entry is rejected

A wrong entry is rejected. The rest of the file still applies.
`overrides_status` reads `N rejected`, and each collection writes one
WARN line per rejected entry, with the reason:

```
Overrides file 'compliance_overrides_vc01': rejected <Override control="esx.account-lockout-max-attempts" expected="five"/>: 'five' is not a whole number (control value type integer); the guide's value is kept
```

Reasons you can see:

- an unknown control id
- a control the pack does not check automatically
- a value that does not suit the control (the guide's value is kept)
- an Override of a control that is also skipped (the Skip wins)
- an unknown version or kind
- an unknown entry type or attribute
- a second entry for the same control, or a second pin for the same
  kind (the first one is used)

## When the file is missing or broken

The alert **VCF Content Factory Compliance Alert: Compliance overrides
file not loaded** fires on the vCenter object when:

- the account names a file that does not exist (status `absent`), or
- the file is not valid XML (status `parse failed`).

A missing file means no overrides at all. The pack never keeps using an
old copy of a file that is gone. A broken file keeps the last copy the
pack read, if there is one. The adapter log names the problem. The alert
clears on the first collection that loads the file.

## One copy for several vCenters

One copy can serve several accounts. Set **Overrides file** to the same
name on each. If some vCenters need different values, make one copy per
group of vCenters and point each account at its group's copy.

## What happens to a skipped control

On the next collection:

- Its metric `VCF-CF Compliance|<control id>|Compliant` is set to -1
  (not evaluated) if it was 0 or 1.
- Its Actual property reads `(skipped by override file <your file>)`.
- An open alert for it stops matching. It clears after three
  collections (about 15 minutes at the default interval), the usual
  cancel time for a control alert.
- It no longer counts in the object's score.

A control that already read -1 is left as it is. The pack never creates
a metric the object did not have. The alert definition stays installed.
It belongs to the pack, not to your file. It has nothing to fire on.

Remove the Skip entry to turn the control back on. It is checked again
on the next collection.

## Alert-only changes: use the policy

If you only want an alert to stop, disable that alert definition in the
VCF Operations policy for those objects. The control is still checked
and still counts in the score. Use the policy when the control matters
but the alert is noise. Use Skip when the control does not apply to
your site and should not count against the score.

## Moving from a Custom profile CSV

The Custom profile choice, and its CSV path on the collector, still
work in this release but are deprecated. While an account uses them,
the adapter log shows a WARN each time the account is configured. To
move:

1. Compare your CSV with the bundled profile it was copied from.
2. For each row you deleted, add a Skip entry.
3. For each expected value you changed, add an Override entry.
4. If you used the CSV to stay on one guide version, add a Profile
   entry.
5. Set **Compliance Profile** back to `Auto (by version)` (or the fixed
   guide you want), and set **Overrides file** to your copy.

The overrides file adjusts the bundled guides. Unlike the Custom CSV,
the manual-review list keeps applying, so you do not need to remove
those controls yourself.
