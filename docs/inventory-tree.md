# Inventory Tree — VCF Content Factory Compliance

> Generated from `describe.xml` v0.0.0.87. Do not edit — regenerated on every build.

## Traversal Tree



> \* = identifying (unique) key

## Resource Kinds Reference

| Kind | Display Label | Identifying Keys | Parent(s) |
|------|--------------|-----------------|-----------|
| `ComplianceWorld` | Compliance World | `world_id` * | — |

## Cross-MP Relationships

These edges are created at collection time via the Suite API and never appear in `describe.xml` — they are declared explicitly in `adapter.yaml` (`cross_mp_edges`) so this generated docset doesn't silently omit them. *Italic* endpoints belong to a foreign management pack; `code` endpoints are owned by this adapter.

| Parent | Child | Description |
|--------|-------|-------------|
| `ComplianceWorld` | *VMwareAdapter Instance* (foreign, VMWARE) | Each adapter instance makes its own vCenter object a child of the Compliance World through the Suite API, every cycle (additive, so instances never remove each other's links). The Rollup\|Environment totals on the Compliance World are computed by the analytics engine over these children. The link is added each cycle and never removed. |
