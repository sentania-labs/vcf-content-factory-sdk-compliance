# Test fixtures (build 96, issue #27)

Response bodies served by `FakeVCenter` (the SOAP Body's inner element) and
by the fake Suite API in `Build96FixtureTest`, so the parsers are driven
through the real HTTP clients. Provenance:

| File | Source |
|---|---|
| `esxcli/syslog-config-get.xml` | Recorded on devel (ESXi 9, `system.syslog.config.get` through `ReflectManagedMethodExecuter.ExecuteSoap`), from the factory's `knowledge/context/investigations/esxcli-soap-reflect-executer-spike.md` section 0.2, abridged there to the proof fields; the remote host is replaced by a placeholder. |
| `esxcli/ssh-server-config-list.xml` | The `list` shape (`ArrayOfDataObject` of `DataObject` rows) from the same spike, section 0.3. Constructed to that shape; values are illustrative. |
| `esxcli/command-fault.xml` | The esxcli-level `<fault>` shape (`faultMsg` / `faultDetail`) from the spike, section 0.2. Constructed. |
| `soap/host-query-options.xml` | `QueryOptionsResponse` per the vim25 WSDL (`OptionValue` key / typed value). Constructed; key names are SCG advanced settings. |
| `soap/vm-extraconfig-missingset.xml` | `RetrievePropertiesResponse` whose property comes back in `missingSet` with a `NoPermission` fault (vim25 `ObjectContent`). Constructed. |
| `soap/host-listing.xml` | `RetrievePropertiesResponse` for a ContainerView listing with `name` (one row without it). Constructed. |
| `suiteapi/resources-hostsystem.json` | `GET /api/resources?adapterKind=VMWARE&resourceKind=HostSystem` per the Suite API spec (`resourceList` / `resourceKey.resourceIdentifiers` / `pageInfo`). Constructed; identifiers are the VMWARE adapter's (VMEntityName, VMEntityObjectID, VMEntityVCID). |

Constructed fixtures follow the published shapes; they are not captures.
