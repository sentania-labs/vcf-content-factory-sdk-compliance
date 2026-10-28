# Test-only stubs (build 96, issue #27)

`ci/run_java_tests.sh` compiles every file under `src/` with
`-sourcepath src:tests:tests/stubs`, so the classes that depend on the VCF
Operations SDK or the factory adapter framework (`ComplianceAdapter`,
`ComplianceStitcher`, `VCenterApiClient`, `VamiApiClient`) compile and run
in CI without either jar. CI has neither: the SDK jar is Broadcom's and is
never redistributed, and the framework jar is built by the factory.

Nothing here ships. `build-sdk` compiles `src/` only, against the real SDK
and framework jars, so a stub that drifts from the real API still fails
the real build (validate-sdk / build-sdk / the tag build), never the pak.

| Path | What it is |
|---|---|
| `com/integrien/alive/common/**` | SDK stubs. Signatures only (the members the adapter calls), no vendor code, plus test hooks (`AdapterBase.testConfDir`, `testMonitoringIntervalSec`, `ResourceConfig.testFields`). |
| `com/vcfcf/adapter/VcfCfAdapter.java`, `spi/*`, `http/*`, `stitch/SuiteApiStitcher.java`, `stitch/SuiteApiBatchResult.java` | Framework stubs, same rule, plus test hooks (`testLog`, `testAbort`, `SuiteApiStitcher.testFactory`). |
| `com/vcfcf/adapter/json/SimpleJson.java` | A verbatim copy of the framework class (factory `src/vcfcf_managementpacks/adapter_framework/src/com/vcfcf/adapter/json/SimpleJson.java` at factory commit `6045435`, in `sdk-buildkit-v1.0.11`), because the stitcher and the REST clients parse with it and a stub would test a different parser. `tests/test_test_stubs.py` fails when its sha256 differs from the pinned sha256 of the factory copy (checked everywhere, CI included), and when it differs from the factory copy itself (checked when the factory tree is beside this repo). |

Every stub file starts with the `TEST-ONLY STUB` header; the same test
checks that, and that no file under `src/` imports a test hook.
