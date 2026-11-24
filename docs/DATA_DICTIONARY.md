# Telemetry data dictionary and source audit

Audit performed on the complete canonical `data/device-telemetry-dataset.ndjson` before defining the input models. The file is 750 NDJSON lines, all 750 parse as JSON objects, with no malformed lines. SHA-256: `fb0ee31ffeeb731b919fc4d5124098c9c5b68cf3fba35eed5092a9f73655c4de`.

## Completeness and nested field distribution

Every listed source value had the indicated JSON type. There are **zero explicit JSON nulls** in the dataset. “Missing” counts are measured at the containing object level.

| Object or field paths | Occurrences | Missing | Explicit null | JSON type |
| --- | ---: | ---: | ---: | --- |
| Root object | 750 | 0 | 0 | object |
| `device_id`, `company_id`, `employee_id`, `collected_at`, `agent_version` | 750 each | 0 | 0 | string |
| `os` | 750 | 0 | 0 | object |
| `os.platform`, `os.product_name`, `os.product_version`, `os.build_version`, `os.architecture`, `os.kernel_name`, `os.kernel_release`, `os.hostname` | 750 each | 0 | 0 | string |
| `device_identity` | 750 | 0 | 0 | object |
| `device_identity.serial_number`, `.model_name`, `.model_identifier`, `.processor`, `.hardware_uuid`, `.total_memory` | 750 each | 0 | 0 | string |
| `memory` | 750 | 0 | 0 | object |
| `memory.ram_bytes`, `.total_memory_bytes`, `.used_memory_bytes`, `.free_memory_bytes`, `.page_size_bytes` | 750 each | 0 | 0 | integer |
| `disk_volumes` | 750 | 0 | 0 | array |
| `disk_volumes[]` | 750 | — | 0 | object |
| `disk_volumes[].volume_name`, `.file_system`, `.mount_point` | 750 each | 0 | 0 | string |
| `disk_volumes[].size_bytes`, `.available_bytes` | 750 each | 0 | 0 | integer |
| `disk_volumes[].encrypted` | 750 | 0 | 0 | boolean |
| `installed_software` | 750 | 0 | 0 | array |
| `installed_software[]` | 3,855 | — | 0 | object |
| `installed_software[].name`, `.version`, `.publisher` | 3,855 each | 0 | 0 | string |
| `compliance_results` | 750 | 0 | 0 | array |
| `compliance_results[]` | 2,250 | — | 0 | object |
| `compliance_results[].check_id`, `.status`, `.severity` | 2,250 each | 0 | 0 | string |
| `battery` | 650 | **100** | 0 | object |
| `battery.battery_present` | 650 | 0 | 0 | boolean |
| `battery.charging_status`, `.condition` | 650 each | 0 | 0 | string |
| `battery.percentage`, `.cycle_count`, `.full_charge_capacity` | 650 each | 0 | 0 | integer |
| `network` | 734 | **16** | 0 | array |
| `network[]` | 734 | — | 0 | object |
| `network[].address`, `.family`, `.interface_name`, `.mac` | 734 each | 0 | 0 | string |
| `network[].internal` | 734 | 0 | 0 | boolean |

Array lengths: each of 750 records has one disk volume and three compliance results. Installed software has five items in 645 records and six items in 105 records. Each present network array has one item.

## Dataset shape and observed values

- 3 companies, 25 tenant-scoped devices, and 14 distinct `(company_id, employee_id)` associations.
- Snapshots: `acme-001` 300; `globex-002` 240; `initech-003` 210. Each device has 30 snapshots.
- Input timestamps carry `+05:30`; after UTC conversion the first is `2026-05-14T08:40:00Z` and the last is `2026-06-12T11:00:00Z`.
- OS values: `darwin` / `macOS` / `Darwin` / `arm64` on 510 rows; `win32` / `Windows` / `Windows_NT` / `x64` on 240 rows.
- Volume mount points are `/` on 510 rows and `C:\` on 240. Filesystems are `apfs` (510) and `ntfs` (240).
- Disk sizes range from 274,877,906,944 to 1,099,511,627,776 bytes; available space ranges from 5,497,559,139 to 669,468,365,229 bytes. Source has no zero/negative sizes, negative available counts, or `available_bytes > size_bytes` cases.
- Memory byte values are strict integers: RAM and total memory range from 8,589,934,592 to 34,359,738,368; used memory from 2,966,762,559 to 19,205,654,559; free memory from 133,414,803 to 25,445,141,037; page size from 4,096 to 16,384.
- Battery conditions: `Normal` 595; `Service Recommended` 55. Charging statuses: `charged` 228, `charging` 198, `discharging` 224. Charge percentage is observed; it does not derive battery health.
- Compliance results total 2,250: status `fail` 706, `pass` 1,544; severity `high` 750, `medium` 1,500. High-severity failures (`status=fail` and `severity=high`) total **zero**.

## Ingestion and persistence

Pydantic v2 input fields use strict scalar types. Timestamps must include an offset and are converted to UTC; disk size must be positive and available bytes must be between zero and size. Unrecognized fields are allowed and the parsed source object is preserved in `raw_json`; absent optional fields remain absent there and are stored as SQL `NULL` in their optional JSON columns.

Database identifiers are normalized with Unicode NFKC and trimming: tenant/employee IDs use casefolding, device IDs use uppercase, and OS platform/product identifiers use casefolding. Original source values remain in `raw_json`. Each snapshot stores source line number, a SHA-256 of that line without its line ending, the full dataset SHA-256, and source path. Import reports also include `policy_version`, `graph_version`, `prompt_version`, and `model_version` (`not_applicable` for this non-LLM ingestion run).

Tenant identity and RLS are documented in `docs/THREAT_REVIEW.md`. Deterministic metric definitions, missing-data rules, as-of behavior, filters, and the frozen query oracles are in `docs/DATA_DICTIONARY.md` and `evals/golden/phase04_query_oracles.json`.
