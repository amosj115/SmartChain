# Connector Matrix

All external connectors below are sandbox-only. The synthetic responses are not evidence of a live connection or an authoritative business decision.

| System | Adapter operations | Environment | Source of truth | Live status / prerequisite |
| --- | --- | --- | --- | --- |
| Travel With Flair | Create travel request; read request status | SANDBOX | TWF for booking execution | Not connected; authorized interface and credentials required |
| Central Supplier Database | Validate supplier reference | SANDBOX | CSD for supplier master data | Not connected; permitted CSD interface and credentials required |
| National Treasury eTender | Simulate tender publication | SANDBOX | eTender for publication | Not connected; official publication contract and authorization required |
| Finance / BAS | Simulate budget check | SANDBOX | Authoritative departmental finance system | Not connected; identify finance system and obtain its authorized contract |
| SmartGov | Submit record metadata | SANDBOX | Authorized SmartGov service | Not connected; SmartGov API/interface specification required |
| SmartFleet | No adapter operation yet | INTERNAL | SmartChain SmartFleet | Native module listed; no integration contract implemented here |
| RQ & Procurement | No adapter operation yet | INTERNAL | SmartChain RQ | Native module listed; no event publisher implemented here |
| Tender Management | No adapter operation yet | INTERNAL | SmartChain Tender | Native module listed; no event publisher implemented here |
| Contract Management | No adapter operation yet | INTERNAL | SmartChain Contracts | Native module listed; no event publisher implemented here |
| Command Centre | No adapter operation yet | INTERNAL | SmartChain Command Centre | Native module listed; no integration contract implemented here |

## v1 sandbox request fields

| Connector operation | Required fields | Optional fields |
| --- | --- | --- |
| TWF `create_travel_request` | `case_id`, `request_id`, `destination`, `travel_date` | None |
| TWF `get_travel_request_status` | `provider_reference` | `case_id` |
| CSD `validate_supplier` | `csd_supplier_number` | `case_id` |
| eTender `publish_tender` | `case_id`, `tender_number`, `title`, `closing_date` | None |
| Finance `check_budget` | `case_id`, `cost_centre`, `amount` | None |
| SmartGov `submit_record_metadata` | `case_id`, `record_reference`, SHA-256 `document_hash` | None |

The sandbox deliberately returns statuses such as `SANDBOX_NOT_VERIFIED`, `SANDBOX_NOT_CHECKED`, and `SANDBOX_PUBLICATION_SIMULATED`. These must not be interpreted as supplier, budget, travel, records, or publication confirmations.