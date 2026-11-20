# Untested Handler Error Branches

Total: 166 untested error branches across 70 handlers

## `crates/dpp-identity/src/handlers/rotate_key.rs`
- **rotate_key_handler()** — routes: `/internal/keys/rotate`
  Untested codes: [422]

## `crates/dpp-identity/src/handlers/sign.rs`
- **sign_handler()** — routes: `/internal/sign`
  Untested codes: [400,422]

## `crates/dpp-identity/src/handlers/verify.rs`
- **verify_handler()** — routes: `/internal/verify`
  Untested codes: [422]

## `crates/dpp-integrator/src/handlers/import.rs`
- **import_file()** — routes: `/api/v1/import/{productGroup}`
  Untested codes: [400,404,422]

## `crates/dpp-integrator/src/handlers/job_status.rs`
- **get_job_status()** — routes: `/api/v1/imports/{job_id}`
  Untested codes: [400,404]

## `crates/dpp-integrator/src/handlers/product_groups.rs`
- **get_product_group()** — routes: `/api/v1/product-groups/{productGroup}`
  Untested codes: [404]

## `crates/dpp-integrator/src/handlers/templates.rs`
- **get_template()** — routes: `/api/v1/templates/{productGroup}`
  Untested codes: [404,501]

## `crates/dpp-resolver/src/handlers/resolve_aas.rs`
- **resolve_aas_handler()** — routes: `no route found`
  Untested codes: [404,406,502,503]

## `crates/dpp-resolver/src/handlers/resolve_by_gtin.rs`
- **unserved_path_handler()** — routes: `no route found`
  Untested codes: [400,404]

## `crates/dpp-resolver/src/handlers/resolve_json.rs`
- **resolve_json_handler()** — routes: `no route found`
  Untested codes: [404,503]

## `crates/dpp-resolver/src/handlers/resolve_qr.rs`
- **resolve_qr_handler()** — routes: `/dpp/{dppId}/qr`
  Untested codes: [404,422]

## `crates/dpp-vault/src/handlers/amend.rs`
- **amend_handler()** — routes: `/dpp/{dppId}/amend`
  Untested codes: [400,404,409,422]

## `crates/dpp-vault/src/handlers/api_keys.rs`
- **api_keys_create_handler()** — routes: `/api-keys`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/api_keys.rs`
- **api_keys_delete_handler()** — routes: `/api-keys/{id}`
  Untested codes: [400,403,404]

## `crates/dpp-vault/src/handlers/api_keys.rs`
- **api_keys_list_handler()** — routes: `/api-keys`
  Untested codes: [403]

## `crates/dpp-vault/src/handlers/audience_read.rs`
- **audience_read_handler()** — routes: `no route found`
  Untested codes: [400,404,410]

## `crates/dpp-vault/src/handlers/create.rs`
- **carrier_serial_conflict()** — routes: `no route found`
  Untested codes: [409]

## `crates/dpp-vault/src/handlers/create.rs`
- **create_handler()** — routes: `/dpp`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/credentials.rs`
- **issue_credential_handler()** — routes: `/credentials`
  Untested codes: [422,501]

## `crates/dpp-vault/src/handlers/eol.rs`
- **eol_handler()** — routes: `/dpp/{dppId}/eol`
  Untested codes: [400,404,409,422]

## `crates/dpp-vault/src/handlers/evidence.rs`
- **generate_evidence_handler()** — routes: `/dpp/{dppId}/evidence`
  Untested codes: [400,403,404,409]

## `crates/dpp-vault/src/handlers/evidence.rs`
- **get_evidence_handler()** — routes: `/evidence/{id}`
  Untested codes: [404,409]

## `crates/dpp-vault/src/handlers/evidence.rs`
- **list_evidence_handler()** — routes: `/dpp/{dppId}/evidence`
  Untested codes: [400,404]

## `crates/dpp-vault/src/handlers/evidence.rs`
- **verify_document_handler()** — routes: `/evidence/verify`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/evidence.rs`
- **verify_evidence_handler()** — routes: `/evidence/{id}/verify`
  Untested codes: [404,409]

## `crates/dpp-vault/src/handlers/find_by_identity.rs`
- **find_by_identity_handler()** — routes: `/dpp/by-identity`
  Untested codes: [404]

## `crates/dpp-vault/src/handlers/history.rs`
- **history_handler()** — routes: `/dpp/{dppId}/history`
  Untested codes: [400,404]

## `crates/dpp-vault/src/handlers/lint.rs`
- **lint_handler()** — routes: `/dpp/{dppId}/lint`
  Untested codes: [400,404]

## `crates/dpp-vault/src/handlers/operator.rs`
- **operator_patch_handler()** — routes: `/operator`
  Untested codes: [400]

## `crates/dpp-vault/src/handlers/personal_data.rs`
- **personal_data_erase_handler()** — routes: `/personal-data/{record}`
  Untested codes: [404]

## `crates/dpp-vault/src/handlers/plugins.rs`
- **install_plugin_handler()** — routes: `/plugins`
  Untested codes: [501]

## `crates/dpp-vault/src/handlers/public_read_by_gtin.rs`
- **public_read_by_gtin_handler()** — routes: `/public/dpp/by-gtin/{gtin}`
  Untested codes: [404,410,422]

## `crates/dpp-vault/src/handlers/public_read.rs`
- **public_read_handler()** — routes: `/public/dpp/{dppId}`
  Untested codes: [400,404,410]

## `crates/dpp-vault/src/handlers/publish.rs`
- **publish_handler()** — routes: `/dpp/{dppId}/publish`
  Untested codes: [403,404,409,422]

## `crates/dpp-vault/src/handlers/read.rs`
- **read_handler()** — routes: `/dpp/{dppId}`
  Untested codes: [404]

## `crates/dpp-vault/src/handlers/registry_abandon.rs`
- **abandon_registration_handler()** — routes: `/dpp/{dppId}/registry/abandon`
  Untested codes: [400,422]

## `crates/dpp-vault/src/handlers/registry_handle.rs`
- **record_registry_handle_handler()** — routes: `/dpp/{dppId}/registry/handle`
  Untested codes: [400,422]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **facilities_audit_handler()** — routes: `/facilities/{id}/audit`
  Untested codes: [400,403]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **facilities_create_handler()** — routes: `/facilities`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **facilities_delete_handler()** — routes: `/facilities/{id}`
  Untested codes: [400,403,404,422]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **facilities_list_handler()** — routes: `/facilities`
  Untested codes: [403]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **facilities_set_default_handler()** — routes: `/facilities/{id}/default`
  Untested codes: [400,403,404]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **operator_ids_audit_handler()** — routes: `/operator-identifiers/{id}/audit`
  Untested codes: [400,403]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **operator_ids_create_handler()** — routes: `/operator-identifiers`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **operator_ids_delete_handler()** — routes: `/operator-identifiers/{id}`
  Untested codes: [400,403,404,422]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **operator_ids_list_handler()** — routes: `/operator-identifiers`
  Untested codes: [403]

## `crates/dpp-vault/src/handlers/registry_identity.rs`
- **operator_ids_set_primary_handler()** — routes: `/operator-identifiers/{id}/primary`
  Untested codes: [400,403,404]

## `crates/dpp-vault/src/handlers/registry_status.rs`
- **passport_registry_handler()** — routes: `/dpp/{dppId}/registry`
  Untested codes: [400,409]

## `crates/dpp-vault/src/handlers/retire.rs`
- **retire_handler()** — routes: `/dpp/{dppId}/retire`
  Untested codes: [400,403,404,409,422]

## `crates/dpp-vault/src/handlers/ruleset.rs`
- **reload_ruleset_handler()** — routes: `/ruleset/reload`
  Untested codes: [403,501]

## `crates/dpp-vault/src/handlers/seal.rs`
- **seal_handler()** — routes: `/dpp/{dppId}/seal`
  Untested codes: [400,404,409]

## `crates/dpp-vault/src/handlers/seal.rs`
- **seal_repair_handler()** — routes: `/dpp/{dppId}/seal/repair`
  Untested codes: [400,403,404,422]

## `crates/dpp-vault/src/handlers/stats.rs`
- **passport_stats_handler()** — routes: `/dpp/{dppId}/stats`
  Untested codes: [400]

## `crates/dpp-vault/src/handlers/supersede.rs`
- **supersede_handler()** — routes: `/dpp/{dppId}/supersede`
  Untested codes: [400,404,409,422]

## `crates/dpp-vault/src/handlers/suspend.rs`
- **suspend_handler()** — routes: `/dpp/{dppId}/suspend`
  Untested codes: [400,404,409]

## `crates/dpp-vault/src/handlers/transfer.rs`
- **transfer_accept_handler()** — routes: `/dpp/{dppId}/transfer/accept`
  Untested codes: [400,403,404,409,422]

## `crates/dpp-vault/src/handlers/transfer.rs`
- **transfer_cancel_handler()** — routes: `/dpp/{dppId}/transfer/cancel`
  Untested codes: [400,403,404,409,422]

## `crates/dpp-vault/src/handlers/transfer.rs`
- **transfer_initiate_handler()** — routes: `/dpp/{dppId}/transfer/initiate`
  Untested codes: [400,404,409,422]

## `crates/dpp-vault/src/handlers/transfer.rs`
- **transfer_reject_handler()** — routes: `/dpp/{dppId}/transfer/reject`
  Untested codes: [400,403,404,409,422]

## `crates/dpp-vault/src/handlers/unsold_goods.rs`
- **discard_record_attach_handler()** — routes: `/discard-records/{id}/evidence`
  Untested codes: [404,409,422]

## `crates/dpp-vault/src/handlers/unsold_goods.rs`
- **discard_record_create_handler()** — routes: `/discard-records`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/unsold_goods.rs`
- **discard_record_missing_handler()** — routes: `/discard-records/{id}/missing-evidence`
  Untested codes: [404]

## `crates/dpp-vault/src/handlers/update.rs`
- **update_handler()** — routes: `/dpp/{dppId}`
  Untested codes: [404,409,422]

## `crates/dpp-vault/src/handlers/validate.rs`
- **validate_handler()** — routes: `/dpp/validate`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/verify_tree.rs`
- **verify_tree_handler()** — routes: `/dpp/{dppId}/verify-tree`
  Untested codes: [400,404]

## `crates/dpp-vault/src/handlers/versions.rs`
- **versions_handler()** — routes: `/dpp/{dppId}/versions`
  Untested codes: [400,404,422]

## `crates/dpp-vault/src/handlers/webhooks.rs`
- **webhooks_create_handler()** — routes: `/webhooks`
  Untested codes: [422]

## `crates/dpp-vault/src/handlers/webhooks.rs`
- **webhooks_delete_handler()** — routes: `/webhooks/{id}`
  Untested codes: [400,403,404]

## `crates/dpp-vault/src/handlers/webhooks.rs`
- **webhooks_list_handler()** — routes: `/webhooks`
  Untested codes: [403]

## `crates/dpp-vault/src/handlers/webhooks.rs`
- **webhooks_test_handler()** — routes: `/webhooks/{id}/test`
  Untested codes: [400,403,404]

## Summary by error code

- `404`: 44 handler(s)
- `400`: 37 handler(s)
- `422`: 33 handler(s)
- `403`: 21 handler(s)
- `409`: 20 handler(s)
- `501`: 4 handler(s)
- `410`: 3 handler(s)
- `503`: 2 handler(s)
- `502`: 1 handler(s)
- `406`: 1 handler(s)

## Summary by crate

- `dpp-vault`: 144 handler(s)
- `dpp-resolver`: 10 handler(s)
- `dpp-integrator`: 8 handler(s)
- `dpp-identity`: 4 handler(s)
