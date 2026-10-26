# HMAC key rotation

Tombstones are derived from a keyed hash. Rotating that key naively would silently
disable protection for every existing tombstone. Redacto therefore uses a
**versioned key ring**, and it fails closed when a required version is missing.

## Configuration

```dotenv
# Current version used for NEW material.
REDACTO_HMAC_KEY_VERSION=2

# Every version that active tombstones may reference must be present.
REDACTO_HMAC_KEYS={"1":"<old-key>","2":"<new-key>"}
```

- `REDACTO_HMAC_KEYS` is a JSON object of integer version → key.
- If it is unset, `REDACTO_HMAC_KEY` is used as version 1 (single-key compatibility).
- Keys belong in a secret manager or local untracked env file, never in Git.
- `redacto_status` reports versions (never keys), active tombstones per version,
  missing versions, and `protection_degraded`.

Each tombstone stores the version that produced its fingerprint, shingles, anchors,
tokens and embedding-readiness material. Matching a record evaluates each active
tombstone with its own version's key. New tombstones use the current version.

## Rotation procedure

1. **Add** the new key without removing the old one:

   ```dotenv
   REDACTO_HMAC_KEYS={"1":"<old-key>","2":"<new-key>"}
   REDACTO_HMAC_KEY_VERSION=1   # still the old version
   ```

   Restart and run `redacto keyring`. `missing_key_versions` must be empty.

2. **Switch** the current version and restart:

   ```dotenv
   REDACTO_HMAC_KEY_VERSION=2
   ```

   New revocations now create v2 tombstones. v1 tombstones continue to match with
   the v1 key. Run `redacto keyring`; both versions may show active tombstones.

3. **Wait** until every v1 tombstone is retired. A tombstone is retired when you
   decide its retention period is over (there is no automatic expiry yet). The
   current key version can never be retired. Then:

   ```powershell
   redacto keyring --retire 1
   ```

   If any active tombstone still references version 1, the command refuses with
   `version_still_in_use`. If version 1 is the current version, it refuses with
   `current_version_in_use`. If it succeeds, `retirable_versions` includes 1.

4. **Remove** the old key from `REDACTO_HMAC_KEYS` and restart. Removing a version
   that no active tombstone references is safe.

## Fail-closed behaviour

- An active tombstone whose version is missing from the ring makes **all**
  ingestion return `blocked` with reason `key_unavailable_fail_closed`. The guard
  cannot know which records are affected, so it refuses everything rather than
  claiming protection it cannot provide.
- If the **current** version is missing, `redacto_status`, scan, plan, apply,
  ingest and verify refuse with `current_key_unavailable` or `keyring_unavailable`.
- If `REDACTO_HMAC_KEYS` is invalid JSON or the current version is absent,
  `protection_degraded` is true and new work is refused (`keyring_invalid`).
- Verification uses the key version recorded on the request/target record. If that
  version is gone, the affected store is reported `not_verifiable`, residuals are
  not claimed clear, and the receipt ends `PARTIAL`.

## What rotation does **not** do

- It does not re-derive old tombstones. They remain bound to their original version.
- Related derivative fingerprints are stored with the version that produced them, so
  a tombstone created after rotation can still block a derivative fingerprinted under
  an older version.
- It does not delete or expire tombstones. Retention is a policy decision and a
  future feature; until then, old keys must remain available.
- It does not rotate store encryption or adapter credentials.

## Audit checklist

```powershell
redacto status     # revocation.protection_degraded must be false
redacto keyring    # missing_key_versions must be empty
redacto keyring --retire <version>   # only when no active tombstone uses it
```

Record the rotation date, versions, and who performed it in your operational log.
Never record the key material itself.