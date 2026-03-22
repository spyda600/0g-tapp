# Safe Enclave Update Procedure

> **WARNING**: Updating the enclave terminates the running instance and wipes all
> in-memory keys. A botched update means **permanent loss of sequencer keys
> holding real funds**. Follow every step below.

## Prerequisites

- `tapp-cli` configured and able to reach the running enclave gRPC endpoint
- AWS CLI access to the KMS key policy (for PCR0 rotation)
- A secure place to store the emergency passphrase (password manager, hardware vault)

## Step-by-Step Procedure

### 1. Run Pre-Update Check

```bash
tapp-cli pre-update-check
```

Review the output. It reports:
- `total_keys` -- number of app keys currently in memory
- `backed_up_count` / `verified_count` -- KMS backup status per key
- `is_safe_to_update` -- **true** only when every key is backed up AND verified

If `is_safe_to_update` is **false**, proceed to step 2 (emergency backup).
If it is **true** AND KMS persistence is configured, you may skip step 2 -- but
doing the emergency backup anyway is strongly recommended.

### 2. Export Emergency Backup

```bash
tapp-cli export-emergency-backup \
  --passphrase "<STRONG_PASSPHRASE_MIN_16_CHARS>" \
  --output-path /opt/tapp/emergency-backup.json
```

This creates a JSON file containing every key encrypted with AES-256-GCM,
keyed via PBKDF2-HMAC-SHA256 (600 000 iterations) from your passphrase.

**Immediately**:
- Copy the backup file OFF the instance to a secure location
- Record the SHA-256 hash printed in the response
- Store the passphrase in a separate secure vault (not alongside the backup file)

### 3. Record Current State

Note down:
- Current PCR0 value (from the running EIF image)
- List of app_ids and their Ethereum addresses (from pre-update check output)
- The emergency backup hash

### 4. Build the New EIF Image

```bash
nitro-cli build-enclave --docker-uri <new_image> --output-file tapp.eif
```

Note the **new PCR0** hash from the build output.

### 5. Update KMS Key Policy (CRITICAL)

Before terminating the old enclave, update the KMS key policy to allow
**both** the old AND new PCR0 values:

```json
{
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": [
        "<OLD_PCR0_HEX>",
        "<NEW_PCR0_HEX>"
      ]
    }
  }
}
```

Verify the policy update took effect:
```bash
aws kms get-key-policy --key-id <KEY_ARN> --policy-name default
```

### 6. Terminate Old Enclave

```bash
nitro-cli terminate-enclave --enclave-id <ENCLAVE_ID>
```

All in-memory keys are now gone. The only copies are in KMS backups and
your emergency backup file.

### 7. Start New Enclave

```bash
nitro-cli run-enclave \
  --eif-path tapp.eif \
  --cpu-count 2 \
  --memory 4096
```

### 8. Verify Key Recovery

After the new enclave boots and the TAPP service starts:

```bash
tapp-cli pre-update-check
```

Verify that:
- All expected app_ids are present
- Keys match the Ethereum addresses recorded in step 3

If any keys are missing, proceed to **Emergency Recovery** below.

### 9. Clean Up KMS Policy (Optional)

Once you have confirmed all keys are recovered, remove the old PCR0 from the
KMS key policy for hygiene:

```json
{
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<NEW_PCR0_HEX>"
    }
  }
}
```

---

## Emergency Recovery

If keys fail to recover from KMS after the update:

### Option A: Re-check KMS Policy

The most common failure is a PCR0 mismatch. Verify:
1. The new enclave's actual PCR0 matches what you put in the policy
2. The KMS key policy update propagated (can take a few seconds)

Restart the enclave after fixing the policy.

### Option B: Recover from Emergency Backup

If KMS recovery is impossible (key deleted, policy locked out, etc.):

1. Copy the emergency backup JSON file into the enclave's accessible storage
2. Use the recovery tool (or implement restoration via the TAPP service):

```bash
tapp-cli recover-from-backup \
  --backup-path /opt/tapp/emergency-backup.json \
  --passphrase "<YOUR_PASSPHRASE>"
```

3. Verify each key's Ethereum address matches expectations
4. Re-establish KMS backups for the recovered keys

### Option C: Contact Incident Response

If both KMS and emergency backup recovery fail:
1. **Do NOT shut down the enclave** -- it may still have keys in memory
2. Escalate to the security team immediately
3. Document the failure mode for post-incident review

---

## Checklist Summary

- [ ] `PreUpdateCheck` returns `is_safe_to_update: true` (or emergency backup done)
- [ ] Emergency backup exported and stored securely off-instance
- [ ] Emergency passphrase stored in separate secure vault
- [ ] Backup file SHA-256 hash recorded
- [ ] New EIF built and new PCR0 noted
- [ ] KMS policy updated to allow BOTH old and new PCR0
- [ ] KMS policy update verified
- [ ] Old enclave terminated
- [ ] New enclave started
- [ ] All keys recovered and verified
- [ ] Old PCR0 removed from KMS policy (optional)
