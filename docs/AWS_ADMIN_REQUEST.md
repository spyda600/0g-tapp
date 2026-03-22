# AWS Admin Request: TAPP Nitro Enclave — IAM + KMS Setup

**Requested by:** PerpDex team
**Account:** 809778145789
**Region:** us-east-1
**Instance:** i-0fc4e8edc2567426f (c6i.xlarge, tapp-enclave)
**Purpose:** Enable encrypted key persistence for a Nitro Enclave running the PerpDex sequencer

---

## What we need (3 items)

### 1. Create a KMS Key for Enclave Key Persistence

This key will encrypt/decrypt the sequencer wallet private keys. Only the enclave (verified by hardware attestation) can decrypt.

```bash
# Create the key
aws kms create-key \
    --description "TAPP Enclave Key Persistence - PerpDex Sequencer" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT \
    --region us-east-1

# Note the KeyId from the output (looks like: arn:aws:kms:us-east-1:809778145789:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

# Create an alias for easy reference
aws kms create-alias \
    --alias-name alias/tapp-enclave-keys \
    --target-key-id <KeyId-from-above> \
    --region us-east-1

# IMPORTANT: Enable deletion protection
aws kms enable-key-rotation --key-id <KeyId> --region us-east-1
```

**Key Policy** — replace the default policy with this one. It allows the enclave to encrypt/decrypt ONLY if the attestation document matches our exact code hash (PCR0):

```json
{
    "Version": "2012-10-17",
    "Id": "tapp-enclave-key-policy",
    "Statement": [
        {
            "Sid": "AllowAccountAdmin",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::809778145789:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "AllowEnclaveEncrypt",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::809778145789:role/TappEnclaveRole"
            },
            "Action": [
                "kms:Encrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "cd06005563b14ba2b671cdd9abea08434538097804b4f4dec03b8ffaa8f9175d069988550c3a59f9f48e8da0ab9545c3"
                }
            }
        },
        {
            "Sid": "AllowEnclaveDecrypt",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::809778145789:role/TappEnclaveRole"
            },
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "cd06005563b14ba2b671cdd9abea08434538097804b4f4dec03b8ffaa8f9175d069988550c3a59f9f48e8da0ab9545c3"
                }
            }
        }
    ]
}
```

**Why PCR0?** This is the SHA-384 hash of the entire enclave image. If anyone modifies the code, PCR0 changes and KMS refuses to decrypt. This is the hardware-enforced guarantee that only our exact code can access the keys.

**IMPORTANT for updates:** When we deploy a new version of the enclave, the PCR0 will change. Before deploying, we need to temporarily add the NEW PCR0 to the policy (so both old and new versions can decrypt during the transition). After verifying the update succeeded, remove the old PCR0.

---

### 2. Create IAM Role + Instance Profile

The EC2 instance needs an IAM role to call KMS and S3 from within the Nitro Enclave.

```bash
# Create the role
aws iam create-role \
    --role-name TappEnclaveRole \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'

# Attach KMS permissions
aws iam put-role-policy \
    --role-name TappEnclaveRole \
    --policy-name TappEnclaveKMS \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey"
            ],
            "Resource": "arn:aws:kms:us-east-1:809778145789:key/*",
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "ec2.us-east-1.amazonaws.com"
                }
            }
        }]
    }'

# Attach S3 permissions (for encrypted key backup storage)
aws iam put-role-policy \
    --role-name TappEnclaveRole \
    --policy-name TappEnclaveS3 \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::tapp-enclave-backups-809778145789",
                "arn:aws:s3:::tapp-enclave-backups-809778145789/*"
            ]
        }]
    }'

# Optional: CloudWatch Logs
aws iam attach-role-policy \
    --role-name TappEnclaveRole \
    --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess

# Create instance profile
aws iam create-instance-profile \
    --instance-profile-name TappEnclaveProfile

aws iam add-role-to-instance-profile \
    --instance-profile-name TappEnclaveProfile \
    --role-name TappEnclaveRole

# Wait a few seconds for propagation, then attach to our instance
sleep 10
aws ec2 associate-iam-instance-profile \
    --instance-id i-0fc4e8edc2567426f \
    --iam-instance-profile Name=TappEnclaveProfile \
    --region us-east-1
```

---

### 3. Create the S3 Backup Bucket

```bash
aws s3 mb s3://tapp-enclave-backups-809778145789 --region us-east-1

# Enable versioning (so we never accidentally overwrite a backup)
aws s3api put-bucket-versioning \
    --bucket tapp-enclave-backups-809778145789 \
    --versioning-configuration Status=Enabled

# Enable server-side encryption by default
aws s3api put-bucket-encryption \
    --bucket tapp-enclave-backups-809778145789 \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "alias/tapp-enclave-keys"
            }
        }]
    }'

# Block all public access
aws s3api put-public-access-block \
    --bucket tapp-enclave-backups-809778145789 \
    --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

---

### 4. Enforce IMDSv2 (quick security fix)

```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-0fc4e8edc2567426f \
    --http-tokens required \
    --http-endpoint enabled \
    --region us-east-1
```

This prevents SSRF-based credential theft from the instance metadata service.

---

## What this enables

Once set up, the Nitro Enclave can:
1. Generate a sequencer wallet (Ethereum private key)
2. Encrypt it using KMS — **only this exact enclave code can decrypt it**
3. Store the encrypted blob in S3
4. On restart, retrieve the blob from S3 and decrypt via KMS (after hardware attestation)
5. The sequencer wallet is recovered — no funds lost

The private key **never** exists in plaintext outside the enclave. KMS ensures that even AWS employees cannot decrypt it without the enclave's attestation.

---

## After setup, please share back:

- [ ] KMS Key ARN (or confirm alias `alias/tapp-enclave-keys` was created)
- [ ] Instance profile attached (confirm `TappEnclaveProfile` is on `i-0fc4e8edc2567426f`)
- [ ] S3 bucket created (confirm `tapp-enclave-backups-809778145789`)
- [ ] IMDSv2 enforced

---

## Questions?

Contact the PerpDex team. The enclave is already running in production mode at `3.81.185.0`. No restart needed for any of these changes — the instance profile attaches live.
