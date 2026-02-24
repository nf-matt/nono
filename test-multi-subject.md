# Manual Testing: Multi-Subject File Attestation

## Prerequisites

```bash
cargo build -p nono-cli
alias nono="./target/debug/nono"
```

## 1. Generate a signing key

```bash
nono trust keygen --name test-key
```

Verify key was created:

```bash
nono trust list
```

## 2. Single file signing (unchanged behavior)

```bash
mkdir -p /tmp/nono-test && cd /tmp/nono-test
echo "# Skills" > SKILLS.md

nono trust sign SKILLS.md --key test-key
ls -la SKILLS.md.bundle
```

Expected: `SKILLS.md.bundle` sidecar created.

## 3. Multi-file keyed signing

```bash
cd /tmp/nono-test
echo "# Skills" > SKILLS.md
echo "print('hello')" > helper.py
echo '{"setting": true}' > config.json

nono trust sign SKILLS.md helper.py config.json --key test-key
ls -la .nono-trust.bundle
```

Expected:
- `.nono-trust.bundle` created in CWD (not per-file sidecars)
- Output shows 3 files signed

## 4. Verify multi-subject bundle

```bash
nono trust verify .nono-trust.bundle
```

Expected: verification passes, shows all 3 subjects.

## 5. Tamper detection

```bash
# Modify one of the signed files
echo "TAMPERED" > helper.py

# Re-verify
nono trust verify .nono-trust.bundle
```

Expected: verification fails, reports digest mismatch for `helper.py`.

## 6. Pre-exec scan with multi-subject bundle

Create a trust policy:

```bash
cd /tmp/nono-test

# Restore original files
echo "# Skills" > SKILLS.md
echo "print('hello')" > helper.py
echo '{"setting": true}' > config.json

# Re-sign
nono trust sign SKILLS.md helper.py config.json --key test-key
```

Get the key ID from `nono trust list`, then create `trust-policy.json`:

```bash
# Replace KEY_ID with actual key ID from `nono trust list`
# Replace PUBLIC_KEY_B64 with the base64 public key
cat > trust-policy.json << 'EOF'
{
  "version": 1,
  "instruction_patterns": ["SKILLS*"],
  "publishers": [
    {
      "name": "test",
      "key_id": "KEY_ID_HERE"
    }
  ],
  "blocklist": {"digests": [], "publishers": []},
  "enforcement": "deny"
}
EOF
```

Sign the trust policy itself:

```bash
nono trust sign trust-policy.json --key test-key
```

Run a sandboxed command with trust scanning:

```bash
nono run --trust-override -- echo "sandbox works"
```

Expected: trust scan runs, shows verification results for instruction files and multi-subject bundle subjects.

## 7. Tamper detection during pre-exec

```bash
# Tamper with a signed companion file
echo "EVIL" > helper.py

nono run --trust-override -- echo "should this work?"
```

Expected with `--trust-override`: proceeds with warning.
Without `--trust-override` and `enforcement: deny`: aborts.

## 8. Read-only enforcement in sandbox

```bash
# Restore files and re-sign
echo "# Skills" > SKILLS.md
echo "print('hello')" > helper.py
nono trust sign SKILLS.md helper.py --key test-key

# Run a command that tries to modify a verified file
nono run --trust-override --allow /tmp/nono-test -- bash -c 'echo "modify" >> helper.py && echo "wrote to helper.py"'
```

Expected: the write to `helper.py` should fail (EPERM) because verified subjects are added as read-only capabilities.

## 9. Keyless signing (requires OIDC/browser)

```bash
cd /tmp/nono-test
echo "# Skills" > SKILLS.md
echo "print('hello')" > helper.py

nono trust sign SKILLS.md helper.py --keyless
ls -la .nono-trust.bundle
```

Expected: opens browser for OIDC authentication, creates `.nono-trust.bundle` with Fulcio cert + Rekor entry.

## Cleanup

```bash
rm -rf /tmp/nono-test
```
