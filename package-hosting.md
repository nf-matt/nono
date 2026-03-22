# Package Policy System for nono

## Context

Agent-specific artifacts (profiles, hooks, instruction files, scripts) are currently hardcoded into the nono binary or require manual setup. Adding support for a new coding agent (Cursor, Claude Code, Codex) means modifying `policy.json`, embedding hook scripts in `build.rs`, and often adding agent-detection logic. This creates maintenance burden (PR #404), muddy separation of concerns (#353), and inflexible hook/script management (#407).

The goal: let these artifacts live **out-of-tree** as signed packages in the existing nono-registry, installable via `nono pull`.

## Design Decisions

- **Top-level commands**: `nono pull`, `nono remove`, `nono update`, `nono search` (not under a `package` subcommand).
- **Registry URL**: Hardcoded default (`https://registry.nono.sh`), overridable via `--registry` flag and `NONO_REGISTRY` env var.
- **Scope**: Pull-side only. No `nono push` -- publishing happens via GitHub Actions CI + registry API (already working).
- **Registry stores artifacts**: The registry stores verified artifacts, not proxied from GitHub. See "Trust Model" section below.

## Trust Model

### The Registry Is Not a Trust Anchor

The registry is a distribution channel and a verification service. It is **not** a trust anchor. The trust anchor is the Sigstore cryptography binding each artifact to the source repository's GitHub Actions OIDC identity.

When a user runs `nono pull acme-corp/claude-policy`, the artifacts they receive carry Sigstore bundles containing Fulcio certificates with embedded OIDC claims (issuer, repository, workflow, ref) and Rekor transparency log inclusion proofs. The client verifies these bundles locally using the Sigstore trust root -- not by asking the registry whether the artifacts are legitimate.

This means: **even if the registry were fully compromised, an attacker cannot forge valid artifacts for `acme-corp/claude-policy`**. Producing a valid Sigstore bundle for the `acme-corp` namespace requires a GitHub Actions OIDC token issued to an `acme-corp/*` repository. The attacker would need to compromise the source repository itself -- at which point the registry is irrelevant.

The user sees a cryptographic proof that the content on their machine is byte-identical to what was signed in the source repository's CI pipeline. The registry has merely transported those bytes. The namespace in the pull command (`acme-corp/`) is verified against the OIDC identity claims in the Fulcio certificate, so the human-readable package name is cryptographically bound to the source organization.

### Why the Registry Stores Artifacts (Not Proxied from GitHub)

The registry stores verified artifacts rather than proxying downloads from GitHub:

1. **Availability**: Force pushes, deleted tags, private repo changes, and GitHub outages do not break `nono pull`. The artifacts the registry verified and stored are the artifacts it serves.
2. **No TOCTOU gap**: The security scan and provenance verification apply to the exact bytes stored. Proxying from GitHub introduces a window where content could change between verification and download.
3. **Simpler client**: `nono pull` talks to one endpoint. No GitHub API auth, rate limiting, or repo structure parsing.
4. **Scan authority**: Prompt injection scans and policy analysis results are authoritative because they ran against the stored content, not a snapshot that may have since changed.

### Publishing Flow

```
1. Author pushes to GitHub (e.g., acme-corp/nono-policies)
2. GitHub Action triggers:
   a. Signs all artifacts with Sigstore (keyless OIDC via Fulcio + Rekor)
   b. Uploads artifacts + bundles to registry via API
3. Registry receives upload:
   a. Verifies Sigstore bundles (Fulcio cert chain, Rekor inclusion proof)
   b. Asserts OIDC claims match the registered trusted publisher (org/repo/workflow)
   c. Runs security scans (prompt injection detection, policy analysis)
   d. Stores artifacts + bundles + scan metadata
   e. Publishes the version
4. User: nono pull acme-corp/claude-policy
   a. Downloads artifacts + bundles from registry
   b. Verifies bundles locally (Sigstore trust root, not registry trust)
   c. Asserts signer identity matches the namespace in the pull command
   d. Displays provenance proof to user
   e. Installs artifacts
```

### Trusted Publisher Registration

Package namespaces are bound to GitHub organizations via trusted publisher registration, following the same model as PyPI and npm trusted publishing. A package author registers their namespace by declaring which GitHub org, repository, and workflow are authorized to publish:

| Registry Field | Matched Against | Example |
|----------------|----------------|---------|
| `namespace` | Fulcio cert `repository` org component | `acme-corp` |
| `repository` | Fulcio cert `repository` claim | `acme-corp/nono-policies` |
| `workflow` | Fulcio cert `workflow` claim | `.github/workflows/publish.yml` |

The registry rejects uploads where the Fulcio certificate OIDC claims do not match the registered trusted publisher for that namespace. No long-lived secrets are involved -- the trust is derived entirely from GitHub's OIDC identity federation.

### Namespace-to-Identity Verification on Pull

When `nono pull acme-corp/claude-policy` runs, the client performs three independent checks:

| Check | What It Proves | Failure Mode |
|-------|---------------|--------------|
| Sigstore bundle verification | Artifacts were signed by a valid Fulcio certificate, logged in Rekor | Abort: signature invalid or cert chain broken |
| Signer identity extraction | The Fulcio certificate identifies the signing workflow and repository | Abort: cannot extract identity claims |
| Namespace assertion | The signer's repository org matches `acme-corp` | Abort: identity mismatch -- artifacts not from claimed source |

The third check is what closes the loop. Without it, a user could receive artifacts validly signed by `evil-corp/backdoor-policies` under the name `acme-corp/claude-policy`. The namespace assertion ensures the human-readable name in the pull command is cryptographically bound to the source organization.

### Provenance Display

On successful pull, the client displays the full provenance chain:

```
$ nono pull acme-corp/claude-policy

  Pulling acme-corp/claude-policy@1.2.0...

  Provenance:
    Signer:     https://github.com/acme-corp/nono-policies/.github/workflows/publish.yml@refs/heads/main
    Repository: acme-corp/nono-policies
    Signed at:  2026-03-17T14:32:01Z (Rekor entry #12345678)
    Scan:       passed (prompt injection, policy analysis)

  Verified: artifacts cryptographically match content signed in acme-corp/nono-policies

  Installed 4 artifacts:
    profile     claude-policy.profile.json -> ~/.config/nono/profiles/claude-policy.json
    hook        hooks/nono-hook.sh -> ~/.claude/hooks/nono-hook.sh
    instruction CLAUDE.md
    groups      groups.json (prefix: acme_corp)
```

The "Verified" line is the key message: the content on the user's machine is byte-identical to what was signed in the source repository's CI pipeline. The registry transported the bytes; the cryptography proves they are authentic.

### Without the Registry

The registry is not required. Package authors can distribute signed artifacts directly — via git clone, tarball, or any other transport mechanism. In this case, the author signs the files using `nono trust sign` (keyed or keyless), and consumers verify the bundles locally using `nono trust verify`.

What the user gives up without the registry:

- **No `nono pull`**: The user is responsible for retrieving files and placing them in the correct locations.
- **No centralized security scanning**: The registry's prompt injection and policy analysis scans do not run. The user trusts the content based solely on the Sigstore signature.
- **No signer pinning via lockfile**: There is no lockfile to track the expected signer identity across updates.
- **No availability guarantee**: If the source repository changes or disappears, the files are gone.

What the user retains:

- **Cryptographic provenance**: The Sigstore bundles still prove who signed the files and that the content has not been tampered with.
- **Sandbox enforcement**: The sandbox policy, hooks, and trust policy all function identically regardless of how the files arrived on disk.

This is the same model described in the existing trust documentation. The registry adds a managed distribution layer with additional verification on top.

## Package Manifest Format

Each package source directory contains a `package.json` manifest uploaded as an artifact alongside the payload files. The registry already stores namespace/name/version and Sigstore bundles per artifact.

```json
{
  "schema_version": 1,
  "name": "claude-code",
  "description": "Sandbox profile, hooks, and trust policy for Claude Code",
  "license": "Apache-2.0",
  "platforms": ["macos", "linux"],
  "min_nono_version": "0.19.0",
  "artifacts": [
    {
      "type": "profile",
      "path": "claude-code.profile.json",
      "install_as": "claude-code"
    },
    {
      "type": "hook",
      "path": "hooks/nono-hook.sh",
      "target": "claude-code",
      "install_dir": "~/.claude/hooks"
    },
    {
      "type": "instruction",
      "path": "CLAUDE.md",
      "placement": "project"
    },
    {
      "type": "trust_policy",
      "path": "trust-policy.json",
      "merge_strategy": "additive"
    },
    {
      "type": "groups",
      "path": "groups.json",
      "prefix": "claude_code"
    }
  ]
}
```

## Artifact Types and Installation Targets

| Type | Install Location | Behavior |
|------|-----------------|----------|
| `profile` | `~/.config/nono/packages/<ns>/<name>/profiles/` + symlink in `~/.config/nono/profiles/<install_as>.json` | Validated as `Profile` struct. Symlink makes it discoverable by existing `load_profile()`. |
| `hook` | `~/.config/nono/packages/<ns>/<name>/hooks/` + copied to `install_dir` | Script file. Never executed during install. Registered in target app settings via existing `install_hooks()` logic. |
| `instruction` | `~/.config/nono/packages/<ns>/<name>/instructions/` | CLAUDE.md, SKILLS.md etc. `placement: "project"` means copy to CWD when `nono pull --init` is used. |
| `trust_policy` | `~/.config/nono/packages/<ns>/<name>/trust-policy.json` | Merged additively into effective trust policy at load time. Cannot weaken existing policy. |
| `groups` | `~/.config/nono/packages/<ns>/<name>/groups.json` | Additional policy groups referenced by the package's profile. All names must start with `prefix`. Loaded alongside embedded `policy.json`. |
| `script` | `~/.config/nono/packages/<ns>/<name>/scripts/` | Utility scripts. Not auto-executed. Made executable on install. |

## Local Package Store

```
~/.config/nono/packages/
  lockfile.json
  nono-project/
    claude-code/
      package.json
      profiles/claude-code.profile.json
      hooks/nono-hook.sh
      instructions/CLAUDE.md
      trust-policy.json
      groups.json
```

## `nono pull` Flow

**Invocation**: `nono pull <namespace>/<name>[@<version>] [--registry URL] [--force] [--init]`

1. Parse package reference (`<namespace>/<name>[@<version>]`). If no version, fetch latest from registry.
2. Check `lockfile.json` -- if same version + checksums, print "up to date" and exit.
3. Download manifest (`package.json`) + its Sigstore bundle from registry.
4. Verify manifest bundle via existing `nono::trust::bundle` verification. Abort on failure.
5. **Namespace assertion**: Extract the repository claim from the Fulcio certificate in the manifest bundle. Assert the org component matches `<namespace>`. Abort on mismatch -- this prevents a compromised registry from serving artifacts signed by a different organization.
6. Check `min_nono_version` against running CLI version (semver comparison). Filter `platforms` against current OS.
7. Download each artifact + its Sigstore bundle.
8. Verify each artifact's Sigstore bundle. Compute SHA-256 digest. Abort on any failure, clean up partial downloads.
9. **Signer consistency**: Assert all artifact bundles share the same signer identity (same repository, workflow, ref). A package where the profile was signed by `acme-corp` but the hook was signed by `other-org` is rejected.
10. Stage to `~/.config/nono/packages/.staging/<ns>/<name>/`.
11. Install by type:
    - **profile**: Validate as `Profile`. Copy to package dir. Symlink into `~/.config/nono/profiles/`.
    - **hook**: Copy to package dir + `install_dir` (restricted to allowed directories). Register in target app settings.
    - **trust_policy**: Validate. Copy to package dir.
    - **groups**: Validate prefix. Copy to package dir.
    - **instruction**: Copy to package dir. If `--init`, also copy to CWD.
    - **script**: Copy to package dir. `chmod +x`.
12. Atomic commit: rename staging to final path. Remove previous version if upgrading.
13. Update `lockfile.json` with version, signer identity, artifact digests, and Rekor log index.
14. Print provenance proof and installation summary.

## Lockfile Format

```json
{
  "lockfile_version": 1,
  "registry": "https://registry.nono.sh",
  "packages": {
    "nono-project/claude-code": {
      "version": "1.2.0",
      "installed_at": "2026-03-17T10:00:00Z",
      "provenance": {
        "signer_identity": "https://github.com/nono-project/packages/.github/workflows/publish.yml@refs/heads/main",
        "repository": "nono-project/packages",
        "workflow": ".github/workflows/publish.yml",
        "ref": "refs/heads/main",
        "rekor_log_index": 12345678,
        "signed_at": "2026-03-17T10:00:00Z"
      },
      "artifacts": {
        "claude-code.profile.json": { "sha256": "abc123...", "type": "profile" },
        "hooks/nono-hook.sh": { "sha256": "def456...", "type": "hook" }
      }
    }
  }
}
```

### Signer Pinning

On subsequent pulls of the same package (e.g., `nono update`), the client compares the new version's signer identity against the `provenance.signer_identity` stored in the lockfile. If the signer identity changes -- even if the new signature is cryptographically valid -- the update is rejected:

```
$ nono update nono-project/claude-code

  Error: signer identity changed for nono-project/claude-code
    Previously: .../nono-project/packages/.github/workflows/publish.yml@refs/heads/main
    Now:        .../other-org/fork/.github/workflows/publish.yml@refs/heads/main

  This could indicate the package source has changed or been compromised.
  Use --force to accept the new signer identity.
```

This prevents an attacker who compromises the registry database from substituting artifacts signed by a different (but valid) Sigstore identity. The first `nono pull` establishes the expected signer; subsequent updates enforce continuity.

## Other Commands

- **`nono remove <ns/name>`**: Delete package dir, remove profile symlink, unregister hooks from target app settings, remove lockfile entry.
- **`nono update [<ns/name>]`**: Check registry for newer versions of installed packages. Pull if available. Without args, updates all.
- **`nono search <query>`**: `GET /api/v1/packages?search=<query>`, display name/description/version/kind table.
- **`nono list --installed`**: Read lockfile, display installed packages with version and install date.

## Hook Script Externalization

Script resolution in `hooks.rs` becomes a fallback chain:

1. Package store (if active profile came from a package)
2. User override: `~/.config/nono/hooks/<script_name>`
3. Embedded script (backward compat for built-in profiles)

`install_hooks()` modified to accept script content as parameter instead of always reading from `embedded::NONO_HOOK_SH`.

New helper `get_package_for_profile(name) -> Option<PathBuf>` checks if `~/.config/nono/profiles/<name>.json` is a symlink into the package store.

## Policy Group Loading

`policy.rs` gains `load_package_groups()`:
1. Read lockfile for packages with `groups` artifacts.
2. Load each `groups.json`, validate names start with declared prefix.
3. Merge into effective `Policy` alongside embedded groups.

`resolve_groups()` already takes a `Policy` struct -- no signature change needed.

## Conflict Resolution

- Profile name collision with existing user file: warn, skip. `--force` to overwrite.
- Profile name collision with another package: error. Must `nono remove` first.
- Group name collision with embedded groups: error at install time.
- Upgrade: `nono pull` with newer version replaces old atomically.

## Migration Path

**Phase 1** (this work): Built-in profiles unchanged. Packages can override built-ins via symlink precedence. No breaking change.

**Phase 2** (future): Add `deprecated: "nono-project/claude-code"` to built-in profiles. Print migration hint. Built-in still works.

**Phase 3** (distant future): Remove non-`default` built-in profiles.

## Files to Create

| File | Purpose |
|------|---------|
| `crates/nono-cli/src/package.rs` | `PackageManifest`, `ArtifactEntry`, `ArtifactType` enums/structs. `Lockfile` types. Read/write lockfile. Package dir helpers. Per-type install logic. |
| `crates/nono-cli/src/registry_client.rs` | HTTP client using `ureq` (already a dep). `fetch_latest_version()`, `fetch_manifest()`, `download_artifact()`, `search_packages()`. Hardcoded default URL + override. |
| `crates/nono-cli/src/package_cmd.rs` | CLI command handlers: `cmd_pull()`, `cmd_remove()`, `cmd_update()`, `cmd_search()`, `cmd_list()`. |

## Files to Modify

| File | Change |
|------|--------|
| `crates/nono-cli/src/cli.rs` | Add `Pull`, `Remove`, `Update`, `Search` variants to `Commands`. Add `PACKAGES` section to help template. Args: `PullArgs { package_ref, registry, force, init }`, `RemoveArgs { package_ref }`, etc. |
| `crates/nono-cli/src/main.rs` | Route `Commands::Pull` etc. to `package_cmd` handlers. |
| `crates/nono-cli/src/hooks.rs` | Add `resolve_hook_script()` fallback chain. Modify `install_hooks()` / `install_claude_code_hook()` to accept script content parameter. |
| `crates/nono-cli/src/profile/mod.rs` | Add `get_package_for_profile()` helper. No change to `load_profile()` (symlinks handle discovery). |
| `crates/nono-cli/src/policy.rs` | Add `load_package_groups()`. Call it when building effective policy. |
| `crates/nono/src/error.rs` | Add `PackageInstall(String)`, `PackageVerification { package, reason }`, `RegistryError(String)` variants. |

## Implementation Order

1. **Error variants** (`error.rs`) -- foundation for all new code.
2. **Package types** (`package.rs`) -- manifest, lockfile, artifact type definitions, dir helpers.
3. **Registry client** (`registry_client.rs`) -- HTTP fetch for manifests/artifacts/search.
4. **Pull command** (`package_cmd.rs`) -- core flow: download, verify, stage, install, lockfile.
5. **CLI integration** (`cli.rs`, `main.rs`) -- add subcommands, route to handlers.
6. **Hook externalization** (`hooks.rs`) -- fallback chain, parameterize `install_hooks()`.
7. **Group loading** (`policy.rs`) -- merge package groups into effective policy.
8. **Remove/Update/Search/List** (`package_cmd.rs`) -- remaining commands.

## Verification

1. Start local registry instance (`nono-registry` with docker-compose).
2. Create a test package directory with profile + hook + manifest.
3. Publish via registry API (or seed DB directly).
4. `nono pull test/my-package --registry http://localhost:3000` -- verify artifacts in correct locations.
5. `nono run --profile my-package -- ls` -- verify profile loads via symlink.
6. Verify hook script resolves from package store, not embedded.
7. `nono remove test/my-package` -- verify cleanup (symlink, hooks, lockfile entry).
8. `nono search test --registry http://localhost:3000` -- verify search output.
9. `make ci` passes.

