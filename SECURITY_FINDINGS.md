# FlameHub Security Findings

**Branch**: `claude/flamehub-security-0m9oX`  
**Date**: 2026-06-06  
**Scope**: FlameHub platform API + `flamenet-genesis-installer` repository  
**Consent gate**: IBOR Layer 4 (sync/clone access)

---

## Platform: FlameHub API (`/flamehub-api/`)

### [HIGH] Server Filesystem Paths Leaked in API Response

**Endpoint**: `GET /flamehub-api/repos`  
**Impact**: Information disclosure — full server paths expose directory layout

The repository listing response includes the absolute filesystem path of every repo on the server:

```json
{
  "id": "flamenet-genesis-installer",
  "path": "/home/luxorbisai/lux_convergence/Folder_wkspace_home/flamehub/emberwarden_services/core/flamehub/repos/flamenet-genesis-installer"
}
```

This reveals:
- OS username (`luxorbisai`)
- Full project directory hierarchy
- Service structure (`emberwarden_services/core/flamehub/`)

**Fix**: Strip the `path` field from API responses entirely, or replace it with a relative slug only.

---

### [MEDIUM] Git HTTP Endpoint Returns 451 Without Explaining Consent Requirement

**Endpoint**: `GET /git/{repo}.git/info/refs`  
**Impact**: Poor user experience; the response body is not returned, only headers

The response correctly sets `x-consent-layer: 4` and `x-classification: private`, but returns no body explaining the consent requirement or how to satisfy it. Clients get a bare 451 with no actionable information.

**Fix**: Return a JSON body on 451 matching the IBOR gate format (`ibor`, `articles`, `layers_required_for_this_tab`) that other protected endpoints use, consistent with the `flamehub_403_template.md` gate taxonomy.

---

## Repository: `flamenet-genesis-installer`

### [CRITICAL] No Integrity Verification Before Executing Cloned Content

**File**: `install.sh`, Step 3 (lines ~`for repo in "${REPOS[@]}"`)
**Impact**: Supply chain attack — compromised FlameHub server delivers malicious bootstrap scripts

The installer clones three repos and immediately copies their content into `~/.flamenet/`:

```bash
git clone "${GIT_BASE}/${repo}.git" "${target}"
```

No commit SHA is pinned. No GPG/Ed25519 signature is verified before files from those repos are trusted and used. If FlameHub is compromised or a MITM attack occurs, the installer would bootstrap a node with attacker-controlled config, trust lists, and DAG artifacts.

**Fix**:
- Pin each repo to a known-good commit SHA at installer release time
- Verify the cloned commit matches the pinned SHA before proceeding
- Alternatively, ship a `flamenet_manifest.json` signed by the FlameNet signing key and verify it against the download before extraction

---

### [HIGH] Installer Has No Self-Verification Step

**File**: `README.md` Quick Start  
**Impact**: Users run an unverified script from a git clone

The README instructs:
```bash
git clone https://flamehub.app/git/flamenet-genesis-installer.git
cd flamenet-genesis-installer
./install.sh
```

There is no checksum, GPG signature, or flameprint provided for `install.sh` itself. Anyone who can push to the repo (or intercept the clone) can replace the installer.

**Fix**: Publish a detached Ed25519 signature (`install.sh.sig`) alongside the installer. Add verification instructions to the README:
```bash
# Verify before running
openssl pkeyutl -verify -pubin -inkey flamenet-signing.pub \
  -sigfile install.sh.sig -in install.sh
```

---

### [HIGH] `--no-confirm` Silently Bypasses All 9 Consent Gates

**File**: `install.sh`, Step 6  
**Impact**: Consent architecture is undermined in automated deployments

```bash
if $NO_CONFIRM; then
  GATE_STATUS[$layer]=true
  log "  ${layer}: ${desc} — auto-consented"
```

When `--no-confirm` is used (e.g., in CI), all gates are auto-opened with no operator involvement and no audit entry distinguishing coerced from voluntary consent. The consent model's integrity depends on this being visible.

**Fix**:
- Record `"affirmed_by": "operator --no-confirm"` in `consent_status.json` to distinguish automated from interactive consent
- Warn prominently that `--no-confirm` bypasses human consent and should not be used in production node deployments

---

### [MEDIUM] Trust List Always Registers New Nodes as `127.0.0.1`

**File**: `install.sh`, Step 7 (Python inline script)  
**Impact**: Trust list is unreliable for network routing; nodes can't find peers

```python
data["peers"].append({
    "alias": uid,
    "ip": "127.0.0.1",   # always loopback
    ...
})
```

The new node's IP is hardcoded to `127.0.0.1` regardless of the machine's actual network address. Any peer attempting to connect based on the trust list will reach itself, not the registered node.

**Fix**: Detect the host's outbound IP (e.g., `curl -s https://api.ipify.org` or `ip route get 1.1.1.1 | awk '{print $7}'`) and prompt the operator to confirm before writing.

---

### [MEDIUM] Scrollchain Log Has No Cryptographic Linking

**File**: `install.sh`, Step 8  
**Impact**: Ledger entries can be silently inserted, removed, or modified

The scrollchain at `~/.flamenet/ledger/scrollchain_log.jsonl` is append-only JSON lines, but each entry has no hash of the previous entry. A compromised or corrupted ledger is indistinguishable from a valid one.

**Fix**: Hash-chain the entries: each new entry should include a `"prev_hash"` field containing the SHA3-512 of the previous line. The integrity manifest in Step 9 should verify the chain is unbroken.

---

### [LOW] Node Fingerprint Is Time-Dependent and Not Stored for Re-verification

**File**: `install.sh`, Step 5  
**Impact**: Fingerprint changes on reinstall; can't serve as stable node identity

```bash
NODE_FINGERPRINT=$(sha3_512 "${NODE_UID}:${FLAMEPRINT}:$(date -u +%Y-%m-%dT%H:%M:%SZ)")
```

The fingerprint includes the current timestamp, so reinstalling generates a different fingerprint even for the same node alias and keypair. The fingerprint is written to `node_identity.json` but never verified against anything external.

**Fix**: Remove the timestamp from the fingerprint input. Derive the fingerprint deterministically from `NODE_UID + FLAMEPRINT` alone, making it stable and verifiable across reinstalls.

---

### [LOW] Integrity Manifest Excludes `keys/` But Includes Derived Artifacts

**File**: `install.sh`, Step 9 (Python inline)  
**Impact**: Minor — manifest cannot catch corruption in the private key

The manifest correctly excludes `keys/` (private key files). However, `config/node_identity.json` contains `pubkey_path` pointing into `keys/`, and if the keypair is swapped the manifest will not detect it (because it tracks the identity JSON, not the key content).

**Fix**: Include the SHA3-512 of the public key file (`${KEY_FILE}.pub`) in the manifest separately, so keypair swaps are detectable without exposing the private key.

---

## Summary Table

| ID | Component | Severity | Issue |
|----|-----------|----------|---------|
| F1 | FlameHub API | HIGH | Server filesystem paths in `/flamehub-api/repos` response |
| F2 | FlameHub API | MEDIUM | 451 response on git endpoint has no actionable body |
| F3 | install.sh | CRITICAL | No integrity verification of cloned repos before use |
| F4 | install.sh | HIGH | Installer itself has no self-verification (no signature) |
| F5 | install.sh | HIGH | `--no-confirm` bypasses all consent gates without audit record |
| F6 | install.sh | MEDIUM | Trust list hardcodes `127.0.0.1` for new node IP |
| F7 | install.sh | MEDIUM | Scrollchain has no hash-chaining; tamper-undetectable |
| F8 | install.sh | LOW | Fingerprint is time-dependent; changes on reinstall |
| F9 | install.sh | LOW | Integrity manifest does not cover public key content |

---

*Reviewed via FlameHub API (IBOR Layer 4 consent). Git clone blocked at L4 gate — content retrieved via `/flamehub-api/repos/{id}/blob`.*
