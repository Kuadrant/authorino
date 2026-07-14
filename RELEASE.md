# How to release Authorino

Authorino uses a two-phase release workflow. Every release is split into two GitHub Actions workflows with a human review gate between them. See [RFC: Two-Phase Release Workflow](https://github.com/Kuadrant/architecture/pull/178) for the full specification.

## Phase 1: Pre-release

1. Go to **Actions → Pre-release** and click **Run workflow**.
2. Enter the target version (e.g. `0.27.0`).
   - For patch releases, set **source-branch** to the existing release branch (e.g. `release-0.27`) if cherry-picks have already been applied there. Otherwise leave it as `main`.
3. The workflow creates the release branch `release-X.Y` (if needed), updates `release.yaml`, runs code generation, and opens a pull request.
4. Review the PR. CI runs tests, code style checks, and the **Version Gate** check.
5. Merge the PR once all checks pass.

## Phase 2: Release

1. Go to **Actions → Release** and click **Run workflow**.
2. Enter the release branch (e.g. `release-0.27`).
3. The workflow:
   - Reads the version from `release.yaml`
   - Runs smoke tests (lint, unit tests, CEL tests)
   - Creates and pushes the `vX.Y.Z` tag
   - Builds and pushes the multi-arch container image to `quay.io/kuadrant/authorino`
   - Creates the GitHub Release (final step)

If any step fails, no GitHub Release is created.

## Release artifacts

| Artifact | Location |
|----------|----------|
| Container image | `quay.io/kuadrant/authorino:vX.Y.Z` |
| GitHub Release | `github.com/Kuadrant/authorino/releases/tag/vX.Y.Z` |

## Version file

The `release.yaml` file at the repository root is the source of truth for version information:

- On `main`: version is always `0.0.0` (active development)
- On release branches: version is the target release (e.g. `0.27.0`)

## GitHub configuration

The release workflows require the following repository secrets to be configured in **Settings → Secrets and variables → Actions**:

| Secret | Used by | Purpose |
|--------|---------|---------|
| `IMG_REGISTRY_USERNAME` | `build-images.yaml` | Username for the `quay.io` container registry |
| `IMG_REGISTRY_TOKEN` | `build-images.yaml` | Auth token/password for the `quay.io` container registry |

The `GITHUB_TOKEN` secret is provided automatically by GitHub Actions and does not need to be configured. It is used by the pre-release workflow to create branches and open pull requests, and by the release workflow to create tags and GitHub Releases.

The release workflow passes `secrets: inherit` when calling `build-images.yaml`, so the registry secrets must be set at the repository (or organization) level — not scoped to an environment.

## Notes on automated builds

- PRs merged to `main` trigger an image build pushed to `quay.io/kuadrant/authorino:latest` (and `quay.io/kuadrant/authorino:<sha>`).
- Smoke tests run automatically after each image build on `main`.
- Authorino owns the AuthConfig CRD and RBAC manifests. A copy is maintained in the [Authorino Operator repository](https://github.com/Kuadrant/authorino-operator).
