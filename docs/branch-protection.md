# Branch Protection Settings for `main`

> **P1 owns this document.** These settings must be applied by a repository admin
> before any team member starts working on Phase 2.

## Required Settings

Apply all of the following to the `main` branch:

| Setting | Required Value |
|---------|---------------|
| Require a pull request before merging | ✅ Enabled |
| Required number of approvals | 1 (non-author) |
| Dismiss stale pull request approvals when new commits are pushed | ✅ Enabled |
| Require review from Code Owners | ✅ Enabled |
| Require status checks to pass before merging | ✅ Enabled |
| Required status checks | See list below |
| Require branches to be up to date before merging | ✅ Enabled |
| Do not allow bypassing the above settings | ✅ Enabled |
| Allow force pushes | ❌ Disabled |
| Allow deletions | ❌ Disabled |
| Require linear history | ✅ Enabled |

### Required Status Checks

These job names must be listed as required checks (they come from `.github/workflows/pipeline.yml`):

- `Contracts & Tests`
- `Prepare Stage Matrix`
- `Stage: secrets`
- `Stage: sast`
- `Stage: sca`
- `Stage: iac`
- `Stage: container`
- `Stage: sbom`
- `Policy Gate`

> **Note:** Add the dast stage check when it is enabled in Phase 3.

## CODEOWNERS: Contracts Require All Four Approvals

The `/contracts/` line in `CODEOWNERS` lists all four handles:

```
/contracts/   @p1-handle @p2-handle @p3-handle @p4-handle
```

This means any PR touching `contracts/` requires approval from all four members
before it can be merged. This enforces the contracts-are-frozen-after-sign-off rule.

## Applying Branch Protection via `gh` CLI

Replace `OWNER/REPO` with the actual repository path.

```bash
gh api \
  --method PUT \
  repos/OWNER/REPO/branches/main/protection \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Contracts & Tests",
      "Prepare Stage Matrix",
      "Stage: secrets",
      "Stage: sast",
      "Stage: sca",
      "Stage: iac",
      "Stage: container",
      "Stage: sbom",
      "Policy Gate"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true,
  "block_creations": false
}
EOF
```

> **Note:** You cannot apply these settings without being a repository admin or
> organization owner. The agent cannot apply them on your behalf.
> Run the command above after the repository is created on GitHub.

