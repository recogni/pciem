# Agent guidelines

This repository is a public fork of an open-source project. Contributors
often find and fix bugs while working in private, proprietary codebases.
Everything written here is public: code, comments, tests, commit messages,
branch names, PR titles and descriptions, and issue text.

## Keep private context out

- Describe changes only in terms of this project's own code and behavior.
  Reproduce bugs with this repo's examples or a minimal standalone
  reproducer, not with the private workload where they were found.
- Do not mention private repository names, internal project or product
  codenames, internal hostnames, paths, or URLs, ticket or issue IDs from
  private trackers, customer names, unreleased hardware details, or people
  other than the commit author.
- Watch for leaks in pasted material. Logs, stack traces, file paths, and
  identifiers copied from another codebase often carry internal names.
  Rename or generalize them.
- If your environment gives you a list of internal terms, treat it as
  authoritative. Otherwise, use your judgement. If you aren't sure whether
  something is internal, leave it out or ask the user.
- Before committing or opening a PR, reread the diff, the commit message,
  and the PR description with this in mind.

## Branches

- `main` is a pure mirror of upstream. Only upstream syncs update it.
  Never commit to it, push to it, or open PRs against it.
- `dev` holds this fork's own changes, including this file. Fork-only
  work branches from `dev` and opens PRs against `dev`.
- To send a fix upstream, branch from `upstream/main` and open the PR
  against the upstream repository, not this fork. Don't branch from `dev`,
  or fork-only files like this one will end up in the upstream PR.
