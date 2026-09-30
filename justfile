# https://github.com/casey/just

build:
	goreleaser build --clean --snapshot

buildWithVersion version commitHash:
	go build -ldflags "-X main.version={{version}} -X main.commit={{commitHash}}" .

# Tag, push and publish a release (GitHub + Homebrew tap), e.g. `just release v1.2.3`
release version:
	#!/usr/bin/env bash
	set -euo pipefail
	version="{{version}}"
	if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
		echo "Invalid version '$version'. Expected semantic version like v1.2.3 or v1.2.3-rc.1." >&2
		exit 1
	fi
	if [[ -n "$(git status --porcelain)" ]]; then
		echo "Working tree is not clean. Commit or stash your changes first." >&2
		exit 1
	fi
	if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
		echo "Tag $version already exists locally." >&2
		exit 1
	fi
	if git ls-remote --exit-code --tags origin "refs/tags/$version" >/dev/null; then
		echo "Tag $version already exists on origin." >&2
		exit 1
	fi
	# GoReleaser needs a GitHub token to create the release. Fall back to the
	# GitHub CLI's token if one isn't set.
	if [[ -z "${GITHUB_TOKEN:-}" ]]; then
		GITHUB_TOKEN="$(gh auth token)"
		export GITHUB_TOKEN
	fi
	goreleaser check
	echo "Creating release $version from commit $(git rev-parse --short HEAD)"
	git tag -a "$version" -m "$version"
	git push origin "$version"
	goreleaser release --clean

hash:
	git rev-parse --short HEAD
