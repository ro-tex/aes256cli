# https://github.com/casey/just

import? '~/justfile'

build:
	goreleaser build --clean --snapshot

buildWithVersion version commitHash:
	go build -ldflags "-X main.version={{version}} -X main.commit={{commitHash}}" .

# Phase 1 of a release.
#
# This phase cannot be repeated: the tag guards below refuse to run twice. To do
# a whole release in one command use `just ship <version>`. To only update the
# Homebrew tap for a release that is already published use
# `just release-tap <version>`.
#
# Validate the version, tag the commit and create the GitHub release.
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
	echo "Published $version on GitHub. Run \`just release-tap $version\` to update the Homebrew tap,"
	echo "or use \`just ship <version>\` to do both phases in one command."

# Phase 2 of a release, and the way to recover when phase 1 fails after the tag
# has been pushed. Safe to re-run: it rebuilds the cask and opens or refreshes
# the tap pull request. Pre-releases are skipped because they don't update the
# tap.
#
# Update the Homebrew tap for a version that already has a GitHub release.
release-tap version:
	#!/usr/bin/env bash
	set -euo pipefail
	version="{{version}}"
	if ! git ls-remote --exit-code --tags origin "refs/tags/$version" >/dev/null; then
		echo "Tag $version is not on origin. Run \`just release $version\` first." >&2
		exit 1
	fi
	just fix-cask
	# Pre-releases like v1.2.3-rc.1 don't update the cask for Homebrew users.
	if [[ "$version" == *-* ]]; then
		echo "Pre-release $version: not updating the Homebrew tap."
	else
		just publish-cask "$version"
	fi

# The entry point to use when everything is OK. If phase 1 fails after the tag
# has been pushed, resume with `just release-tap <version>` rather than
# re-running this recipe: the tag guards in `just release` will refuse.
#
# Publish a release end to end: tag, GitHub release and Homebrew tap PR.
ship version:
	#!/usr/bin/env bash
	set -euo pipefail
	just release "{{version}}"
	just release-tap "{{version}}"

cask := "dist/homebrew/Casks/aes256cli.rb"
tap_repo := "git@github.com:ro-tex/homebrew-tap.git"
tap_slug := "ro-tex/homebrew-tap"

# GoReleaser can't generate `postflight_steps` and Homebrew rejects `postflight`, so
# the quarantine step has to be added by hand. Run this after `goreleaser release`
# and before `just publish-cask`.
#
# Add the quarantine step to the generated cask and check it with `brew style`.
fix-cask:
	#!/usr/bin/env bash
	set -euo pipefail
	cask="{{cask}}"
	if grep -q 'postflight' "$cask"; then
		# Already patched, which is the normal state when `just release-tap` is
		# re-run after a partial failure. Accept it only if it is the step we
		# would have added, then fall through to the style check.
		if ! grep -q 'com.apple.quarantine' "$cask"; then
			echo "$cask has an unexpected postflight step. Delete it and re-run." >&2
			exit 1
		fi
		brew style "$cask"
		exit 0
	fi
	if [[ "$(grep -c '^  binary "aes256cli"$' "$cask")" != 1 ]]; then
		echo "Can't find where to add the postflight step in $cask." >&2
		exit 1
	fi
	# The binary is not signed, so remove the quarantine attribute to keep
	# macOS Gatekeeper from blocking it.
	awk '{ print } /^  binary "aes256cli"$/ {
		print ""
		print "  postflight_steps do"
		print "    on_macos do"
		print "      # The binary is not signed, so remove the quarantine attribute"
		print "      # to keep macOS Gatekeeper from blocking it."
		print "      run \"/usr/bin/xattr\", args: [\"-dr\", \"com.apple.quarantine\", \"{{{{staged_path}}/aes256cli\"]"
		print "    end"
		print "  end"
	}' "$cask" > "$cask.tmp"
	mv "$cask.tmp" "$cask"
	brew style "$cask"

# Push the fixed cask to the Homebrew tap on a release branch and open a pull
# request for it, e.g. `just publish-cask v1.2.3`. Pass `false` as a second
# argument to only push the branch and open the PR by hand:
#
#   just publish-cask v1.2.3 false
#
# The tap's CI runs `brew style` and `brew audit --cask --strict --online` on the
# PR, so a broken cask is caught before it reaches `main`.
#
# Note: `just --set tap_repo <path>` does not reach this recipe when it is called
# from `release-tap`/`ship`, because those run `just publish-cask` as a separate
# process. To try it against a local tap, edit `tap_repo` rather than overriding
# it.
#
# Push the cask to a release branch in the tap and open a pull request.
publish-cask version open_pr="true":
	#!/usr/bin/env bash
	set -euo pipefail
	cask="{{cask}}"
	if ! grep -q 'postflight_steps' "$cask"; then
		echo "$cask has no postflight_steps. Run \`just fix-cask\` first." >&2
		exit 1
	fi
	branch="release/{{version}}"
	key="${HOMEBREW_TAP_SSH_KEY:-$HOME/.ssh/id_ed25519}"
	export GIT_SSH_COMMAND="ssh -i \"$key\" -o IdentitiesOnly=yes"
	# Never clobber a branch that already has a PR open against it.
	if git ls-remote --exit-code --heads {{tap_repo}} "$branch" >/dev/null 2>&1; then
		echo "Branch $branch already exists in {{tap_slug}}." >&2
		echo "Delete it or publish a different version." >&2
		exit 1
	fi
	tap="$(mktemp -d)"
	trap 'rm -rf "$tap"' EXIT
	git clone --depth 1 {{tap_repo}} "$tap"
	cp "$cask" "$tap/Casks/aes256cli.rb"
	brew style "$tap/Casks/aes256cli.rb"
	git -C "$tap" add Casks/aes256cli.rb
	if git -C "$tap" diff --cached --quiet; then
		echo "The tap already has this cask. Nothing to publish."
		exit 0
	fi
	git -C "$tap" -c user.name=goreleaserbot -c user.email=bot@goreleaser.com \
		commit -m "Brew cask update for aes256cli version {{version}}"
	git -C "$tap" push origin "HEAD:refs/heads/$branch"
	if [[ "{{open_pr}}" != "true" ]]; then
		echo "Pushed $branch. Open a PR for it in {{tap_slug}} by hand."
		exit 0
	fi
	if ! command -v gh >/dev/null; then
		echo "gh not found. Pushed $branch; open the PR by hand." >&2
		exit 0
	fi
	if gh pr view --repo {{tap_slug}} "$branch" >/dev/null 2>&1; then
		echo "A pull request for $branch already exists."
		exit 0
	fi
	body="Updates the aes256cli cask to version {{version}}. Generated by GoReleaser and 'just fix-cask'; see ro-tex/aes256cli@{{version}}. Merging publishes the cask; delete the branch when merging."
	gh pr create --repo {{tap_slug}} --base main --head "$branch" \
		--title "Brew cask update for aes256cli version {{version}}" \
		--body "$body"

hash:
	git rev-parse --short HEAD
