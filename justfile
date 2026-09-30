# https://github.com/casey/just

import '~/justfile'

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
	just fix-cask
	# Pre-releases like v1.2.3-rc.1 don't update the cask for Homebrew users.
	if [[ "$version" == *-* ]]; then
		echo "Pre-release $version: not updating the Homebrew tap."
	else
		just publish-cask "$version"
	fi

cask := "dist/homebrew/Casks/aes256cli.rb"

# GoReleaser can't generate `postflight_steps` and Homebrew rejects `postflight`, so
# add the quarantine step to the generated cask and check it with `brew style`.
fix-cask:
	#!/usr/bin/env bash
	set -euo pipefail
	cask="{{cask}}"
	if grep -q 'postflight' "$cask"; then
		echo "$cask already has a postflight step." >&2
		exit 1
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
		print "      run \"/usr/bin/xattr\", args: [\"-dr\", \"com.apple.quarantine\", \"{{{{staged_path}}/aes256cli\"]"
		print "    end"
		print "  end"
	}' "$cask" > "$cask.tmp"
	mv "$cask.tmp" "$cask"
	brew style "$cask"

# Push the fixed cask to the Homebrew tap, e.g. `just publish-cask v1.2.3`
publish-cask version:
	#!/usr/bin/env bash
	set -euo pipefail
	cask="{{cask}}"
	if ! grep -q 'postflight_steps' "$cask"; then
		echo "$cask has no postflight_steps. Run \`just fix-cask\` first." >&2
		exit 1
	fi
	key="${HOMEBREW_TAP_SSH_KEY:-$HOME/.ssh/id_ed25519}"
	export GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes"
	tap="$(mktemp -d)"
	trap 'rm -rf "$tap"' EXIT
	git clone --depth 1 git@github.com:ro-tex/homebrew-tap.git "$tap"
	cp "$cask" "$tap/Casks/aes256cli.rb"
	brew style "$tap/Casks/aes256cli.rb"
	git -C "$tap" add Casks/aes256cli.rb
	if git -C "$tap" diff --cached --quiet; then
		echo "The tap already has this cask."
		exit 0
	fi
	git -C "$tap" -c user.name=goreleaserbot -c user.email=bot@goreleaser.com \
		commit -m "Brew cask update for aes256cli version {{version}}"
	git -C "$tap" push origin HEAD:main

hash:
	git rev-parse --short HEAD
