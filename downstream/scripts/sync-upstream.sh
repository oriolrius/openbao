#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Merge an upstream OpenBao release into the PKI Manager build and open the pull request.
#
#   downstream/scripts/sync-upstream.sh [vX.Y.Z]   # default: the latest upstream release
#   downstream/scripts/sync-upstream.sh --continue # after you fix a conflict or GO_IMAGE
#
# Steps: sync `main` with upstream, make branch sync/<tag> from origin/pki-manager, merge the
# tag, set OPENBAO_VERSION in the image Dockerfile, check that GO_IMAGE has the Go version of
# .go-version, push, open the pull request to pki-manager. It stops when you must do a step by
# hand, and tells you which one. Run it with your own GitHub account (gh), so the pull request
# starts all the checks. Procedure: downstream/README.md#how-the-build-follows-upstream
set -euo pipefail

REPO=${REPO:-oriolrius/openbao}
UPSTREAM_URL=https://github.com/openbao/openbao.git
DOCKERFILE=downstream/pki-manager/image/Dockerfile

die() { echo "sync-upstream: $*" >&2; exit 1; }
cd "$(git rev-parse --show-toplevel)"

if [ "${1:-}" = --continue ]; then
  branch=$(git branch --show-current)
  [[ "$branch" =~ ^sync/(v[0-9]+\.[0-9]+\.[0-9]+)$ ]] || die "not on a sync/<tag> branch"
  tag=${BASH_REMATCH[1]}
  [ ! -f "$(git rev-parse --git-path MERGE_HEAD)" ] || die "finish the merge first: fix the files, git add, git commit --no-edit"
  git merge-base --is-ancestor "$tag" HEAD || die "$tag is not merged in $branch"
else
  tag=${1:-$(gh api repos/openbao/openbao/releases/latest --jq .tag_name)}
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unexpected tag '$tag'"
  [ -z "$(git status --porcelain)" ] || die "the working tree is not clean"
  git fetch -q origin "+refs/heads/pki-manager:refs/remotes/origin/pki-manager"
  git fetch -q --no-tags "$UPSTREAM_URL" "+refs/tags/$tag:refs/tags/$tag"
  if git merge-base --is-ancestor "$tag" origin/pki-manager; then
    echo "$tag is already in pki-manager. Nothing to do."; exit 0
  fi
  branch=sync/$tag
  git show-ref -q --verify "refs/heads/$branch" && die "branch $branch exists: switch to it and use --continue, or delete it"

  echo "== sync main of $REPO with upstream"
  gh repo sync "$REPO" -b main

  echo "== merge $tag into $branch"
  git switch -q -c "$branch" origin/pki-manager
  if ! git merge --no-ff --no-edit -m "Merge upstream OpenBao $tag into pki-manager" "$tag"; then
    echo
    echo "Conflicts:"; git diff --name-only --diff-filter=U | sed 's/^/  /'
    echo
    echo "Fix them (keep the upstream change and put the downstream one back), then:"
    echo "  git add <files> && git commit --no-edit && $0 --continue"
    exit 3
  fi
fi

version=${tag#v}
old=$(git show "origin/pki-manager:$DOCKERFILE" | sed -n 's/^ARG OPENBAO_VERSION=//p' | head -1)
if [ "$(sed -n 's/^ARG OPENBAO_VERSION=//p' "$DOCKERFILE" | head -1)" != "$version" ]; then
  sed -i "s/^ARG OPENBAO_VERSION=.*/ARG OPENBAO_VERSION=$version/" "$DOCKERFILE"
  git commit -q -m "build: OpenBao $version in the image build" -- "$DOCKERFILE"
  echo "== OPENBAO_VERSION $old -> $version"
fi

go=$(cat .go-version)
img_go=$(sed -n 's/^ARG GO_IMAGE=golang:\([0-9.]*\)-.*/\1/p' "$DOCKERFILE")
if [ "$go" != "$img_go" ]; then
  echo
  echo ".go-version is $go, GO_IMAGE in $DOCKERFILE is Go $img_go. Set GO_IMAGE to golang:$go-alpine<x>@sha256:<digest>"
  echo "(docker buildx imagetools inspect golang:$go-alpine<x>), commit it, then: $0 --continue"
  exit 4
fi

echo "== push $branch and open the pull request"
git push -q -u origin "$branch"
stale=$(git grep -l -F "$old" -- downstream DOWNSTREAM-LICENSING.md README.md ':!downstream/scripts' || true)
body=$(mktemp)
{
  echo "Merges upstream [OpenBao $tag](https://github.com/openbao/openbao/releases/tag/$tag) into the PKI Manager build."
  echo
  echo "- [ ] All checks pass (upstream tests and \`PKI Manager image\`)"
  echo "- [ ] The downstream features still work: \`downstream/README.md#features\`"
  echo "- [ ] The version text is updated (old version $old). Files that name it:"
  printf '%s\n' "$stale" | sed '/^$/d; s/^/  - `/; s/$/`/'
  echo "- [ ] After the merge: tag \`$tag-pki-manager.1\` on pki-manager, then the release notes"
} > "$body"
gh pr create --repo "$REPO" --base pki-manager --head "$branch" \
  --title "Merge upstream OpenBao $tag" --body-file "$body"
rm -f "$body"
