#!/usr/bin/env bash
# Cutting a release, the same way every time. Every component moves to a version
# together; a candidate is tagged and released first; the final tag goes on the commit
# that candidate proved. The tags run .github/workflows/release.yml.
#
#   scripts/release.sh bump X.Y.Z [git commit options]
#       Every component to X.Y.Z, the CHANGELOG's "## [Unreleased]" dated as X.Y.Z, and
#       one commit, not pushed.
#   scripts/release.sh rc [--dry-run] [--wait]
#       Tag the next vX.Y.Z-rcN on main - X.Y.Z being what the components say - and push
#       it. A candidate runs every release job and publishes nothing final.
#   scripts/release.sh final [--dry-run] [--wait]
#       Tag vX.Y.Z and push it: only on the commit its latest candidate was cut from, once
#       that candidate's release run has passed, and with the image public. The SDK goes
#       to npm too while the repository variable NPM_PUBLISH is "true".
#   scripts/release.sh npm vX.Y.Z [--dry-run] [--wait]
#       Publish a released version's Node SDK to npm, when npm was off at release time.
#
# --dry-run runs every check and changes nothing. --wait follows the run it starts and
# fails unless it passes.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "release: $*" >&2; exit 1; }

# What the components say now. scripts/check-versions.sh holds every one of them to it.
current() { sed -n 's/^  "version": "\([^"]*\)",$/\1/p' sdk/node/package.json | head -1; }

consistent() { scripts/check-versions.sh "$1" >&2 || die "the components do not all say $1"; }

owner() { git remote get-url origin | sed -E 's#^.*github\.com[:/]([^/]+)/.*$#\1#' | tr '[:upper:]' '[:lower:]'; }

bump() {
  local new=${1:-} old today
  [ -n "$new" ] || die "usage: scripts/release.sh bump X.Y.Z [git commit options]"
  shift
  [[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "a version is X.Y.Z, not $new"
  old=$(current)
  [ "$new" != "$old" ] || die "every component already says $new"
  [ -z "$(git status --porcelain)" ] || die "the working tree has changes: commit or stash them first"
  grep -q '^## \[Unreleased\]' CHANGELOG.md || grep -qF "## [$new]" CHANGELOG.md \
    || die "CHANGELOG.md has no '## [Unreleased]' section: write what changed there first"
  consistent "$old"

  for p in authzen-pdp sideband-pdp; do
    git mv "gateways/kong/$p/kong-plugin-$p-$old-1.rockspec" "gateways/kong/$p/kong-plugin-$p-$new-1.rockspec"
  done
  # The version where it is the version. Upgrade notes and history keep theirs, and so do
  # the CHANGELOG and the workflows' examples.
  git grep -l -z -F "$old" -- . ':!CHANGELOG.md' ':!.github' ':!sdk/node/package.json' ':!sdk/node/package-lock.json' \
    | OLD=$old NEW=$new xargs -0 perl -pi -e '
        BEGIN { $o = quotemeta $ENV{OLD}; $n = $ENV{NEW} }
        s/^version = "$o-1"$/version = "$n-1"/;
        s/^(  tag = )"v$o",$/$1"v$n",/;
        s/"kong-plugin-authzen-pdp == $o"/"kong-plugin-authzen-pdp == $n"/;
        s/((?:S\.)?VERSION = )"$o"/$1"$n"/;
        s/(SDK_VERSION = )\x27$o\x27/$1\x27$n\x27/;
        s/kong-plugin-(authzen|sideband)-pdp-$o-1/kong-plugin-$1-pdp-$n-1/g;
        s/coaz-pep:$o(?![\w-]|\.\d)/coaz-pep:$n/g;
        s/VERSION=$o(?![\w-]|\.\d)/VERSION=$n/g;
        s/\bVersion $o(?=;)/Version $n/g;
        s/"coaz-pep $o"/"coaz-pep $n"/g;
        s/(`|<code>)v$o(`|<\/code>)/$1v$n$2/g;
        s/((?:`|<code>)kong-plugin-authzen-pdp(?:`|<\/code>)) $o(?![\w-]|\.\d)/$1 $n/g;
      '
  # The pom's first <version> is the project's own.
  OLD=$old NEW=$new perl -0pi -e 'BEGIN { $o = quotemeta $ENV{OLD} } s/<version>$o<\/version>/<version>$ENV{NEW}<\/version>/' \
    gateways/pingaccess/authzen-pdp/pom.xml
  (cd sdk/node && npm version "$new" --no-git-tag-version --ignore-scripts >/dev/null)
  today=$(date +%F)
  NEW=$new TODAY=$today perl -pi -e 's/^## \[Unreleased\].*$/## [$ENV{NEW}] - $ENV{TODAY}/' CHANGELOG.md

  consistent "$new"
  git add -A
  git commit -q -m "release: $new" "$@"
  echo "every component says $new: $(git log -1 --format='%h %s')"
  echo "these still say $old - upgrade notes and history, which keep theirs:"
  git grep -n -F "$old" -- . ':!CHANGELOG.md' ':!.github' | cut -c1-140 | sed 's/^/  /' || true
  echo "next: push main, then scripts/release.sh rc"
}

preflight() {
  [ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "releases are cut from main"
  [ -z "$(git status --porcelain)" ] || die "the working tree has changes"
  git fetch -q origin main
  [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
    || die "main here is not main on origin: push it (or pull) first"
}

# The candidate numbers origin holds for version $1, ascending.
candidates() {
  git ls-remote --tags origin "refs/tags/v$1-rc*" | sed -n "s|^.*refs/tags/v$1-rc\([0-9][0-9]*\)$|\1|p" | sort -n
}

released() { git ls-remote --exit-code --tags origin "refs/tags/v$1" >/dev/null 2>&1; }

# Anyone can pull ghcr.io/$1/coaz-pep: an anonymous token that lists its tags.
public() {
  local token
  token=$(curl -fsS "https://ghcr.io/token?scope=repository:$1/coaz-pep:pull" 2>/dev/null \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  [ -n "$token" ] && curl -fsS -o /dev/null -H "Authorization: Bearer $token" "https://ghcr.io/v2/$1/coaz-pep/tags/list"
}

# Follow the release run a tag started, and fail unless it passes.
follow() {
  local tag=$1 id="" conclusion
  for _ in $(seq 1 24); do
    id=$(gh run list --workflow Release --branch "$tag" --limit 1 --json databaseId --jq '.[0].databaseId // empty')
    [ -n "$id" ] && break
    sleep 5
  done
  [ -n "$id" ] || die "no release run started for $tag"
  gh run watch "$id" --interval 30 >/dev/null 2>&1 || true
  gh run view "$id" --json jobs --jq '.jobs[] | "  \(.name): \(.conclusion)"'
  conclusion=$(gh run view "$id" --json conclusion --jq .conclusion)
  [ "$conclusion" = success ] || die "the release run for $tag ended '$conclusion': $(gh run view "$id" --json url --jq .url)"
  echo "$tag released: $(gh release view "$tag" --json url --jq .url)"
}

tag_and_push() {
  local tag=$1 message=$2 dry=$3 wait=$4
  if [ "$dry" = 1 ]; then
    echo "would tag $tag on $(git rev-parse --short HEAD) and push it"
    return 0
  fi
  git tag -a "$tag" -m "$message"
  git push -q origin "$tag"
  echo "tagged $tag on $(git rev-parse --short HEAD) and pushed it"
  if [ "$wait" = 1 ]; then follow "$tag"; fi
}

rc() {
  local dry=$1 wait=$2 v n
  preflight
  v=$(current)
  consistent "$v"
  ! released "$v" || die "v$v is already released: bump to the next version first"
  n=$(candidates "$v" | tail -1)
  n=$(( ${n:-0} + 1 ))
  tag_and_push "v$v-rc$n" "$v release candidate $n" "$dry" "$wait"
}

final() {
  local dry=$1 wait=$2 v n rc conclusion o
  preflight
  v=$(current)
  consistent "$v"
  ! released "$v" || die "v$v is already released"
  n=$(candidates "$v" | tail -1)
  [ -n "$n" ] || die "no candidate for $v yet: scripts/release.sh rc"
  rc="v$v-rc$n"
  git fetch -q origin "refs/tags/$rc:refs/tags/$rc"
  [ "$(git rev-parse "$rc^{commit}")" = "$(git rev-parse HEAD)" ] \
    || die "$rc was cut from $(git rev-parse --short "$rc^{commit}"), not from this commit: cut a candidate of this one first"
  conclusion=$(gh run list --workflow Release --branch "$rc" --limit 1 --json conclusion --jq '.[0].conclusion // "missing"')
  [ "$conclusion" = success ] || die "$rc's release run is '$conclusion', not a pass"
  if [ "$(gh variable get NPM_PUBLISH 2>/dev/null)" = true ]; then
    gh secret list --json name --jq '.[].name' | grep -qx NPM_TOKEN \
      || echo "release: NPM_PUBLISH is on and there is no NPM_TOKEN: unless npm trusted publishing is set up for this workflow, the npm job fails" >&2
    echo "npm: on - the Node SDK goes to npm with v$v"
  else
    echo "npm: off (NPM_PUBLISH is not \"true\") - the SDK is attached to the release; scripts/release.sh npm v$v publishes it later"
  fi
  o=$(owner)
  public "$o" \
    || die "ghcr.io/$o/coaz-pep is private, so nobody could pull the release's image: https://github.com/orgs/$o/packages/container/coaz-pep/settings"
  tag_and_push "v$v" "$v" "$dry" "$wait"
}

# Publish a released version's Node SDK to npm, by hand: the release workflow, run with
# the tag, builds and tests that tag's SDK and publishes it with provenance.
to_npm() {
  local tag=$1 dry=$2 wait=$3 v since id=""
  [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "npm takes a released version's tag, vX.Y.Z, not '$tag'"
  v=${tag#v}
  released "$v" || die "$tag is not released"
  if npm view "@id-partners/authzen-pep@$v" version >/dev/null 2>&1; then
    die "@id-partners/authzen-pep@$v is already on npm"
  fi
  if [ "$dry" = 1 ]; then
    echo "would publish $tag's Node SDK to npm"
    return 0
  fi
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  gh workflow run release.yml -f tag="$tag"
  echo "started the npm publish of $tag"
  [ "$wait" = 1 ] || return 0
  for _ in $(seq 1 24); do
    id=$(gh run list --workflow Release --event workflow_dispatch --limit 5 --json databaseId,createdAt \
      --jq "[.[] | select(.createdAt >= \"$since\")] | .[0].databaseId // empty")
    [ -n "$id" ] && break
    sleep 5
  done
  [ -n "$id" ] || die "no npm publish run started for $tag"
  gh run watch "$id" --interval 30 >/dev/null 2>&1 || true
  [ "$(gh run view "$id" --json conclusion --jq .conclusion)" = success ] \
    || die "the npm publish of $tag did not pass: $(gh run view "$id" --json url --jq .url)"
  echo "@id-partners/authzen-pep@$v is on npm"
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case "$cmd" in
  bump) bump "$@" ;;
  npm)
    tag=""
    dry=0
    wait=0
    for a in "$@"; do
      case "$a" in
        --dry-run) dry=1 ;;
        --wait) wait=1 ;;
        -*) die "unknown option $a" ;;
        *) tag=$a ;;
      esac
    done
    to_npm "$tag" "$dry" "$wait"
    ;;
  rc | final)
    dry=0
    wait=0
    for a in "$@"; do
      case "$a" in
        --dry-run) dry=1 ;;
        --wait) wait=1 ;;
        *) die "unknown option $a" ;;
      esac
    done
    "$cmd" "$dry" "$wait"
    ;;
  *)
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
    exit 2
    ;;
esac
