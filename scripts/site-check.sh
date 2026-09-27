#!/usr/bin/env bash
# The site, served: every page answers, every local link and image on every page
# resolves, the health check answers, an unknown path is the 404 page, and the security
# headers are on. Run it against a container built from site/Dockerfile:
#
#   docker run -d --name site -p 8080:8080 federated-enforcement
#   scripts/site-check.sh http://localhost:8080
set -euo pipefail

base="${1:?usage: scripts/site-check.sh http://host:port}"
base="${base%/}"
fail=0

# A link that redirects to a page that answers is a link that works.
status() { curl -sL -o /dev/null -w '%{http_code}' "$1"; }
status_here() { curl -s -o /dev/null -w '%{http_code}' "$1"; }

# Wait for the server: the entrypoint renders the template before nginx listens.
for _ in $(seq 1 50); do
  [ "$(status_here "$base/healthz" 2>/dev/null || true)" = 200 ] && break
  sleep 0.2
done
[ "$(status_here "$base/healthz")" = 200 ] || { echo "site-check: $base/healthz is not answering"; exit 1; }

# Every page: the landing page, the 404 page, the overview, and the reference.
pages="/ /404.html /overview.html /docs/"
for p in $(curl -fsS "$base/docs/" | grep -o 'href="[a-z-]*\.html"' | sed 's/href="//;s/"$//' | sort -u); do
  pages="$pages /docs/$p"
done

# Resolve a link against the page it was on: absolute paths as they are, relative ones
# from the page's directory, with ./ and ../ folded.
resolve() {
  local page=$1 link=$2 path prev=""
  case "$link" in
    /*) path=$link ;;
    *)  path="${page%/*}/$link" ;;
  esac
  path=${path%%#*}
  path=${path%%\?*}
  while [ "$path" != "$prev" ]; do
    prev=$path
    path=$(printf '%s' "$path" | sed -E 's#/\./#/#g; s#/[^/]+/\.\./#/#')
  done
  printf '%s' "$path"
}

checked=""
for page in $pages; do
  code=$(status_here "$base$page")
  if [ "$code" != 200 ]; then echo "site-check: $page -> $code"; fail=1; continue; fi
  html=$(curl -fsS "$base$page")
  links=$(printf '%s' "$html" | grep -oE '(href|src|srcset)="[^"]+"' | sed -E 's/^[a-z]+="//;s/"$//' | sort -u)
  for link in $links; do
    case "$link" in
      http://*|https://*|mailto:*|data:*|\#*) continue ;;
    esac
    path=$(resolve "$page" "$link")
    [ -n "$path" ] || continue
    case " $checked " in *" $path "*) continue ;; esac
    checked="$checked $path"
    code=$(status "$base$path")
    if [ "$code" != 200 ]; then echo "site-check: on $page, $link -> $path -> $code"; fail=1; fi
  done
done

# An unknown path is the 404 page, not a 200 or a redirect somewhere odd.
code=$(status_here "$base/no-such-page")
[ "$code" = 404 ] || { echo "site-check: /no-such-page -> $code, wanted 404"; fail=1; }
curl -s "$base/no-such-page" | grep -q "Not found" || { echo "site-check: the 404 page is not the 404 page"; fail=1; }

# A directory redirects to itself with a slash, relatively; the overview's link to its
# neighbour in the repository lands on the reference.
loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$base/docs")
[ "$loc" = "$base/docs/" ] || { echo "site-check: /docs redirects to '$loc', wanted $base/docs/"; fail=1; }
loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$base/reference/index.html")
[ "$loc" = "$base/docs/index.html" ] || { echo "site-check: /reference/index.html redirects to '$loc', wanted $base/docs/index.html"; fail=1; }

# The headers every response carries.
headers=$(curl -sI "$base/")
for h in "Content-Security-Policy" "X-Content-Type-Options: nosniff" "Referrer-Policy" "Cache-Control: no-cache"; do
  printf '%s' "$headers" | grep -qi "^$h" || { echo "site-check: / lacks header $h"; fail=1; }
done
curl -sI "$base/site.css" | grep -qi '^Cache-Control: public' || { echo "site-check: site.css is not cacheable"; fail=1; }

if [ "$fail" = 0 ]; then
  echo "site-check: $(echo "$pages" | wc -w | tr -d ' ') pages and $(echo "$checked" | wc -w | tr -d ' ') linked paths answer at $base"
fi
exit $fail
