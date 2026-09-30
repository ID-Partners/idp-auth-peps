# The site: federated-enforcement.idpartners.global

The project's front door, as one nginx image. It serves three things:

| Path | What | From |
| --- | --- | --- |
| `/` | the landing page | `site/public/` |
| `/overview.html` | the one-page overview | `docs/overview.html` |
| `/docs/` | the configuration reference | `docs/reference/` |

The reference is the same one the demo serves at its `/docs/`; this is its permanent
home. The landing page is written by hand in `public/index.html` with `public/site.css`,
which shares the reference site's tokens so the two read as one. There is no build step
and no script on any page.

## Build and run

From the repository root:

```sh
docker build -f site/Dockerfile -t federated-enforcement .
docker run --rm -p 8080:8080 federated-enforcement
scripts/site-check.sh http://localhost:8080   # every page, every local link, the headers
```

The image is `nginxinc/nginx-unprivileged`, pinned by digest (Dependabot moves it). It
listens on `$PORT`, which Railway sets and which defaults to 8080; the entrypoint
substitutes it into `nginx/default.conf.template` and touches nothing else there. The
config sets a scripts-off Content Security Policy, `no-cache` on pages so a deploy shows
at once, a day's cache on styles and images, `/healthz` for the platform, and the 404
page for anything else.

## Hosting

Railway, in the same project as the demo (`idp-auth-peps-demo`), as a second service,
`site`, built from this Dockerfile on every push to `main`, with the custom domain
`federated-enforcement.idpartners.global` on it. The zone is on Cloudflare: the domain
needs the CNAME and the TXT record Railway shows, and, if the record is proxied,
Cloudflare's SSL/TLS mode set to Full (not Full strict).

## The social preview

`og/og.html` is the 1200x630 card behind `public/img/og.png`. Render it again after
changing it, from this directory, with headless Chrome:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu \
  --hide-scrollbars --window-size=1200,630 --screenshot="$PWD/public/img/og.png" "file://$PWD/og/og.html"
```

## Versions in the page

The install lines on the landing page name a version (`coaz-pep:0.4.1`,
`kong-plugin-authzen-pdp-0.4.1-1.all.rock`). `scripts/release.sh bump` moves them with
every other document, and `scripts/check-versions.sh` holds them to the release; do not
edit them by hand.
