# Routekit

This project adopts engineering-standard 1.0.0 at
09f93fd9415b0ddeaec8843273cbaf3d8772c603. Read README.md and the affected files.
Keep upstream attribution and licenses. Customizations cover the declared routes,
their TUN exclusions, update URL, exact duplicate removal and the curated domain
supplement declared in update.py. Preserve the original rule order and rejection
policies. Never add credentials,
proxy subscriptions, certificates or Tailscale authentication keys.

`python3 -m unittest -v` and `python3 update.py` are offline checks.
`python3 update.py --update` downloads the upstream revision and regenerates the
profile; it does not publish. Validate before pushing. GitHub Actions owns daily
updates. A generated configuration passing checks is not phone-side acceptance.
