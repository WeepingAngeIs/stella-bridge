# Status-only bridge validation

Experimental status-only PufferPanel MCP bridge. Not a live deployment or a completed ChatGPT integration.

The transfer script contains the exact reviewed candidate source archive, its README, tests, and integrity hash. It is embedded to test the same package without recompressing or altering it. No real panel credentials, addresses, server IDs, tunnel keys, world data, or private machine paths are included. All test credentials are synthetic.

CI runs the exact candidate installer in a disposable Debian 13 container, then checks service-user ownership, mock-only stdio MCP discovery/status/denial, absent write/log/power tools, and installer refusal cases. No tunnel connection is started. Never run the CI harness on a live machine.

The GitHub workflow has read-only repository permissions and no secrets. Dependencies download from official Debian repositories, PyPI, and a hash-pinned official OpenAI tunnel-client release. The Debian image and Python transitive dependencies are not yet digest/hash locked; this is validation, not a reproducible production release.

`ci/install.sh` is an exact historical installer fixture for validation, not an approved live installation procedure. Its reference to README.txt belongs to the original review package; that private setup document is intentionally not published here. Do not run this fixture on a live host.
