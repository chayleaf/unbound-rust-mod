# unbound-rust-mod Example

This is an example module written using unbound-rust-mod. It
automatically populates nft sets using IP and domain info from .json
files. On start, it checks various environment variables, then loads
the .json files. The IPs are added immediately, but the domains are only
added if they're already in the module's cache (stored on the
filesystem) or whenever Unbound sends a response. Additionally, it
optionally supports live editing certain domain sets by sending a
command (that is, a specially formatted DNS request). This could be done
using an HTTP server, but that is a holdover from when this was still a
Python module (which took 100 seconds to load...)
