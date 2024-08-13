# unbound-rust-mod

This is a library for writing Unbound modules in Rust. See
[`example`](./example) for an example module.

Most of Unbound's features don't have safe bindings, so you might have
to write some yourself - in that case, PRs are appreciated.

To regenerate the bindings, there's a small problem - you actually
need to run Unbound's configure script for that. That's why I provide a
Nix file to generate them (running `nix build .#bindings` in project
root will produce the bindings at the `result` symlink). Alternatively,
you may call rust-bindgen manually.
