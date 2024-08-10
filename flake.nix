{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:chayleaf/nixpkgs/unbound";
  };

  outputs = { self, nixpkgs }: {

    packages.x86_64-linux.bindings = let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
    in pkgs.unbound-full.overrideAttrs (old: {
      name = "unbound-dynmod-bindings.rs";
      nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.rust-bindgen pkgs.rustfmt ];
      phases = ["unpackPhase" "patchPhase" "configurePhase" "installPhase"];
      outputs = [ "out" ];
      installPhase = ''
        cp ${./dummy.h} ./dummy.h
        bindgen ./dummy.h -- -I $PWD > $out
      '';
    });

    devShells.x86_64-linux.default =  let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
    in pkgs.mkShell rec {
      name = "unbound-rust-mod-shell";
      LIBMNL_LIB_DIR = "${nixpkgs.lib.getLib pkgs.libmnl}/lib";
      LIBNFTNL_LIB_DIR = "${nixpkgs.lib.getLib (pkgs.libnftnl.overrideAttrs (old: {
        patches = (old.patches or []) ++ [ ./libnftnl-fix.patch ];
      }))}/lib";
      LD_LIBRARY_PATH = "${LIBMNL_LIB_DIR}:${LIBNFTNL_LIB_DIR}";
    };
  };
}
