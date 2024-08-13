{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:chayleaf/nixpkgs/unbound";
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, crane }: let
    gen = func: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system: func (import nixpkgs { inherit system; }));
  in {

    packages = gen (pkgs: rec {
      bindings = pkgs.unbound-full.overrideAttrs (old: {
        name = "unbound-dynmod-bindings.rs";
        nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.rust-bindgen pkgs.rustfmt ];
        phases = ["unpackPhase" "patchPhase" "configurePhase" "installPhase"];
        outputs = [ "out" ];
        installPhase = ''
          cp ${./dummy.h} ./dummy.h
          opts=()
          for file in **/*.h; do
            opts+=(--allowlist-file "$PWD/$file")
          done

          bindgen --no-layout-tests "''${opts[@]}" dummy.h -- -I "$PWD" > "$out"
        '';
      });
      unbound-mod = let
        craneLib = crane.mkLib pkgs;
        inherit (nixpkgs) lib;
      in craneLib.buildPackage {
        pname = "unbound-mod";
        version = "0.1.0";
        cargoExtraArgs = "--package example";
        postPatch = ''
          ls -la
          cp ${bindings} unbound-mod/src/bindings.rs
        '';
        src = nixpkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type: lib.hasSuffix ".h" path || craneLib.filterCargoSources path type;
        };
        postInstall = ''
          mv $out/lib/libexample.so $out/lib/libunbound_mod.so
        '';
        doCheck = false;
        LIBMNL_LIB_DIR = "${nixpkgs.lib.getLib pkgs.libmnl}/lib";
        LIBNFTNL_LIB_DIR = "${nixpkgs.lib.getLib pkgs.libnftnl}/lib";
      };
      default = unbound-mod;
    });

    devShells = gen (pkgs: {
      default = pkgs.mkShell rec {
        name = "unbound-rust-mod-shell";
        nativeBuildInputs = [
          # pkgs.rustc pkgs.cargo
          pkgs.nftables
        ];
        LIBMNL_LIB_DIR = "${nixpkgs.lib.getLib pkgs.libmnl}/lib";
        LIBNFTNL_LIB_DIR = "${nixpkgs.lib.getLib pkgs.libnftnl}/lib";
        LD_LIBRARY_PATH = "${LIBMNL_LIB_DIR}:${LIBNFTNL_LIB_DIR}";
      };
    });
  };
}
