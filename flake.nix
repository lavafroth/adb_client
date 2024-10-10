{
  description = "devshell for zilch";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            stdenv.cc.cc
            pkg-config
          ];

          LD_LIBRARY_PATH = "${nixpkgs.lib.makeLibraryPath [
            # pkgs.libglvnd
            # pkgs.xorg.libX11
            # pkgs.xorg.libXcursor
            # pkgs.xorg.libXi
            # pkgs.xorg.libXrandr
            # pkgs.libxkbcommon
            pkgs.stdenv.cc.cc.lib
            pkgs.wayland
            pkgs.libusb1
          ]}";
        };
      }
    );
}
