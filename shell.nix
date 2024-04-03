let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-23.11";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

with pkgs; mkShell {
  packages = [
    git
    neovim
    capnproto
    poetry
    vault
  ];
}
