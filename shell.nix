let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-23.11";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

with pkgs; mkShell {
  packages = [
    git
    # (python3.withPackages (python-pkgs: with python-pkgs; [
    #   dissononce
    #   transitions
    #   cryptography
    #   pycapnp
    #   python-dotenv
    #   aiomqtt
    #   hvac
    # ]))
    neovim
    capnproto
    poetry
    vault
  ];
}
