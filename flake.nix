{
  description = "A Nix-flake based Project development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
  };

  outputs = { self, nixpkgs, ...}: let
    system = "x86_64-linux";
  in {
    devShells."${system}".default = let
      pkgs = import nixpkgs {
        inherit system;
      };
    in pkgs.mkShell {
      packages = with pkgs; [
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
    };
  };
}
