{
  description = "A Nix-flake based Project development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, ...}: let
    system = "x86_64-linux";
  in {
    devShells."${system}".default = let
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
        # make unstable packages available via overlay
        overlays = [
        (final: prev: {
          unstable = import nixpkgs-unstable {
            system = prev.system;
            # Hashicorp vault has an unfree license, thus must configure this to isntall it
            config.allowUnfree = true;
          };
          })
        ];
      };
    in pkgs.mkShell {
      packages = with pkgs; [
        git
        python3
        capnproto
        poetry
        mosquitto
        unstable.vault
      ];

      shellHook = ''
        `${pkgs.poetry}/bin/poetry install`
        `${pkgs.poetry}/bin/poetry run python3`
      '';
    };
  };
}
