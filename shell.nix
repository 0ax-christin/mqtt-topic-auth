let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-23.11";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

with pkgs; mkShell {
  packages = [
    git
    neovim
    (python3.withPackages (ps: [
      ps.asyncio-mqtt
      ps.paho-mqtt
      ps.cryptography
      ps.dissononce
      ps.python-dotenv
      ps.pycapnp 
    ]))
  ];
}
