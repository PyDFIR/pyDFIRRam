{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    systems.url = "github:nix-systems/default";
    devenv.url = "github:cachix/devenv";
    fenix.url = "github:nix-community/fenix";
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs =
    { self
    , nixpkgs
    , devenv
    , systems
    , ...
    } @ inputs:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = forEachSystem (system: {
        devenv-up = self.devShells.${system}.default.config.procfileScript;
      });

      devShells =
        forEachSystem
          (system:
            let
              pkgs = nixpkgs.legacyPackages.${system};
            in
            {
              default = devenv.lib.mkShell {
                inherit inputs pkgs;
                modules = [
                  {
                    languages.python = {
                      enable = true;
                      poetry = {
                        enable = true;
                        activate.enable = true;
                      };
                    };

                    # https://devenv.sh/reference/options/
                    packages = with pkgs; [
                      libstdcxx5
                    ];


                    env.LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
                  }
                ];
              };
            });
    };
}
