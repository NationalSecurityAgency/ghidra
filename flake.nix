{
  description = "Nix flake for building and running Ghidra from this repository";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
        jdk = pkgs.jdk21;
        python = pkgs.python3.withPackages (ps: [ ps.pip ]);
        ghidraLocal = pkgs.writeShellApplication {
          name = "ghidra-local";
          runtimeInputs = with pkgs; [
            jdk
            gradle
            python
            gnumake
            gcc
            unzip
            zip
            coreutils
            gnused
          ];
          text = ''
            set -euo pipefail
            shopt -s nullglob

            repo="''${GHIDRA_REPO:-$PWD}"
            if [ ! -f "$repo/settings.gradle" ] || [ ! -f "$repo/build.gradle" ]; then
              echo "Not a Ghidra source checkout: $repo" >&2
              echo "Run from the repo root or set GHIDRA_REPO=/path/to/ghidra" >&2
              exit 1
            fi

            export JAVA_HOME="${jdk}"
            export GRADLE_USER_HOME="''${GRADLE_USER_HOME:-$repo/.gradle}"

            cd "$repo"

            if [ ! -d dependencies/flatRepo ]; then
              echo "Fetching non-Maven dependencies..."
              gradle --no-daemon -p "$repo" -I gradle/support/fetchDependencies.gradle help
            fi

            zip_candidates=(build/dist/*.zip)
            if [ "''${#zip_candidates[@]}" -eq 0 ]; then
              echo "Building Ghidra distribution..."
              gradle --no-daemon -p "$repo" buildGhidra
            fi

            zip_candidates=(build/dist/*.zip)
            if [ "''${#zip_candidates[@]}" -eq 0 ]; then
              echo "No zip found in build/dist after buildGhidra." >&2
              exit 1
            fi

            zip_file=""
            for candidate in "''${zip_candidates[@]}"; do
              if [ -z "$zip_file" ] || [ "$candidate" -nt "$zip_file" ]; then
                zip_file="$candidate"
              fi
            done
            run_dir="''${XDG_CACHE_HOME:-$HOME/.cache}/ghidra-flake-run"
            rm -rf "$run_dir"
            mkdir -p "$run_dir"
            unzip -q "$zip_file" -d "$run_dir"
            ghidra_dir="$(echo "$run_dir"/ghidra_*)"

            exec "$ghidra_dir/ghidraRun" "$@"
          '';
        };
        ghidraElectronMigration = pkgs.writeShellApplication {
          name = "ghidra-electron-migration";
          runtimeInputs = with pkgs; [
            jdk
            curl
            nodejs
            electron
            ripgrep
            coreutils
          ];
          text = ''
            set -euo pipefail

            repo="''${GHIDRA_REPO:-$PWD}"
            if [ ! -f "$repo/settings.gradle" ] || [ ! -f "$repo/build.gradle" ]; then
              echo "Not a Ghidra source checkout: $repo" >&2
              echo "Run from the repo root or set GHIDRA_REPO=/path/to/ghidra" >&2
              exit 1
            fi
            if [ ! -d "$repo/experimental/electron-gateway/src/main/java" ] || [ ! -d "$repo/electron" ]; then
              echo "Missing electron migration sources in repo: $repo" >&2
              exit 1
            fi

            export JAVA_HOME="${jdk}"
            export GHIDRA_GATEWAY_URL="''${GHIDRA_GATEWAY_URL:-http://127.0.0.1:8089}"

            classes_dir="$repo/build/electron-gateway-classes"
            rm -rf "$classes_dir"
            mkdir -p "$classes_dir"
            mapfile -t java_files < <(rg --files "$repo/experimental/electron-gateway/src/main/java" -g "*.java")
            if [ "''${#java_files[@]}" -eq 0 ]; then
              echo "No Java gateway sources found." >&2
              exit 1
            fi
            javac -d "$classes_dir" "''${java_files[@]}"

            java -cp "$classes_dir" ghidra.electron.gateway.GatewayServer &
            gateway_pid="$!"

            cleanup() {
              kill "$gateway_pid" >/dev/null 2>&1 || true
            }
            trap cleanup EXIT INT TERM

            for _ in $(seq 1 40); do
              if curl -fsS "$GHIDRA_GATEWAY_URL/api/v1/health" >/dev/null; then
                ready=1
                break
              fi
              sleep 0.25
            done
            if [ "''${ready:-0}" -ne 1 ]; then
              echo "Gateway failed to become healthy at $GHIDRA_GATEWAY_URL" >&2
              exit 1
            fi

            electron "$repo/electron" "$@"
          '';
        };
        ghidraHeadlessElectron = pkgs.writeShellApplication {
          name = "ghidra-headless-electron";
          runtimeInputs = with pkgs; [
            jdk
            gradle
            python
            curl
            electron
            coreutils
          ];
          text = ''
            set -euo pipefail

            repo="''${GHIDRA_REPO:-$PWD}"
            if [ ! -f "$repo/settings.gradle" ] || [ ! -f "$repo/build.gradle" ]; then
              echo "Not a Ghidra source checkout: $repo" >&2
              echo "Run from the repo root or set GHIDRA_REPO=/path/to/ghidra" >&2
              exit 1
            fi
            if [ ! -d "$repo/electron-headless" ] || [ ! -d "$repo/Ghidra/Features/HeadlessElectron" ]; then
              echo "Missing headless electron slice sources in repo: $repo" >&2
              exit 1
            fi

            export JAVA_HOME="${jdk}"
            export GRADLE_USER_HOME="''${GRADLE_USER_HOME:-$repo/.gradle}"
            export GHIDRA_REPO="$repo"
            export GHIDRA_ELECTRON_PORT="''${GHIDRA_ELECTRON_PORT:-8089}"
            export GHIDRA_BACKEND_URL="''${GHIDRA_BACKEND_URL:-http://127.0.0.1:$GHIDRA_ELECTRON_PORT}"
            export GHIDRA_ELECTRON_DATA_DIR="''${GHIDRA_ELECTRON_DATA_DIR:-$repo/.headless-electron-data}"

            cd "$repo"

            if [ ! -d dependencies/flatRepo ]; then
              echo "Fetching non-Maven dependencies..."
              gradle --no-daemon -p "$repo" -I gradle/support/fetchDependencies.gradle help
            fi

            echo "Preparing Ghidra development launch files..."
            gradle --no-daemon -p "$repo" prepDev

            echo "Building HeadlessElectron runtime jar..."
            gradle --no-daemon -p "$repo" :HeadlessElectron:jar

            backend_pid=""
            cleanup() {
              if [ -n "$backend_pid" ]; then
                kill "$backend_pid" >/dev/null 2>&1 || true
              fi
            }
            trap cleanup EXIT INT TERM

            if curl -fsS "$GHIDRA_BACKEND_URL/api/v1/health" >/dev/null 2>&1; then
              echo "Reusing existing headless backend at $GHIDRA_BACKEND_URL..."
            else
              echo "Starting headless backend on $GHIDRA_BACKEND_URL..."
              "$repo/Ghidra/RuntimeScripts/Linux/support/launch.sh" \
                fg jdk Ghidra-Electron-Headless 2G "-Djava.awt.headless=true" \
                ghidra.electron.headless.ElectronHeadlessLaunchable \
                "$GHIDRA_ELECTRON_PORT" \
                "$GHIDRA_ELECTRON_DATA_DIR" \
                "$repo" &
              backend_pid="$!"

              ready=0
              for _ in $(seq 1 240); do
                if curl -fsS "$GHIDRA_BACKEND_URL/api/v1/health" >/dev/null; then
                  ready=1
                  break
                fi
                sleep 0.25
              done
              if [ "$ready" -ne 1 ]; then
                echo "Backend failed to become healthy at $GHIDRA_BACKEND_URL" >&2
                exit 1
              fi
            fi

            electron "$repo/electron-headless" "$@"
          '';
        };
      in
      {
        # This package performs a fully sandboxed, reproducible build of the source tree.
        # It may fail if your Nix environment blocks network access during builds.
        packages.sandboxed = pkgs.stdenv.mkDerivation rec {
          pname = "ghidra-dev";
          version = "12.2-dev";
          src = lib.cleanSource ./.;

          # Ghidra needs Java, Python, and native build tooling.
          nativeBuildInputs = with pkgs; [
            gradle
            makeWrapper
            python3
            gnumake
            gcc
            unzip
            zip
          ];

          buildInputs = [ jdk ];

          dontConfigure = true;
          dontStrip = true;

          # Ghidra's build requires downloading dependencies via fetchDependencies.gradle.
          # If your Nix daemon enforces full sandboxing, run:
          #   nix build --option sandbox false
          # or pre-populate dependencies/ and Gradle caches.
          buildPhase = ''
            runHook preBuild

            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
            export JAVA_HOME="${jdk}"
            export GRADLE_USER_HOME="$TMPDIR/gradle-home"

            gradle --no-daemon -I gradle/support/fetchDependencies.gradle init
            gradle --no-daemon buildGhidra

            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            mkdir -p "$out/opt" "$out/bin"

            zip_file="$(echo build/dist/*.zip)"
            unzip -q "$zip_file" -d "$out/opt"

            ghidra_dir="$(echo "$out"/opt/ghidra_*)"

            makeWrapper "$ghidra_dir/ghidraRun" "$out/bin/ghidra" \
              --set JAVA_HOME "${jdk}" \
              --set GHIDRA_INSTALL_DIR "$ghidra_dir"

            runHook postInstall
          '';

          meta = with lib; {
            description = "Ghidra development build from repository source";
            homepage = "https://github.com/NationalSecurityAgency/ghidra";
            license = licenses.asl20;
            platforms = platforms.linux;
            mainProgram = "ghidra";
          };
        };

        # Default package is an impure local runner that builds from your checkout, then launches.
        packages.default = ghidraLocal;
        packages.electron = ghidraElectronMigration;
        packages.electron-migration = ghidraElectronMigration;
        packages.electron-headless = ghidraHeadlessElectron;
        packages.project-home = ghidraHeadlessElectron;

        apps.default = flake-utils.lib.mkApp {
          drv = ghidraLocal;
          exePath = "/bin/ghidra-local";
        };
        apps.electron = flake-utils.lib.mkApp {
          drv = ghidraElectronMigration;
          exePath = "/bin/ghidra-electron-migration";
        };
        apps.electron-migration = flake-utils.lib.mkApp {
          drv = ghidraElectronMigration;
          exePath = "/bin/ghidra-electron-migration";
        };
        apps.electron-headless = flake-utils.lib.mkApp {
          drv = ghidraHeadlessElectron;
          exePath = "/bin/ghidra-headless-electron";
        };
        apps.project-home = flake-utils.lib.mkApp {
          drv = ghidraHeadlessElectron;
          exePath = "/bin/ghidra-headless-electron";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            jdk
            gradle
            python
            nodejs
            electron
            gnumake
            gcc
            unzip
            zip
            git
          ];

          shellHook = ''
            export JAVA_HOME="${jdk}"
            echo "Ghidra dev shell ready."
            echo "Build: gradle -I gradle/support/fetchDependencies.gradle init && gradle buildGhidra"
          '';
        };
      });
}
