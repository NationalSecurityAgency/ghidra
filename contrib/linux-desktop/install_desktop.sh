#!/usr/bin/bash
# Desc: customise and install a Ghidra desktop file
# Author: m3gat0nn4ge <m3gat0nn4ge@gmail.com>
# License: Apache License 2.0

function usage {
  cat <<EOH
Usage: $0 [</path/to/ghidra>]

If the path to ghidra is not provided it will be located automatically
EOH
}

if [[ $# -gt 1 ]]
then
  usage
  exit 1
elif [[ $# -eq 1 ]]
then
  # ghidra location provided
  ghidra_path=${1}
  ghidra_exec=${1}/ghidraRun
  ghidra_icon=${1}/docs/GhidraClass/Beginner/Images/GhidraLogo64.png
else
  # locate ghidra
  ghidra=$(which ghidraRun > /dev/null 2>&1)
  if [[ -n "${ghidra}" ]]
  then
    echo "[*] found ghidra in your PATH"
    ghidra_path=$(dirname "${ghidra}")
    ghidra_exec=ghidraRun
    ghidra_icon=${ghidra_path}/docs/GhidraClass/Beginner/Images/GhidraLogo64.png
  else
    echo "[*] Searching for ghidra..."
    ghidra_paths=($(dirname $(find / -name ghidraRun 2>/dev/null)))
    if [[ ${#ghidra_paths[@]} -eq 0 ]]
    then
      echo "[!] could not locate ghidraRun"
      exit 1
    elif [[ ${#ghidra_paths[@]} -gt 1 ]]
    then
      echo "[!] found multiple ghidra installations, please pass one as an argument"
      for path in "${ghidra_paths[@]}"
      do
        echo "${path}" 
      done
      exit 1
    else
      echo "[*] found ghidra at: ${ghidra_paths[0]}"
      ghidra_path=${ghidra_paths[0]}
      ghidra_exec=${ghidra_paths[0]}/ghidraRun
      ghidra_icon=${ghidra_path}/docs/GhidraClass/Beginner/Images/GhidraLogo64.png
    fi
  fi
fi

# validate vars
if [[ ! -x ${ghidra_exec} ]]
then
  echo "[!] ${ghidra_exec} is not executable"
  exit 1
fi

if [[ ! -d ${ghidra_path} ]]
then
  echo "[!] ${ghidra_path} is not a directory"
  exit 1
fi

# update desktop file
echo "[*] updating desktop file"
desktop_file=$(dirname "${0}")/ghidra.desktop
sed -i "s|^Exec=.*|Exec=$ghidra_exec|" "${desktop_file}"
sed -i "s|^Icon=.*|Icon=$ghidra_icon|" "${desktop_file}"

# copy desktop file
echo "[*] placing desktop file for current user"
mkdir -p ~/.local/share/applications/
cp "${desktop_file}" ~/.local/share/applications/

echo "[*] install complete, please verify desktop file works as expected"

