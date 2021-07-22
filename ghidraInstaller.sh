#!/bin/bash

# Downloading with the custom version...

if [ $0 == -c ]
then
  if [ -z "$1"]
  then
  echo "Please enter the download link of the zip file for the desired version of Ghidra"
  read url
  mkdir Ghidra
  cd Ghidra
  wget \"$url\"
  unzip ghidra_10.0.1_PUBLIC_20210708.zip
  cd ghidra_10.0.1
  sudo apt-get update
  sudo add-apt-repository ppa:openjdk-r/ppa
  sudo apt install openjdk-11-jdk
  sudo apt install openjdk-11-jre-headless
  chmod +x ghidraRun
./ghidraRun
  fi
fi

if [ -z "$0"]
then
# Downloading with the latest version...
echo "Downloading with the latest version" # This would need to be updated everytime a new version is released
echo

mkdir Ghidra
cd Ghidra
wget https://ghidra-sre.org/ghidra_10.0.1_PUBLIC_20210708.zip
unzip ghidra_10.0.1_PUBLIC_20210708.zip
cd ghidra_10.0.1
sudo add-apt-repository ppa:openjdk-r/ppa
sudo apt update
sudo apt install openjdk-11-jdk
sudo apt install openjdk-11-jre-headless
chmod +x ghidraRun

echo 
echo "Do you want to launch Ghidra now(y/n):"
read input
if [ $input == "y"]
   then
./ghidraRun
else
   exit 1
   fi

fi
