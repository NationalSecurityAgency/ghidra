#!/bin/bash
#
# Author: Coleman Kane <ckane@colemankane.org>
#
# Script that follows the "DevGuide" instructions to install and deploy necessary
# build dependencies.
# Derived from: https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md
#
# There were a lot of steps, so I just scripted it. Once the script is complete, you should
# be able to run "gradle buildGhidra"
#
# Tested with gradle 5.6.4 and 6.2.2
#

if `which gradle > /dev/null` && `which eclipse > /dev/null`; then
  echo "Found gradle and eclipse!"
else
  if `which lsb_release > /dev/null`; then
    if lsb_release -i | grep -i ubuntu > /dev/null; then
      sudo snap install --classic eclipse
      sudo add-apt-repository -y ppa:cwchien/gradle
      sudo apt install gradle-ppa
    fi
    # TODO: I just use Ubuntu, but feel free to add more variations here
  else
    echo "You will need to manually install eclipse and gradle"
    exit 1
  fi
fi

# Create flatRepo
mkdir flatRepo
cd flatRepo/

# Deploy dex2jar
curl -OL https://bitbucket.org/pxb1988/dex2jar/downloads/dex2jar-2.0.zip
unzip ~/Downloads/dex2jar-2.0.zip
mv dex2jar-2.0/lib/*.jar .
rm -rf dex2jar-2.0/

# Deploy AXMLPrinter2
curl -OL https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/android4me/AXMLPrinter2.jar

# Deploy hfsx
mkdir hfsx
cd hfsx/
curl -OL https://sourceforge.net/projects/catacombae/files/HFSExplorer/0.21/hfsexplorer-0_21-bin.zip
unzip hfsexplorer-0_21-bin.zip
cd lib/
cp csframework.jar hfsx_dmglib.jar hfsx.jar iharder-base64.jar ../../
cd ../../
rm -rf hfsx

# Return to base ghidra project folder
cd ..

# Create build dirs
mkdir -p Ghidra/Features/GhidraServer/build/
mkdir -p GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/

cd Ghidra/Features/GhidraServer/build/

# Deploy yajsw
curl -OL https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/yajsw-stable-12.12.zip

cd ../../../../GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/
# Deploy CDT
curl -OL 'http://www.eclipse.org/downloads/download.php?r=1&protocol=https&file=/tools/cdt/releases/8.6/cdt-8.6.0.zip'

# Deploy PyDev
curl -L -o 'PyDev 6.3.1.zip' https://sourceforge.net/projects/pydev/files/pydev/PyDev%206.3.1/PyDev%206.3.1.zip

