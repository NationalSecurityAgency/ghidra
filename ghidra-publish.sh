#!/usr/bin/env bash

set -e #stop on error
set -o pipefail

# this script downloads a ghidra release from ghidra-sre and publishes it to
# sonatype, so that we can promote it to maven central:
# https://repo1.maven.org/maven2/io/joern/ghidra/
# see also https://github.com/NationalSecurityAgency/ghidra/issues/799

VERSION=11.2.1_PUBLIC_20241105
VERSION_SHORTER=11.2.1
VERSION_SHORT=${VERSION_SHORTER}_PUBLIC
CUSTOM_RELEASE_VERSION=${VERSION}-2

SONATYPE_URL=https://central.sonatype.com/service/local/staging/deploy/maven2/
# the server id from your local ~/.m2/settings.xml
REPO_ID=sonatype-nexus-staging-joern

DISTRO_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${VERSION_SHORTER}_build/ghidra_${VERSION}.zip
echo "download and unzip ghidra distribution from $DISTRO_URL"
wget $DISTRO_URL
unzip ghidra_$VERSION.zip
rm ghidra_$VERSION.zip
cd ghidra_${VERSION_SHORT}
support/buildGhidraJar

# create custom-made maven build just for deploying to maven central
mkdir -p build/src/main/resources
sed s/__VERSION__/$CUSTOM_RELEASE_VERSION/ ../pom.xml.template > build/pom.xml
unzip -d build/src/main/resources ghidra.jar

# add classes from ByteViewer.jar - those are looked up at runtime via reflection
# context: lookup happens transitively by loading classes from _Root/Ghidra/EXTENSION_POINT_CLASSES
# unzip flag `-o` to override and update files without prompting the user
unzip -o -d build/src/main/resources Ghidra/Features/ByteViewer/lib/ByteViewer.jar


# deploy to sonatype central
pushd build
  mvn deploy
popd

echo "release is now published to sonatype central. next step: log into https://central.sonatype.com/publishing/deployments and publish it to maven central"
echo "once it's synchronised to maven central (https://repo1.maven.org/maven2/io/joern/ghidra/), update the ghidra version in 'joern/project/Versions.scala' to $CUSTOM_RELEASE_VERSION"
echo "don't forget to commit and push the local changes in this repo to https://github.com/joernio/ghidra"
