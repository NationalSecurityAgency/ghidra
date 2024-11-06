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
CUSTOM_RELEASE_VERSION=${VERSION}-1

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

# add classes from ByteViewer.jar - those are looked up at runtime via reflection
# context: lookup happens transitively by loading classes from _Root/Ghidra/EXTENSION_POINT_CLASSES
unzip Ghidra/Features/ByteViewer/lib/ByteViewer.jar -d byteviewer
cd byteviewer
zip -r ../ghidra.jar *
cd ..

# hack: remove h2 database from the fat jar - only because we need to use it together with overflowdb which has it's own dependency on a different version of h2... jar hell ftw
# can be removed once joern is migrated to flatgraph
zip ghidra.jar -d '*org/h2/*'

# install into local maven repo, mostly to generate a pom
mvn install:install-file -DgroupId=io.joern -DartifactId=ghidra -Dpackaging=jar -Dversion=$CUSTOM_RELEASE_VERSION -Dfile=ghidra.jar -DgeneratePom=true
cp ~/.m2/repository/io/joern/ghidra/$CUSTOM_RELEASE_VERSION/ghidra-$CUSTOM_RELEASE_VERSION.pom pom.xml

# add pom-extra to pom.xml, to make sonatype happy
head -n -1 pom.xml > pom.tmp
cat pom.tmp ../pom-extra > pom.xml
rm pom.tmp

# create empty jar for "sources" - just to make sonatype happy
zip empty.jar LICENSE

# sign and upload artifacts to sonatype staging
mvn gpg:sign-and-deploy-file -Durl=$SONATYPE_URL -DrepositoryId=$REPO_ID -DpomFile=pom.xml -Dclassifier=sources -Dfile=empty.jar
mvn gpg:sign-and-deploy-file -Durl=$SONATYPE_URL -DrepositoryId=$REPO_ID -DpomFile=pom.xml -Dclassifier=javadoc -Dfile=docs/GhidraAPI_javadoc.zip
mvn gpg:sign-and-deploy-file -Durl=$SONATYPE_URL -DrepositoryId=$REPO_ID -DpomFile=pom.xml -Dfile=ghidra.jar

echo "artifacts are now published to sonatype central. next step: log into https://central.sonatype.com/publishing/deployments and publish it to maven central"
echo "once it's synchronised to maven central (repo1), update the ghidra version in 'joern/joern-cli/frontends/ghidra2cpg/build.sbt'"
echo "don't forget to commit and push the local changes in this repo to https://github.com/joernio/ghidra"
