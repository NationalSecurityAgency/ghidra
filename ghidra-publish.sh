#!/usr/bin/env bash
set -e #stop on error
set -o pipefail

# this script downloads a ghidra release from ghidra-sre and publishes it to
# sonatype, so that we can promote it to maven central:
# https://repo1.maven.org/maven2/io/shiftleft/ghidra/
# see also https://github.com/NationalSecurityAgency/ghidra/issues/799
VERSION=9.2_PUBLIC_20201113
SONATYPE_URL=https://oss.sonatype.org/service/local/staging/deploy/maven2/
# the server id from your local ~/.m2/settings.xml
REPO_ID=sonatype-nexus-staging

echo "download and unzip ghidra distribution"
wget https://ghidra-sre.org/ghidra_${VERSION}.zip
unzip ghidra_$VERSION.zip
rm ghidra_$VERSION.zip
cd ghidra_9.2_PUBLIC
support/buildGhidraJar

# install into local maven repo, mostly to generate a pom
mvn install:install-file -DgroupId=io.shiftleft -DartifactId=ghidra -Dpackaging=jar -Dversion=$VERSION -Dfile=ghidra.jar -DgeneratePom=true
cp ~/.m2/repository/io/shiftleft/ghidra/$VERSION/ghidra-$VERSION.pom pom.xml

# add pom-extra to pom.xml, to make sonatype happy
head -n -1 pom.xml > pom.tmp
cat pom.tmp ../pom-extra > pom.xml
rm pom.tmp

# create empty jar for "sources" - just to make sonatype happy
zip empty.jar LICENSE

# sign and upload artifacts to sonatype staging
mvn gpg:sign-and-deploy-file -Durl=$SONATYPE_URL -DrepositoryId=$REPO_ID -DpomFile=pom.xml -Dfile=ghidra.jar
mvn gpg:sign-and-deploy-file -Durl=$SONATYPE_URL -DrepositoryId=$REPO_ID -DpomFile=pom.xml -Dclassifier=javadoc -Dfile=docs/GhidraAPI_javadoc.zip
mvn gpg:sign-and-deploy-file -Durl=$SONATYPE_URL -DrepositoryId=$REPO_ID -DpomFile=pom.xml -Dclassifier=sources -Dfile=empty.jar

echo "artifacts are now published to sonatype staging. next step: log into https://oss.sonatype.org -> staging repos -> find the right one -> close -> promote"
