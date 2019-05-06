# Should permit building Ghidra for GNU/Linux on any arch supported by Fedora and Ghidra
# Install docker on the build host
# Build image with
# $docker build -t ghidrabuild .
# Building the image builds Ghidra. Run the image with,
# $docker run -it --rm ghidrabuild /bin/bash
# then copy the zip file out of the running container in another terminal like
# $docker ps
# note container id
# $sudo docker cp <container_id>:/root/git/ghidra/build/dist/ .
# you can now go back to your first terminal and exit the container
# #exit
# TODO: build GhidraDev eclipse plugin from source
FROM fedora:29
RUN dnf update -y
RUN dnf install -y eclipse-cdt eclipse-pde eclipse-pydev git java-11-openjdk unzip bison flex
RUN curl -OL https://downloads.gradle.org/distributions/gradle-5.0-bin.zip
RUN unzip gradle-5.0-bin.zip -d /opt/
RUN rm -f gradle-5.0-bin.zip
ENV PATH="/opt/gradle-5.0/bin:${PATH}"
RUN update-alternatives --set java java-11-openjdk.`arch`
ADD repos.gradle /root/.gradle/init.d/repos.gradle
WORKDIR /root/flatRepo
RUN curl -OL https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/android4me/AXMLPrinter2.jar
RUN curl -OL https://github.com/pxb1988/dex2jar/releases/download/2.0/dex-tools-2.0.zip
RUN unzip -j dex-tools-2.0.zip dex2jar-2.0/lib/dex-*.jar -d .
RUN curl -OL https://sourceforge.net/projects/catacombae/files/HFSExplorer/0.21/hfsexplorer-0_21-bin.zip
RUN unzip -j hfsexplorer-0_21-bin.zip lib/csframework.jar lib/hfsx.jar lib/hfsx_dmglib.jar lib/iharder-base64.jar -d .
RUN rm -f *.zip
WORKDIR /root/git/ghidra.bin/Ghidra/Features/GhidraServer/
RUN curl -OL https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/yajsw-stable-12.12.zip
WORKDIR /root/git/
RUN git clone https://github.com/NationalSecurityAgency/ghidra.git
WORKDIR /root/git/ghidra/
RUN gradle yajswDevUnpack
RUN gradle buildGhidra
