# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2022 Olliver Schinagl <oliver@schinagl.nl>

ARG ALPINE_VERSION="stable-slim"
ARG TARGET_ARCH="library"

FROM index.docker.io/${TARGET_ARCH}/debian:${ALPINE_VERSION} AS builder

WORKDIR /src

COPY "." "/src"

RUN apt-get update && apt-get install --yes \
        build-essential \
        default-jdk-headless \
        gradle \
        unzip \
    && \
    export JAVA_HOME='/usr/lib/jvm/default-java/' && \
    echo 'Updating gradle, as debian ships with an ancient version' && \
    _gradle_wrapper="$(mktemp -d -p "${TMPDIR:-/tmp}" 'graddlewrapper.XXXXXX')" && \
    ( cd "${_gradle_wrapper}" && gradle wrapper --gradle-version '7.4.2' --distribution-type 'bin') && \
    cp -r "${_gradle_wrapper}/"* '.' && \
    rm -f -r "${_gradle_wrapper}" && \
    ./gradlew --init-script 'gradle/support/fetchDependencies.gradle' init && \
    ./gradlew 'buildGhidra' && \
    _ghidra_tmp="$(mktemp -d -p "${TMPDIR:-/tmp}" 'ghidra.XXXXXX')" && \
    unzip -u 'build/dist/ghidra_'*'.zip' -d "${_ghidra_tmp}" && \
    mv "${_ghidra_tmp}/ghidra_"*'_DEV' '/ghidra' && \
    sed -i \
        -e "s|^\(ghidra\.repositories\.dir=\).*$|\1/var/lib/ghidra/|g" \
        -e "s|^\(wrapper\.logfile=\).*$|\1/var/log/ghidra/wrapper.log|g" \
        -e "s|^\(wrapper\.daemon\.system.*\)$|#\1|g" \
        -e '/^wrapper\.app\.parameter\..*$/d' \
        '/ghidra/server/server.conf' && \
    rm -f -r \
       '/ghidra/Extensions/' \
       #       '/ghidra/GPL/' \
       #       '/ghidra/Ghidra/Configurations/' \
       #       '/ghidra/Ghidra/Debug/' \
       #       '/ghidra/Ghidra/Features/Base/' \
       #       '/ghidra/Ghidra/Features/BytePatterns/' \
       #       '/ghidra/Ghidra/Features/ByteViewer/' \
       #       '/ghidra/Ghidra/Features/DebugUtils/' \
       #       '/ghidra/Ghidra/Features/Decompiler/' \
       #       '/ghidra/Ghidra/Features/DecompilerDependent/' \
       #       '/ghidra/Ghidra/Features/FileFormats/' \
       #       '/ghidra/Ghidra/Features/FunctionGraph/' \
       #       '/ghidra/Ghidra/Features/FunctionGraphDecompilerExtension/' \
       #       '/ghidra/Ghidra/Features/FunctionID/' \
       #       '/ghidra/Ghidra/Features/GnuDemangler/' \
       #       '/ghidra/Ghidra/Features/GraphFunctionCalls/' \
       #       '/ghidra/Ghidra/Features/GraphServices/' \
       #       '/ghidra/Ghidra/Features/MicrosoftCodeAnalyzer/' \
       #       '/ghidra/Ghidra/Features/MicrosoftDemangler/' \
       #       '/ghidra/Ghidra/Features/MicrosoftDemang/' \
       #       '/ghidra/Ghidra/Features/PDB/' \
       #       '/ghidra/Ghidra/Features/ProgramDiff/' \
       #       '/ghidra/Ghidra/Features/ProgramGraph/' \
       #       '/ghidra/Ghidra/Features/Python/' \
       #       '/ghidra/Ghidra/Features/Recognizers/' \
       #       '/ghidra/Ghidra/Features/SourceCodeLookup/' \
       #       '/ghidra/Ghidra/Features/VersionTracking/' \
       #       '/ghidra/Ghidra/Framework/' \
       #       '/ghidra/Ghidra/Processors/' \
       '/ghidra/LICENSE' \
       '/ghidra/bom.json' \
       '/ghidra/docs/' \
       '/ghidra/ghidraRun' \
       '/ghidra/licenses/' \
       '/ghidra/wrapper.log' \
       '/ghidra/wrapper.log.lck' \
       ;
    # TODO remove all uneeded bits for the server


# Ghidra server container
ARG TARGET_ARCH="library"

FROM index.docker.io/${TARGET_ARCH}/openjdk:jdk-slim

LABEL maintainer="Olliver Schinagl <oliver@schinagl.nl>"

EXPOSE 13100
EXPOSE 13101
EXPOSE 13102

VOLUME /var/lib/ghidra/

COPY --from=builder "/ghidra" "/usr/share/ghidra/"
COPY "./containerfiles/healthcheck.sh" "/usr/local/bin/"
COPY "./containerfiles/container-entrypoint.sh" "/init"

RUN apt-get update && apt-get install --yes \
        tini \
    && \
    rm -f -r '/var/lib/apt/lists/' '/var/cache/apt' && \
    ln -s '/usr/share/ghidra/server/ghidraSvr' '/usr/local/bin/ghidra-server' && \
    ln -s '/usr/share/ghidra/server/svrAdmin' '/usr/local/bin/ghidra-admin' && \
    ln -s '/usr/share/ghidra/support/analyzeHeadless' '/usr/local/bin/ghidra-analyze' && \
    'ghidra-server' 'install'

WORKDIR /usr/share/ghidra/

HEALTHCHECK --interval=10m --start-period=1m --timeout=1m CMD "healthcheck.sh"

ENTRYPOINT [ "/init" ]
