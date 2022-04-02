#!/usr/bin/tini /bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2021 Olliver Schinagl <oliver@schinagl.nl>
# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# A beginning user should be able to docker run image bash (or sh) without
# needing to learn about --entrypoint
# https://github.com/docker-library/official-images#consistency

set -eu

# run command if it is not starting with a "-" and is an executable in PATH
if [ "${#}" -gt 0 ] && \
   [ "${1#-}" = "${1}" ] && \
   command -v "${1}" > "/dev/null" 2>&1; then
	# Ensure healthcheck always passes
	exec "${@}"
else
	if [ -f '/var/lib/ghidra/server.conf' ]; then
		cat '/var/lib/ghidra/server.conf' > '/usr/share/ghidra/server/server.conf'
	elif [ -n "${GHIDRA_SERVER_CONF:-}" ]; then
		echo "${GHIDRA_SERVER_CONF}" >> '/usr/share/ghidra/server/server.conf'
	else
		echo 'wrapper.app.parameter.1=-a0' >> '/usr/share/ghidra/server/server.conf'
		echo 'wrapper.app.parameter.2=-u' >> '/usr/share/ghidra/server/server.conf'
		echo 'wrapper.app.parameter.3=-anonymous' >> '/usr/share/ghidra/server/server.conf'
		echo "wrapper.app.parameter.4=-ip ${GHIDRA_PUBLIC_HOST:-$(hostname || true)}" >> '/usr/share/ghidra/server/server.conf'
		echo 'wrapper.app.parameter.5=${ghidra.repositories.dir}' >> '/usr/share/ghidra/server/server.conf'
	fi

	ghidra-server start

	tail -f '/var/log/ghidra/wrapper.log'
fi

exit 0
