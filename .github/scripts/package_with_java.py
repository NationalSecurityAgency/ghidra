# HexToCode
# Copyright (c) 2026 Shmuel Sinay <g47ben@gmail.com>. All rights reserved.
# Licensed under the HexToCode Restricted License; see LICENSE.
"""
Creates a "with Java" HexToCode package: the platform build from build/dist plus the
JDK the build ran with (JAVA_HOME), placed in the installation's "jdk" folder. The
launch scripts use that folder when it exists, so nothing else needs to be installed.

usage: python package_with_java.py <release-tag> <runner-os: Linux|Windows|macOS>
"""
import glob
import os
import sys
import zipfile

tag, runner_os = sys.argv[1], sys.argv[2].lower()
platform = {"linux": "linux", "windows": "windows", "macos": "macos"}[runner_os]

dists = glob.glob(os.path.join("build", "dist", "hextocode_*.zip"))
if len(dists) != 1:
    sys.exit("expected exactly one build/dist/hextocode_*.zip, found: %s" % dists)
java_home = os.environ["JAVA_HOME"]
if not os.path.isfile(os.path.join(java_home, "bin", "java.exe" if platform == "windows" else "java")):
    sys.exit("JAVA_HOME does not contain bin/java: " + java_home)

out = "HexToCode-%s-%s-with-java.zip" % (tag, platform)
with zipfile.ZipFile(dists[0]) as src, \
        zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as dst:
    top = None
    for info in src.infolist():
        top = top or info.filename.split("/")[0]
        # copying the ZipInfo keeps file permissions (executable launchers)
        with src.open(info) as data:
            dst.writestr(info, data.read())
    for root, _dirs, files in os.walk(java_home):
        for name in files:
            full = os.path.join(root, name)
            # skip broken links and the JDK's own source archive (not needed to run)
            if not os.path.exists(full) or name == "src.zip":
                continue
            rel = os.path.relpath(full, java_home).replace(os.sep, "/")
            dst.write(full, "%s/jdk/%s" % (top, rel))

print("created", out, "(%d MB)" % (os.path.getsize(out) // (1024 * 1024)))
