#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
from setuptools import setup


if __name__ == "__main__":
    # This is necessary so that we can build the sdist using pip wheel.
    # Unfortunately we have to have this work without having setuptools
    # which pip will install in an isolated environment from the
    # dependencies directory.
    if "bdist_wheel" in sys.argv and "sdist" not in sys.argv:
        sys.argv.append("sdist")
    setup()
