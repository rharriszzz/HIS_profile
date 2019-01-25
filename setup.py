#!/usr/bin/env python

import sys, os, re, platform
from os.path import exists, abspath, dirname, join, isdir, relpath

from setuptools import setup, Command
from distutils.extension import Extension
from distutils.errors import *

from configparser import ConfigParser

OFFICIAL_BUILD = 9999

class VersionCommand(Command):

    description = "prints the his_profile version, determined from git"

    user_options = []

    def initialize_options(self):
        self.verbose = 0

    def finalize_options(self):
        pass

    def run(self):
        version_str, version = get_version()
        print(version_str)



def get_version():
    """
    Returns the version of the product as (description, [major,minor,micro,beta]).

    If the release is official, `beta` will be 9999 (OFFICIAL_BUILD).

      1. If in a git repository, use the latest tag (git describe).
      2. If in an unzipped source directory (from setup.py sdist),
         read the version from the PKG-INFO file.
      3. Use 4.0.0.0 and complain a lot.
    """
    name    = None              # branch/feature name.  Should be None for official builds.
    numbers = None              # The 4 integers that make up the version.

    if not numbers:
        name, numbers = _get_version_git()

    if not numbers:
        print('WARNING: Unable to determine version.  Using 4.0.0.0')
        name, numbers = '4.0.0-unsupported', [4,0,0,0]

    return name, numbers


def _get_version_git():
    n, result = getoutput("git describe --tags --match [0-9]*")
    if n:
        print('WARNING: git describe failed with: %s %s' % (n, result))
        return None, None

    match = re.match(r'(\d+).(\d+).(\d+) (?: -(\d+)-g[0-9a-z]+)?', result, re.VERBOSE)
    if not match:
        return None, None

    numbers = [int(n or OFFICIAL_BUILD) for n in match.groups()]
    if numbers[-1] == OFFICIAL_BUILD:
        name = '%s.%s.%s' % tuple(numbers[:3])
    if numbers[-1] != OFFICIAL_BUILD:
        # This is a beta of the next micro release, so increment the micro number to reflect this.
        numbers[-2] += 1
        name = '%s.%s.%sb%d' % tuple(numbers)

    return name, numbers


def getoutput(cmd):
    pipe = os.popen(cmd, 'r')
    text   = pipe.read().rstrip('\n')
    status = pipe.close() or 0
    return status, text


def main():

    version_str, version = get_version()

    kwargs = {
        'name': "his_profile",
        'version': version_str,
        'description': "A profiler using the zos HIS service",

        'maintainer':       "Rick Harris",
        'maintainer_email': "rharris@rocketsoftware.com",

        'ext_modules': [Extension('_csv_info', [ "his_profile/_csv_info.c" ])],
        'packages': ['his_profile']

        'license': 'Other',

        'classifiers': ['Development Status :: 1 - Alpha',
                       'Intended Audience :: Developers',
                       'Intended Audience :: System Administrators',
                        'License :: Other',
                        'Operating System :: IBM :: z/OS',
                        'Programming Language :: Python',
                        'Programming Language :: Python :: 3',
                        'Topic :: Database',
        ],

        'cmdclass': { 'version' : VersionCommand }
        }

    setup(**kwargs)

if __name__ == '__main__':
    main()
