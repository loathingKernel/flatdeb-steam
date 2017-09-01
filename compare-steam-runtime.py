#!/usr/bin/python3

# Compare Steam Runtime with official package list
#
# Copyright © 2017 Collabora Ltd.
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import argparse

import yaml

def main(packages):
    with open('com.valvesoftware.SteamRuntime.yaml') as reader:
        manifest = yaml.safe_load(reader)

    missing_platform = set()
    missing_sdk = set()

    with open(packages, 'r') as reader:
        for line in reader:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            tokens = line.split()

            source = tokens[0]
            binaries = tokens[1:]

            for binary in binaries:
                if (binary.endswith('-dev') or
                        binary.endswith('-multidev') or
                        binary.endswith('-dbg') or
                        # Probably not intentionally in the user-facing Runtime?
                        # https://github.com/ValveSoftware/steam-runtime/issues/76
                        binary.endswith('-pic') or
                        # Probably not intentionally in the user-facing Runtime?
                        # https://github.com/ValveSoftware/steam-runtime/issues/77
                        binary == 'nvidia-cg-toolkit'):
                    if binary in manifest['sdk']['add_packages']:
                        continue

                    missing_sdk.add(binary)
                    continue

                if binary in manifest['add_packages_multiarch']:
                    continue

                if binary in manifest['add_packages']:
                    continue

                missing_platform.add(binary)

    if missing_platform:
        print('Missing from platform:')

        for binary in sorted(missing_platform):
            print('  - ' + binary)

    if missing_sdk:
        print('Missing from sdk:')

        for binary in sorted(missing_sdk):
            print('    - ' + binary)

    if missing_platform or missing_sdk:
        raise SystemExit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Compare Steam Runtime with official package list')
    parser.add_argument(
        'packages', metavar='PACKAGES.TXT',
        help='Path to packages.txt from the Steam Runtime',
    )
    args = parser.parse_args()
    main(args.packages)
