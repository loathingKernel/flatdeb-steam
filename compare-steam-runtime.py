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
import os
from debian.debian_support import Version

import yaml


def main(packages, *, manifest=None, steam=None):
    with open('runtimes/com.valvesoftware.SteamRuntime.yaml') as reader:
        source_manifest = yaml.safe_load(reader)

    print('---')

    missing_platform = set()
    missing_sdk = set()
    only_in_flatpak = set()
    only_in_steam = set()
    newer_in_flatpak = set()
    newer_in_steam = set()

    if packages is not None:
        print('comparing_packages_txt:')
        print('  path: ' + packages)

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
                            # Probably not intentionally in the user-facing
                            # Runtime?
                            # https://github.com/ValveSoftware/steam-runtime/issues/76
                            binary.endswith('-pic') or
                            # Probably not intentionally in the user-facing
                            # Runtime?
                            # https://github.com/ValveSoftware/steam-runtime/issues/77
                            binary == 'nvidia-cg-toolkit'):
                        if binary in source_manifest['sdk'].get(
                                'add_packages_multiarch', ()):
                            continue

                        if binary in source_manifest['sdk']['add_packages']:
                            continue

                        missing_sdk.add(binary)
                        continue

                    if binary in source_manifest['add_packages_multiarch']:
                        continue

                    if binary in source_manifest['add_packages']:
                        continue

                    missing_platform.add(binary)

        if missing_platform:
            print('  missing_from_platform:')

            for binary in sorted(missing_platform):
                print('  - ' + binary)

        if missing_sdk:
            print('  missing_from_sdk:')

            for binary in sorted(missing_sdk):
                print('    - ' + binary)

    if steam is None:
        steam = os.path.join(os.path.expanduser('~'), '.steam', 'steam')

        if not os.path.exists(steam):
            steam = None

    steam_runtime = os.path.join(steam, 'ubuntu12_32', 'steam-runtime')

    if not os.path.exists(steam_runtime):
        steam_runtime = None

    if steam_runtime is not None and manifest is not None:
        print('comparing_steam_installation:')
        print('  steam: ' + steam_runtime)
        print('  manifest: ' + manifest)

        records = []

        with open(manifest, 'r') as reader:
            for line in reader:
                if line.strip().startswith('#'):
                    continue

                if not line.strip():
                    continue

                records.append(line.split('\t'))

        architectures = set()
        flatpak_versions = {}

        for line in records:
            if line[0].startswith('coreutils:'):
                arch = line[0].split(':', 1)[1]
                architectures.add(arch)
            elif line[0].startswith('libc6:'):
                arch = line[0].split(':', 1)[1]
                architectures.add(arch)

            flatpak_versions[line[0].split(':', 1)[0]] = line

        in_steam = set()
        only_in_flatpak = set()
        sources_only_in_flatpak = set()

        for arch in architectures:
            contents = os.listdir(
                os.path.join(steam_runtime, arch, 'installed'))

            for name in contents:
                if name in ('.', '..'):
                    continue

                if name.endswith('.md5'):
                    continue

                binary, version, arch_ = name.split('_', 2)
                assert arch_ in (arch, 'all'), (arch, name)
                in_steam.add(binary)

                flatpak_version = flatpak_versions.get(binary)

                if flatpak_version is None:
                    only_in_steam.add(binary)
                else:
                    no_epoch_version = Version(flatpak_version[1])
                    no_epoch_version.epoch = None

                    if no_epoch_version < Version(version):
                        newer_in_steam.add(
                            (binary, flatpak_version[1], version, arch))

                    if no_epoch_version > Version(version):
                        newer_in_flatpak.add(
                            (binary, flatpak_version[1], version, arch))

        for package, line in flatpak_versions.items():
            if package not in in_steam:
                source = line[2] or package

                if '(' in source:
                    source_version = source.split('(', 1)[1].strip(')')
                else:
                    source_version = line[1]

                only_in_flatpak.add(package)
                sources_only_in_flatpak.add((source, source_version))

        if only_in_steam:
            print('  only_in_steam:')

            for binary in sorted(only_in_steam):
                print('    - ' + binary)

        if only_in_flatpak:
            print('  only_in_flatpak:')

            for binary in sorted(only_in_flatpak):
                print('    - ' + binary)

        if sources_only_in_flatpak:
            print('  sources_only_in_flatpak:')

            for source in sorted(sources_only_in_flatpak):
                print('    - source: ' + source[0])
                print('      source_version: ' + source[1])

        if newer_in_flatpak:
            print('  newer_in_flatpak:')

            for binary in sorted(newer_in_flatpak):
                print('    - package: ' + binary[0])
                print('      in_flatpak: ' + binary[1])
                print('      in_steam: ' + binary[2])
                print('      architecture: ' + binary[3])

        if newer_in_steam:
            print('  newer_in_steam:')

            for binary in sorted(newer_in_steam):
                print('    - package: ' + binary[0])
                print('      in_flatpak: ' + binary[1])
                print('      in_steam: ' + binary[2])
                print('      architecture: ' + binary[3])

    print('...')

    if (missing_platform or missing_sdk or only_in_steam or
            newer_in_flatpak or newer_in_steam):
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Compare Steam Runtime with official package list')
    parser.add_argument(
        '--steam', metavar='STEAM',
        help='Path to ~/.steam/steam or ~/.local/share/Steam',
    )
    parser.add_argument(
        '--manifest', metavar='MANIFEST',
        help='Path to '
        '~/.local/share/flatpak/runtime/'
        'com.valvesoftware.SteamRuntime.Platform/'
        'x86_64/scout_beta/active/files/manifest.dpkg or similar',
    )
    parser.add_argument(
        'packages', metavar='PACKAGES.TXT',
        help='Path to packages.txt from the Steam Runtime',
    )
    args = parser.parse_args()
    main(args.packages, manifest=args.manifest, steam=args.steam)
