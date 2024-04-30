#!/usr/bin/python3

# flatdeb — build Flatpak runtimes from Debian packages
#
# Copyright 2015-2017 Simon McVittie
# Copyright 2017-2023 Collabora Ltd.
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

"""
Create Flatpak runtimes from Debian packages.
"""

import argparse
import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import typing
import urllib.parse
from contextlib import ExitStack
from tempfile import TemporaryDirectory

import yaml
from gi.repository import GLib


logger = logging.getLogger('flatdeb')


# TODO: When flatdeb is packaged/released, replace this with the released
# version in packages/releases
VERSION = None

if VERSION is None:
    _git_version = subprocess.check_output([
        'sh', '-c',
        'cd "$(dirname "$1")" && '
        'git describe '
        '--always '
        '--dirty '
        '--first-parent '
        '--long '
        '--tags '
        '--match="v[0-9]*" '
        '2>/dev/null || :',
        'sh',
        sys.argv[0],
    ])[1:].decode('utf-8').strip()
    VERSION = _git_version

_DEBOS_BASE_RECIPE = os.path.join(
    os.path.dirname(__file__), 'flatdeb', 'debos-base.yaml')
_DEBOS_COLLECT_DBGSYM_RECIPE = os.path.join(
    os.path.dirname(__file__), 'flatdeb', 'debos-collect-dbgsym.yaml')
_DEBOS_COLLECT_SOURCE_RECIPE = os.path.join(
    os.path.dirname(__file__), 'flatdeb', 'debos-collect-source.yaml')
_DEBOS_RUNTIMES_RECIPE = os.path.join(
    os.path.dirname(__file__), 'flatdeb', 'debos-runtimes.yaml')


class SignedBy:
    def __str__(self) -> str:
        raise NotImplementedError


class SignedByFingerprint(SignedBy):
    def __init__(self, fingerprint: str, subkeys: bool = True) -> None:
        self.fingerprint = fingerprint
        self.subkeys = subkeys

    def __str__(self):
        return '{}{}'.format(
            self.fingerprint,
            '!' if not self.subkeys else '',
        )


class SignedByKeyring(SignedBy):
    def __init__(self, path: str) -> None:
        self.path = path

    def __str__(self):
        return self.path


class AptSource:
    def __init__(
        self,
        kind,                       # type: str
        uri,                        # type: str
        suite,                      # type: str
        components=('main',),       # type: typing.Sequence[str]
        signed_by=(),               # type: typing.Sequence[SignedBy]
        trusted=False
    ):
        self.kind = kind
        self.uri = uri
        self.suite = suite
        self.components = components
        self.signed_by = set(signed_by)
        self.trusted = trusted

    def __eq__(self, other):
        # type: (typing.Any) -> bool
        if not isinstance(other, AptSource):
            return False

        if self.kind != other.kind:
            return False

        if self.uri != other.uri:
            return False

        if self.suite != other.suite:
            return False

        if set(self.components) != set(other.components):
            return False

        if set(self.signed_by) != set(other.signed_by):
            return False

        if self.trusted != other.trusted:
            return False

        return True

    @classmethod
    def multiple_from_string(
        cls,        # type: typing.Type[AptSource]
        line,       # type: str
    ):
        # type: (...) -> typing.Iterable[AptSource]
        line = line.strip()
        tokens = line.split()

        if tokens[0] in ('deb', 'deb-src'):
            return (cls.from_string(line),)
        elif tokens[0] == 'both':
            return (
                cls.from_string('deb' + line[4:]),
                cls.from_string('deb-src' + line[4:]),
            )
        else:
            raise ValueError(
                'apt sources must start with "deb ", "deb-src " or "both "')

    @classmethod
    def from_string(
        cls,        # type: typing.Type[AptSource]
        line,       # type: str
    ):
        # type: (...) -> AptSource
        signed_by: typing.List[SignedBy] = []
        rest: typing.List[str] = []
        tokens = line.split()
        trusted = False

        if len(tokens) < 4:
            raise ValueError(
                'apt sources must be specified in the form '
                '"deb http://URL SUITE COMPONENT [COMPONENT...]"')

        if tokens[0] not in ('deb', 'deb-src'):
            raise ValueError(
                'apt sources must start with "deb " or "deb-src "')

        if tokens[1].startswith('['):
            for i in range(1, len(tokens)):
                token = tokens[i].lstrip('[')
                option = token.rstrip(']')

                if option == 'trusted=yes':
                    trusted = True
                elif option.startswith('signed-by='):
                    signed_by_str = option[len('signed-by='):].split(',')

                    for signer in signed_by_str:
                        if signer.startswith('/'):
                            signed_by.append(SignedByKeyring(signer))
                        elif re.match(r'^[0-9A-Fa-f]+$', signer):
                            signed_by.append(SignedByFingerprint(signer))
                        elif re.match(r'^[0-9A-Fa-f]+!$', signer):
                            signed_by.append(
                                SignedByFingerprint(signer, subkeys=False)
                            )
                        else:
                            signed_by.append(
                                SignedByKeyring(
                                    f'/etc/apt/keyrings/{signer}'
                                )
                            )

                if option != token:
                    rest = tokens[i + 1:]
                    break
        else:
            rest = tokens[1:]

        return cls(
            kind=tokens[0],
            uri=rest[0],
            suite=rest[1],
            components=rest[2:],
            signed_by=signed_by,
            trusted=trusted,
        )

    def __str__(self):
        # type: () -> str
        options: typing.List[str] = []

        if self.signed_by:
            options.append(
                'signed-by={}'.format(
                    ','.join(map(str, self.signed_by))
                )
            )

        if self.trusted:
            options.append('trusted=yes')

        if options:
            maybe_options = ' [{}]'.format(' '.join(options))
        else:
            maybe_options = ''

        return '%s%s %s %s %s' % (
            self.kind,
            maybe_options,
            self.uri,
            self.suite,
            ' '.join(self.components),
        )


class Builder:

    """
    Main object
    """

    __multiarch_tuple_cache = {}    # type: typing.Dict[str, str]

    def __init__(self):
        # type: () -> None

        self.apt_debug = False
        #: The Debian suite to use
        self.apt_suite = 'stretch'
        #: The Flatpak branch to use for the runtime, or None for apt_suite
        self.runtime_branch = None      # type: typing.Optional[str]
        #: The Flatpak branch to use for the app
        self.app_branch = None          # type: typing.Optional[str]
        #: The freedesktop.org cache directory
        self.xdg_cache_dir = os.getenv(
            'XDG_CACHE_HOME', os.path.expanduser('~/.cache'))
        #: Where to write output
        self.build_area = os.path.join(
            self.xdg_cache_dir, 'flatdeb',
        )
        self.ostree_repo = os.path.join(self.build_area, 'ostree-repo')
        self.remote_url = None      # type: typing.Optional[str]

        self.__dpkg_archs = []      # type: typing.Sequence[str]
        self.flatpak_arch = None    # type: typing.Optional[str]

        self.__primary_dpkg_arch_matches_cache = {
        }       # type: typing.Dict[str, bool]
        self.suite_details = {}         # type: typing.Dict[str, typing.Any]
        self.runtime_details = {}       # type: typing.Dict[str, typing.Any]
        self.ostree_commit = True
        self.ostree_mode = 'archive-z2'
        self.export_bundles = False
        self.strip_source_version_suffix = None
        self.bootstrap_apt_keyring = ''
        #: apt sources to use when building the runtime
        self.build_apt_keyrings = []    # type: typing.List[str]
        self.build_apt_sources = []     # type: typing.List[AptSource]
        #: apt sources to leave in /etc/apt/sources.list afterwards
        self.final_apt_keyrings = []    # type: typing.List[str]
        self.final_apt_sources = []     # type: typing.List[AptSource]
        self.build_id = None
        self.variant_name = None
        self.variant_id = None
        self.sdk_variant_name = None
        self.sdk_variant_id = None
        self.debug_symbols = True
        self.automatic_dbgsym = True
        self.collect_source_code = True
        self.do_mtree = False
        self.strict = False
        self.do_platform = False
        self.do_sdk = False

        self.metadata = GLib.KeyFile()
        self.metadata_debug = GLib.KeyFile()
        self.metadata_sources = GLib.KeyFile()

        self.logger = logger.getChild('Builder')

    @staticmethod
    def yaml_dump_one_line(
        data,               # type: typing.Any
        stream=None,        # type: ignore
    ):
        # type: (...) -> typing.Optional[str]
        return yaml.safe_dump(
            data,
            stream=stream,
            default_flow_style=True,
            width=0xFFFFFFFF,
        ).replace('\n', ' ')

    @staticmethod
    def get_flatpak_arch(arch=None):
        # type: (typing.Optional[str]) -> str
        """
        Return the Flatpak architecture name corresponding to uname
        result arch.

        If arch is None, return the Flatpak architecture name
        corresponding to the machine where this script is running.
        """

        if arch is None:
            arch = os.uname()[4]

        if re.match(r'^i.86$', arch):
            return 'i386'
        elif re.match(r'^arm.*', arch):
            if arch.endswith('b'):
                return 'armeb'
            else:
                return 'arm'
        elif arch in ('mips', 'mips64'):
            import struct
            if struct.pack('i', 1).startswith(b'\x01'):
                return arch + 'el'

        return arch

    @staticmethod
    def other_multiarch(arch):
        # type: (str) -> typing.Optional[str]
        """
        Return the other architecture that accompanies the given Debian
        architecture in a multiarch setup, or None.
        """

        if arch == 'amd64':
            return 'i386'
        elif arch == 'arm64':
            return 'armhf'
        else:
            return None

    @staticmethod
    def multiarch_tuple(arch):
        # type: (str) -> str
        """
        Return the multiarch tuple for the given dpkg architecture name.
        """

        if arch not in Builder.__multiarch_tuple_cache:
            Builder.__multiarch_tuple_cache[arch] = subprocess.check_output([
                'dpkg-architecture',
                '-qDEB_HOST_MULTIARCH',
                '-a{}'.format(arch),
            ]).decode('utf-8').strip()

        return Builder.__multiarch_tuple_cache[arch]

    @staticmethod
    def dpkg_to_flatpak_arch(arch):
        # type: (str) -> str
        """
        Return the Flatpak architecture name corresponding to the given
        dpkg architecture name.
        """

        if arch == 'amd64':
            return 'x86_64'
        elif arch == 'arm64':
            return 'aarch64'
        elif arch in ('armel', 'armhf'):
            return 'arm'
        elif arch == 'powerpc':
            return 'ppc'
        elif arch == 'powerpc64':
            return 'ppc64'
        elif arch == 'powerpcel':
            return 'ppcle'
        elif arch == 'ppc64el':
            return 'ppc64le'

        return arch

    @property
    def primary_dpkg_arch(self):
        # type: () -> str
        """
        The Debian architecture we are building a runtime for, such as
        i386 or amd64.
        """
        return self.__dpkg_archs[0]

    @property
    def dpkg_archs(self):
        # type: () -> typing.Sequence[str]
        """
        The Debian architectures we support via multiarch, such as
        ['amd64', 'i386'].
        """
        return self.__dpkg_archs

    @dpkg_archs.setter
    def dpkg_archs(self, value):
        # type: (typing.Sequence[str]) -> None
        self.__primary_dpkg_arch_matches_cache = {}
        self.__dpkg_archs = value

    def primary_dpkg_arch_matches(self, arch_spec):
        # type: (str) -> bool
        """
        Return True if arch_spec matches primary_dpkg_arch (or
        equivalently, if primary_dpkg_arch is one of the architectures
        described by arch_spec). For example, any-amd64 matches amd64
        but not i386.
        """
        if arch_spec not in self.__primary_dpkg_arch_matches_cache:
            exit_code = subprocess.call(
                ['dpkg-architecture', '--host-arch', self.primary_dpkg_arch,
                 '--is', arch_spec])
            self.__primary_dpkg_arch_matches_cache[arch_spec] = (
                exit_code == 0
            )

        return self.__primary_dpkg_arch_matches_cache[arch_spec]

    def run_command_line(self):
        # type: () -> None
        """
        Run appropriate commands for the command-line arguments
        """
        parser = argparse.ArgumentParser(
            description='Build Flatpak runtimes',
        )
        parser.add_argument('--chdir', default=None)
        parser.add_argument(
            '--ostree-mode', default=self.ostree_mode,
        )
        parser.add_argument(
            '--export-bundles', action='store_true', default=False,
        )
        parser.add_argument('--build-area', default=self.build_area)
        parser.add_argument('--ostree-repo', default=self.ostree_repo)
        parser.add_argument('--remote-url', default=self.remote_url)
        parser.add_argument(
            '--ostree-commit', action='store_true', default=self.ostree_commit,
        )
        parser.add_argument(
            '--no-ostree-commit', dest='ostree_commit', action='store_false',
        )
        parser.add_argument('--suite', '-d', default=self.apt_suite)
        parser.add_argument('--architecture', '--arch', '-a')
        parser.add_argument('--runtime-branch', default=self.runtime_branch)
        parser.add_argument('--version', action='store_true')
        parser.add_argument(
            '--replace-apt-source', action='append', default=[])
        parser.add_argument(
            '--remove-apt-source', action='append', default=[])
        parser.add_argument(
            '--add-apt-source', action='append', default=[])
        parser.add_argument(
            '--replace-build-apt-source', action='append', default=[])
        parser.add_argument(
            '--remove-build-apt-source', action='append', default=[])
        parser.add_argument(
            '--add-build-apt-source', action='append', default=[])
        parser.add_argument(
            '--replace-final-apt-source', action='append', default=[])
        parser.add_argument(
            '--remove-final-apt-source', action='append', default=[])
        parser.add_argument(
            '--add-final-apt-source', action='append', default=[])
        parser.add_argument(
            '--bootstrap-apt-keyring', default='')
        parser.add_argument(
            '--add-apt-keyring', action='append', default=[])
        parser.add_argument(
            '--add-build-apt-keyring', action='append', default=[])
        parser.add_argument(
            '--add-final-apt-keyring', action='append', default=[])
        parser.add_argument(
            '--generate-sysroot-tarball', action='store_true')
        parser.add_argument(
            '--no-generate-sysroot-tarball',
            dest='generate_sysroot_tarball',
            action='store_false',
        )
        parser.add_argument(
            '--generate-platform-sysroot-tarball',
            action='store_true',
            default=False,
        )
        parser.add_argument(
            '--no-generate-platform-sysroot-tarball',
            dest='generate_platform_sysroot_tarball',
            action='store_false',
        )
        parser.add_argument(
            '--generate-sdk-sysroot-tarball',
            action='store_true',
            default=None,
        )
        parser.add_argument(
            '--no-generate-sdk-sysroot-tarball',
            dest='generate_sdk_sysroot_tarball',
            action='store_false',
            default=None,
        )
        parser.add_argument(
            '--generate-source-tarball',
            action='store_true',
            default=None,
        )
        parser.add_argument(
            '--no-generate-source-tarball',
            dest='generate_source_tarball',
            action='store_false',
        )
        parser.add_argument(
            '--generate-source-directory',
            default='',
        )
        parser.add_argument(
            '--no-generate-source-directory',
            dest='generate_source_directory',
            action='store_const',
            const='',
        )
        parser.add_argument(
            '--generate-mtree',
            action='store_true',
            default=True,
        )
        parser.add_argument(
            '--no-generate-mtree',
            dest='generate_mtree',
            action='store_false',
        )
        parser.add_argument(
            '--build-id', default=None)
        parser.add_argument(
            '--variant-name', default=None)
        parser.add_argument(
            '--variant-id', default=None)
        parser.add_argument(
            '--sdk-variant-name', default=None)
        parser.add_argument(
            '--sdk-variant-id', default=None)
        subparsers = parser.add_subparsers(dest='command', metavar='command')
        parser.add_argument('--apt-debug', action='store_true')
        parser.add_argument(
            '--no-apt-debug', dest='apt_debug',
            action='store_false')
        parser.add_argument(
            '--debug-symbols', action='store_true', default=True,
            help='Include packages that are tagged as debug symbols',
        )
        parser.add_argument(
            '--no-debug-symbols', dest='debug_symbols', action='store_false',
            help='Exclude packages that are tagged as debug symbols',
        )
        parser.add_argument(
            '--automatic-dbgsym', action='store_true', default=None,
            help='Include corresponding automatic -dbgsym packages for '
                 'each package in the Platform (default: detect from suite)',
        )
        parser.add_argument(
            '--no-automatic-dbgsym', dest='automatic_dbgsym',
            action='store_false', default=None,
            help='Do not include corresponding automatic -dbgsym packages '
                 'for each package in the Platform',
        )
        parser.add_argument(
            '--ddeb-include-executables', action='store_true', default=False,
            help='Include executable code in --ddeb-directory',
        )
        parser.add_argument(
            '--dbgsym-tarball', action='store_true', default=None,
            help='',
        )
        parser.add_argument(
            '--no-dbgsym-tarball', dest='dbgsym_tarball',
            action='store_false', default=None,
            help='',
        )
        parser.add_argument(
            '--ddeb-directory',
            metavar='DIR',
            default='',
            help=(
                'Download detached debug symbol .deb/.ddeb packages '
                'into DIR'
            ),
        )
        parser.add_argument(
            '--no-ddeb-directory',
            dest='ddeb_directory',
            action='store_const',
            const='',
            help=(
                'Do not collect detached debug symbol .deb/.ddeb packages '
                'in a directory'
            ),
        )
        parser.add_argument(
            '--collect-source-code', action='store_true', default=True,
            help='Include source code for each package (default)',
        )
        parser.add_argument(
            '--no-collect-source-code', dest='collect_source_code',
            action='store_false', default=True,
            help='Do not include source code',
        )
        parser.add_argument(
            '--strict', action='store_true', default=False,
            help='Make various warnings into fatal errors',
        )
        parser.add_argument(
            '--no-strict', action='store_false', dest='strict', default=False,
            help='Do not make various warnings fatal (default)',
        )

        parser.add_argument(
            '--platform', action='store_true', default=None,
            help='Build Platform image (default unless --sdk is used)',
        )
        parser.add_argument(
            '--no-platform', action='store_false', dest='platform',
            default=None,
            help='Do not build Platform (default if --sdk is used)',
        )
        parser.add_argument(
            '--sdk', action='store_true', default=None,
            help='Build SDK image (default unless --platform is used)',
        )
        parser.add_argument(
            '--no-sdk', action='store_false', dest='sdk', default=None,
            help='Do not build SDK (default if --platform is used)',
        )

        subparser = subparsers.add_parser(
            'base',
            help='Build a fresh base tarball',
        )

        subparser = subparsers.add_parser(
            'collect-source',
            help="Collect a runtime's source code",
        )
        subparser.add_argument('runtime_yaml_file')
        subparser.add_argument('source_required', nargs='*')

        subparser = subparsers.add_parser(
            'collect-dbgsym',
            help="Collect a runtime's detached debug symbols",
        )
        subparser.add_argument(
            '--platform-manifest', action='append', default=[],
        )
        subparser.add_argument(
            '--sdk-manifest', action='append', default=[],
        )
        subparser.add_argument('runtime_yaml_file')

        subparser = subparsers.add_parser(
            'runtimes',
            help='Build runtimes',
        )
        subparser.add_argument('yaml_file')

        subparser = subparsers.add_parser(
            'app',
            help='Build an app',
        )
        subparser.add_argument('--app-branch', default=self.app_branch)
        subparser.add_argument('yaml_manifest')

        subparser = subparsers.add_parser(
            'print-flatpak-architecture',
            help='Print the Flatpak architecture',
        )

        args = parser.parse_args()

        for replacement in args.replace_apt_source:
            if '=' not in replacement:
                parser.error(
                    '--replace-apt-source argument must be in the form '
                    '"LABEL=deb http://ARCHIVE SUITE COMPONENT[...]"')

        if (
            '/' in args.generate_source_directory
            or args.generate_source_directory == '..'
        ):
            parser.error(
                '--generate-source-directory must be a single '
                'directory name'
            )

        if args.version:
            print('flatdeb {}'.format(VERSION))
            return

        if args.chdir is not None:
            os.chdir(args.chdir)

        self.apt_debug = args.apt_debug
        self.bootstrap_apt_keyring = args.bootstrap_apt_keyring
        self.build_area = args.build_area
        self.build_id = args.build_id
        self.debug_symbols = args.debug_symbols
        self.variant_name = args.variant_name
        self.variant_id = args.variant_id
        self.sdk_variant_name = args.sdk_variant_name
        self.sdk_variant_id = args.sdk_variant_id
        self.apt_suite = args.suite
        self.runtime_branch = args.runtime_branch
        self.ostree_commit = args.ostree_commit
        self.ostree_repo = args.ostree_repo
        self.remote_url = args.remote_url
        self.export_bundles = args.export_bundles
        self.ostree_mode = args.ostree_mode
        self.strict = args.strict
        self.do_mtree = args.generate_mtree

        if args.platform is None and args.sdk is None:
            self.do_platform = True
            self.do_sdk = True
        elif args.sdk:
            self.do_platform = bool(args.platform)
            self.do_sdk = True
        elif args.platform:
            self.do_platform = True
            self.do_sdk = bool(args.sdk)
        else:
            self.do_platform = bool(args.platform)
            self.do_sdk = bool(args.sdk)

        if args.generate_sdk_sysroot_tarball is None:
            args.generate_sdk_sysroot_tarball = args.generate_sysroot_tarball

        if not (self.do_sdk or self.do_platform):
            parser.error(
                '--no-sdk and --no-platform cannot work together')

        if self.export_bundles and not self.ostree_commit:
            parser.error(
                '--export-bundles and --no-ostree-commit cannot '
                'work together')

        if args.architecture is None:
            self.dpkg_archs = [
                subprocess.check_output(
                    ['dpkg-architecture', '-q', 'DEB_HOST_ARCH'],
                ).decode('utf-8').rstrip('\n')
            ]
        else:
            self.dpkg_archs = args.architecture.split(',')

        self.flatpak_arch = self.dpkg_to_flatpak_arch(self.primary_dpkg_arch)

        self.ensure_build_area()

        if self.ostree_repo:
            os.makedirs(os.path.dirname(self.ostree_repo), exist_ok=True)

        if args.command is None:
            parser.error('A command is required')

        with open(
                os.path.join('suites', self.apt_suite + '.yaml'),
                encoding='utf-8') as reader:
            self.suite_details = yaml.safe_load(reader)

        self.strip_source_version_suffix = self.suite_details.get(
            'strip_source_version_suffix', '')
        self.use_signed_by = bool(self.suite_details.get('signed_by', []))

        if args.automatic_dbgsym is None:
            self.automatic_dbgsym = self.suite_details.get(
                'has_automatic_dbgsym', True,
            )
        else:
            self.automatic_dbgsym = args.automatic_dbgsym

        if self.do_sdk:
            self.collect_source_code = args.collect_source_code
        else:
            # --no-sdk overrides --collect-source-code: if we are not
            # building the SDK then we have no opportunity to collect
            # the source code
            self.collect_source_code = False

        self.build_apt_sources = self.generate_apt_sources(
            add=args.add_apt_source + args.add_build_apt_source,
            replace=args.replace_apt_source + args.replace_build_apt_source,
            remove=args.remove_apt_source + args.remove_build_apt_source,
            for_build=True,
        )
        self.final_apt_sources = self.generate_apt_sources(
            add=args.add_apt_source + args.add_final_apt_source,
            replace=args.replace_apt_source + args.replace_final_apt_source,
            remove=args.remove_apt_source + args.remove_final_apt_source,
            for_build=False,
        )

        for addition in args.add_apt_keyring + args.add_build_apt_keyring:
            self.build_apt_keyrings.append(addition)

        for addition in args.add_apt_keyring + args.add_final_apt_keyring:
            self.final_apt_keyrings.append(addition)

        if self.build_apt_sources[0].kind != 'deb':
            parser.error('First apt source must provide .deb packages')

        getattr(
            self, 'command_' + args.command.replace('-', '_'))(**vars(args))

    def generate_apt_sources(
        self,
        add=(),         # type: typing.Sequence[str]
        replace=(),     # type: typing.Sequence[str]
        remove=(),      # type: typing.Sequence[str]
        for_build=False
    ):
        # type: (...) -> typing.List[AptSource]

        apt_sources = []        # type: typing.List[AptSource]

        for source in self.suite_details['sources']:
            keyring = source.get('keyring')

            if keyring is not None:
                if for_build:
                    self.build_apt_keyrings.append(keyring)
                else:
                    self.final_apt_keyrings.append(keyring)

            keyrings = source.get('keyrings', [])

            if keyrings:
                if for_build:
                    self.build_apt_keyrings.extend(keyrings)
                else:
                    self.final_apt_keyrings.extend(keyrings)

            uri = source['apt_uri']
            suite = source.get('apt_suite', self.apt_suite)
            suite = suite.replace('*', self.apt_suite)
            components = source.get(
                'apt_components',
                self.suite_details.get('apt_components', ['main'])
            )
            signed_by_str = source.get(
                'signed_by',
                source.get(
                    'keyrings',
                    self.suite_details.get('signed_by', []),
                ),
            )
            signed_by: typing.List[SignedBy] = []
            trusted = source.get('apt_trusted', False)

            if self.use_signed_by:
                for token in signed_by_str:
                    if token.startswith('/'):
                        signed_by.append(SignedByKeyring(token))
                    elif re.match(r'^[0-9A-Fa-f]+$', token):
                        signed_by.append(SignedByFingerprint(token))
                    elif re.match(r'^[0-9A-Fa-f]+!$', token):
                        signed_by.append(
                            SignedByFingerprint(token, subkeys=False)
                        )
                    elif for_build:
                        signed_by.append(
                            SignedByKeyring(
                                f'/etc/apt/keyrings/flatdeb-build-{token}'
                            )
                        )
                    else:
                        signed_by.append(
                            SignedByKeyring(
                                f'/etc/apt/keyrings/{token}'
                            )
                        )

            if 'label' in source:
                replaced = False

                for replacement in reversed(replace):
                    key, value = replacement.split('=', 1)

                    if key == source['label']:
                        apt_sources.extend(
                            AptSource.multiple_from_string(value))
                        replaced = True
                        break

                if replaced or source['label'] in remove:
                    continue

            if for_build:
                if not source.get('for_build', True):
                    continue
            else:
                if not source.get('for_final', True):
                    continue

            if source.get('deb', True):
                apt_sources.append(AptSource(
                    'deb', uri, suite,
                    components=components,
                    signed_by=signed_by,
                    trusted=trusted,
                ))

            if source.get('deb-src', True):
                apt_sources.append(AptSource(
                    'deb-src', uri, suite,
                    components=components,
                    signed_by=signed_by,
                    trusted=trusted,
                ))

        for addition in add:
            apt_sources.extend(AptSource.multiple_from_string(addition))

        return apt_sources

    def command_print_flatpak_architecture(self, **kwargs):
        # type: (...) -> None
        print(self.flatpak_arch)

    def ensure_build_area(self):
        # type: () -> None
        os.makedirs(self.xdg_cache_dir, 0o700, exist_ok=True)
        os.makedirs(self.build_area, 0o755, exist_ok=True)
        os.makedirs(os.path.join(self.build_area, 'tmp'), exist_ok=True)

    def octal_escape_char(self, match: 're.Match') -> str:
        ret = []    # type: typing.List[str]

        for byte in match.group(0).encode('utf-8', 'surrogateescape'):
            ret.append('\\%03o' % byte)

        return ''.join(ret)

    _NEEDS_OCTAL_ESCAPE = re.compile(r'[^-A-Za-z0-9+,./:@_]')

    def octal_escape(self, s: str) -> str:
        return self._NEEDS_OCTAL_ESCAPE.sub(self.octal_escape_char, s)

    def command_base(self, **kwargs):
        # type: (...) -> None
        with ExitStack() as stack:
            scratch = stack.enter_context(
                TemporaryDirectory(prefix='flatdeb.')
            )
            self.ensure_build_area()

            # debootstrap only supports one suite, so we use the first
            apt_suite = self.build_apt_sources[0].suite
            dest_recipe = os.path.join(scratch, 'flatdeb.yaml')
            shutil.copyfile(_DEBOS_BASE_RECIPE, dest_recipe)

            for helper in (
                'apt-install',
                'clean-up-base',
                'clean-up-before-pack',
                'debootstrap',
                'disable-services',
                'list-required-source-code',
                'set-build-id',
                'usrmerge',
                'write-manifest',
            ):
                dest = os.path.join(scratch, helper)
                shutil.copyfile(
                    os.path.join(
                        os.path.dirname(__file__),
                        'flatdeb',
                        helper,
                    ),
                    dest,
                )
                os.chmod(dest, 0o755)

            for d in (
                'apt.conf.d',
                'keyrings',
                'sources.list.d',
                'trusted.gpg.d',
            ):
                os.makedirs(
                    os.path.join(
                        scratch, 'suites', apt_suite, 'overlay', 'etc',
                        'apt', d,
                    ),
                    0o755,
                    exist_ok=True,
                )

            tarball = 'base-{}-{}.tar.gz'.format(
                self.apt_suite,
                ','.join(self.dpkg_archs),
            )
            output = os.path.join(self.build_area, tarball)
            mtree = 'base-{}-{}.mtree.gz'.format(
                self.apt_suite,
                ','.join(self.dpkg_archs),
            )
            mtree = os.path.join(self.build_area, mtree)

            self.configure_apt(
                os.path.join(scratch, 'suites', apt_suite, 'overlay'),
                self.build_apt_sources,
                self.build_apt_keyrings,
                apt_keyring_prefix='flatdeb-build-',
            )

            argv = [
                'debos',
                '--artifactdir={}'.format(self.build_area),
                '-t', 'architecture:{}'.format(self.primary_dpkg_arch),
                '-t', 'suite:{}'.format(apt_suite),
                '-t', 'mirror:{}'.format(
                    self.build_apt_sources[0].uri,
                ),
                '-t', 'ospack:{}'.format(tarball + '.new'),
                '-t', 'artifact_prefix:base-{}-{}'.format(
                    self.apt_suite,
                    ','.join(self.dpkg_archs),
                ),
                '-t', 'foreignarchs:{}'.format(
                    ' '.join(self.dpkg_archs[1:]),
                ),
                '-t', 'mergedusr:{}'.format(
                    str(
                        self.suite_details.get('can_merge_usr', False),
                    ).lower(),
                ),
                '-t', 'strip_source_version_suffix:{}'.format(
                    self.strip_source_version_suffix,
                ),
            ]

            if self.apt_debug:
                argv.append('-t')
                argv.append('apt_debug:true')

            if self.build_id is not None:
                argv.append('-t')
                argv.append('build_id:{}'.format(self.build_id))

            if self.variant_name is not None:
                argv.append('-t')
                argv.append('variant:{}'.format(self.variant_name))

            if self.variant_id is not None:
                argv.append('-t')
                argv.append('variant_id:{}'.format(
                    self.escape_variant_id(self.variant_id)
                ))

            exclude = self.suite_details.get('debootstrap_exclude')
            if exclude:
                argv.append('-t')
                argv.append('exclude:{}'.format(','.join(exclude)))

            include = self.suite_details.get('debootstrap_include')
            if include:
                argv.append('-t')
                argv.append('include:{}'.format(','.join(include)))

            add_pkgs = self.suite_details.get('additional_base_packages')
            if add_pkgs:
                argv.append('-t')
                argv.append('additional_base_packages:{}'.format(
                    self.yaml_dump_one_line(add_pkgs)
                ))

            apt_keyrings = list(self.build_apt_keyrings)

            if self.bootstrap_apt_keyring:
                apt_keyrings[:0] = [self.bootstrap_apt_keyring]
            elif self.suite_details.get('bootstrap_keyring', ''):
                apt_keyrings[:0] = [self.suite_details['bootstrap_keyring']]

            for keyring in apt_keyrings:
                if os.path.exists(os.path.join('suites', keyring)):
                    keyring = os.path.join('suites', keyring)
                elif os.path.exists(keyring):
                    pass
                else:
                    raise RuntimeError('Cannot open {}'.format(keyring))

                if self.use_signed_by:
                    keyring_dir = 'keyrings'
                else:
                    keyring_dir = 'trusted.gpg.d'

                dest = os.path.join(
                    scratch, 'suites', apt_suite, 'overlay',
                    'etc', 'apt', keyring_dir,
                    'flatdeb-build-' + os.path.basename(keyring),
                )
                shutil.copyfile(keyring, dest)

                argv.append('-t')
                argv.append(
                    'keyring:suites/{}/overlay/etc/apt/{}/{}'.format(
                        apt_suite,
                        keyring_dir,
                        'flatdeb-build-' + os.path.basename(keyring),
                    )
                )

                # debootstrap only supports one keyring and one apt source,
                # so we take the first one
                break

            components = self.build_apt_sources[0].components

            if components:
                argv.append('-t')
                argv.append('components:{}'.format(','.join(components)))

            argv.append(dest_recipe)
            logger.info('%r', argv)
            subprocess.check_call(argv)

            os.rename(output + '.new', output)

            if self.do_mtree:
                self.generate_mtree(output, mtree)

    def generate_mtree(self, output: str, mtree: str) -> None:
        with open(
            mtree + '.new', 'wb'
        ) as binary_writer, gzip.GzipFile(
            os.path.basename(mtree), 'wb', fileobj=binary_writer, mtime=0
        ) as writer:
            logger.info('Summarizing archive as mtree...')
            proc = subprocess.Popen(
                [
                    'bsdtar',
                    ('--options='
                     '!all,type,link,device,mode,uid,gid,time,size,sha256'),
                    '--format=mtree',
                    '-cf',
                    '-',
                    '@' + output,
                ],
                stdout=subprocess.PIPE,
            )

            stdout = proc.stdout
            assert stdout is not None

            for line in stdout:
                writer.write(line)

            # Unfortunately mtree doesn't have an equivalent of tar
            # LNKTYPE, and we can only infer which files are hard-linked
            # together from their (resdevice,inode) tuples (which we don't
            # want to record here because that would be non-reproducible).
            # Generating a flatdeb-specific record is a bit ugly, but
            # at least it means we can compare successive builds.
            logger.info('Checking for hard links in archive...')
            with tarfile.open(
                output, 'r'
            ) as tar_reader:
                for entry in tar_reader:
                    if entry.islnk():
                        name = self.octal_escape(entry.name)
                        target = self.octal_escape(entry.linkname)
                        writer.write(
                            f'./{name} x-flatdeb-hardlink={target}\n'.encode(
                                'ascii'
                            ),
                        )

        logger.info('Finished writing mtree')
        os.rename(mtree + '.new', mtree)

    def command_collect_dbgsym(
        self,
        *,
        runtime_yaml_file,                      # type: str
        ddeb_directory='',
        ddeb_include_executables=False,
        dbgsym_tarball=None,                    # type: typing.Optional[bool]
        platform_manifest=[],                   # type: typing.List[str]
        sdk_manifest=[],                        # type: typing.List[str]
        **kwargs
    ):
        # type: (...) -> None
        if self.ostree_commit:
            self.ensure_local_repo()

        if self.runtime_branch is None:
            self.runtime_branch = self.apt_suite

        with open(runtime_yaml_file, encoding='utf-8') as reader:
            self.runtime_details = yaml.safe_load(reader)

        tarball = 'base-{}-{}.tar.gz'.format(
            self.apt_suite,
            ','.join(self.dpkg_archs),
        )

        with ExitStack() as stack:
            scratch = stack.enter_context(
                TemporaryDirectory(prefix='flatdeb.')
            )
            self.ensure_build_area()

            dest_recipe = os.path.join(scratch, 'flatdeb.yaml')
            shutil.copyfile(_DEBOS_COLLECT_DBGSYM_RECIPE, dest_recipe)

            for helper in (
                'collect-dbgsym',
                'dbgsym-use-build-id',
                'unpack-dbgsym',
            ):
                dest = os.path.join(scratch, helper)
                shutil.copyfile(
                    os.path.join(
                        os.path.dirname(__file__),
                        'flatdeb',
                        helper,
                    ),
                    dest,
                )
                os.chmod(dest, 0o755)

            prefix = self.runtime_details['id_prefix']
            runtime = prefix + '.Sdk'
            artifact_prefix = '{}-{}-{}'.format(
                runtime,
                ','.join(self.dpkg_archs),
                self.runtime_branch,
            )

            with open(
                os.path.join(scratch, 'manifest.dpkg.platform'),
                'w',
            ) as writer:
                for path in platform_manifest:
                    with open(path) as reader:
                        for line in reader:
                            writer.write(line)

            with open(
                os.path.join(scratch, 'manifest.dpkg'),
                'w',
            ) as writer:
                for path in sdk_manifest:
                    with open(path) as reader:
                        for line in reader:
                            writer.write(line)

            argv = [
                'debos',
                '--artifactdir={}'.format(self.build_area),
                '--scratchsize=8G',
                '-t', 'architecture:{}'.format(self.primary_dpkg_arch),
                '-t', 'flatpak_arch:{}'.format(self.flatpak_arch),
                '-t', 'suite:{}'.format(self.apt_suite),
                '-t', 'ospack:{}'.format(tarball),
                '-t', 'artifact_prefix:{}'.format(artifact_prefix),
                '-t', 'runtime:{}'.format(runtime),
                '-t', 'runtime_branch:{}'.format(self.runtime_branch),
            ]

            debug_prefix = artifact_prefix + '-debug'
            debug_tarball = debug_prefix + '.tar.gz'

            if self.apt_debug:
                argv.append('-t')
                argv.append('apt_debug:true')

            argv.append('-t')

            if self.automatic_dbgsym:
                argv.append('automatic_dbgsym:yes')
            else:
                argv.append('automatic_dbgsym:')

            if ddeb_directory:
                os.makedirs(
                    os.path.join(
                        self.build_area,
                        ddeb_directory,
                    ),
                    0o755,
                    exist_ok=True,
                )
                argv.append('-t')
                argv.append(
                    'ddeb_directory:{}'.format(
                        ddeb_directory))
                argv.append('-t')

                if ddeb_include_executables:
                    argv.append('ddeb_include_executables:yes')
                else:
                    argv.append('ddeb_include_executables:')

            if dbgsym_tarball is None:
                dbgsym_tarball = not ddeb_directory

            if dbgsym_tarball:
                argv.append('-t')
                argv.append('debug_tarball:' + debug_tarball + '.new')

            argv.append('-t')
            argv.append('debug_prefix:' + debug_prefix)

            overlay = os.path.join(
                scratch, 'flatpak-overlay',
            )
            self.create_flatpak_manifest_overlay(
                overlay, prefix, runtime, sdk=True,
            )

            argv.append(dest_recipe)
            logger.info('%r', argv)
            subprocess.check_call(argv)

            if dbgsym_tarball:
                output = os.path.join(self.build_area, debug_tarball)
                os.rename(output + '.new', output)

                if self.ostree_commit:
                    logger.info('Committing %s to OSTree', debug_tarball)
                    subprocess.check_call([
                        'time',
                        'ostree',
                        '--repo=' + self.ostree_repo,
                        'commit',
                        '--branch=runtime/{}.Debug/{}/{}'.format(
                            runtime,
                            self.flatpak_arch,
                            self.runtime_branch,
                        ),
                        '--subject=Update',
                        '--tree=tar={}'.format(output),
                        '--fsync=false',
                        '--tar-autocreate-parents',
                        '--add-metadata-string',
                        'xa.metadata=' + self.metadata_debug.to_data()[0],
                    ])

                    # Don't keep the history in this working repository:
                    # if history is desired, mirror the commits into a public
                    # repository and maintain history there.
                    subprocess.check_call([
                        'time',
                        'ostree',
                        '--repo=' + self.ostree_repo,
                        'prune',
                        '--refs-only',
                        '--depth=1',
                    ])

                    subprocess.check_call([
                        'time',
                        'flatpak',
                        'build-update-repo',
                        self.ostree_repo,
                    ])

    def command_collect_source(
        self,
        *,
        runtime_yaml_file,                      # type: str
        source_required,                        # type: typing.List[str]
        generate_source_directory='',
        generate_source_tarball=True,
        **kwargs
    ):
        # type: (...) -> None
        if self.ostree_commit:
            self.ensure_local_repo()

        if self.runtime_branch is None:
            self.runtime_branch = self.apt_suite

        with open(runtime_yaml_file, encoding='utf-8') as reader:
            self.runtime_details = yaml.safe_load(reader)

        tarball = 'base-{}-{}.tar.gz'.format(
            self.apt_suite,
            ','.join(self.dpkg_archs),
        )

        with ExitStack() as stack:
            scratch = stack.enter_context(
                TemporaryDirectory(prefix='flatdeb.')
            )
            self.ensure_build_area()

            dest_recipe = os.path.join(scratch, 'flatdeb.yaml')
            shutil.copyfile(_DEBOS_COLLECT_SOURCE_RECIPE, dest_recipe)

            for helper in (
                'collect-source-code',
            ):
                dest = os.path.join(scratch, helper)
                shutil.copyfile(
                    os.path.join(
                        os.path.dirname(__file__),
                        'flatdeb',
                        helper,
                    ),
                    dest,
                )
                os.chmod(dest, 0o755)

            prefix = self.runtime_details['id_prefix']
            runtime = prefix + '.Sdk'
            artifact_prefix = '{}-{}-{}'.format(
                runtime,
                ','.join(self.dpkg_archs),
                self.runtime_branch,
            )
            sources_prefix = artifact_prefix + '-sources'

            if not source_required:
                source_required = [
                    os.path.join(
                        self.build_area,
                        'base-{}-{}.source-required.txt'.format(
                            self.apt_suite,
                            ','.join(self.dpkg_archs),
                        ),
                    ),
                    os.path.join(
                        self.build_area,
                        artifact_prefix + '.source-required.txt',
                    ),
                ]

            # Concatenate all the required sources
            with open(
                os.path.join(scratch, 'source-required.txt'),
                'w',
            ) as writer:
                for path in source_required:
                    with open(path) as reader:
                        for line in reader:
                            writer.write(line)

            argv = [
                'debos',
                '--artifactdir={}'.format(self.build_area),
                '--scratchsize=8G',
                '-t', 'architecture:{}'.format(self.primary_dpkg_arch),
                '-t', 'flatpak_arch:{}'.format(self.flatpak_arch),
                '-t', 'suite:{}'.format(self.apt_suite),
                '-t', 'ospack:{}'.format(tarball),
                '-t', 'artifact_prefix:{}'.format(artifact_prefix),
                '-t', 'runtime:{}'.format(runtime),
                '-t', 'runtime_branch:{}'.format(self.runtime_branch),
            ]

            sources_tarball = sources_prefix + '.tar.gz'

            if generate_source_directory:
                os.makedirs(
                    os.path.join(
                        self.build_area,
                        generate_source_directory,
                    ),
                    0o755,
                    exist_ok=True,
                )
                argv.append('-t')
                argv.append(
                    'sources_directory:{}'.format(
                        generate_source_directory,
                    ),
                )

            if generate_source_tarball is None:
                generate_source_tarball = not generate_source_directory

            if generate_source_tarball:
                argv.append('-t')
                argv.append(
                    'sources_tarball:{}'.format(
                        sources_tarball + '.new',
                    ),
                )

            argv.append('-t')
            argv.append('sources_prefix:' + sources_prefix)

            overlay = os.path.join(
                scratch, 'flatpak-overlay',
            )
            self.create_flatpak_manifest_overlay(
                overlay, prefix, runtime, sdk=True,
            )

            argv.append(dest_recipe)
            logger.info('%r', argv)
            subprocess.check_call(argv)

            output = os.path.join(
                self.build_area,
                sources_prefix + '.MISSING.txt',
            )

            if os.path.exists(output) and self.strict:
                raise SystemExit(
                    'Some source code was missing: aborting'
                )

            if generate_source_tarball:
                output = os.path.join(self.build_area, sources_tarball)
                os.rename(output + '.new', output)

                if self.ostree_commit:
                    logger.info(
                        'Committing %s to OSTree', sources_tarball)
                    subprocess.check_call([
                        'time',
                        'ostree',
                        '--repo=' + self.ostree_repo,
                        'commit',
                        '--branch=runtime/{}.Sources/{}/{}'.format(
                            runtime,
                            self.flatpak_arch,
                            self.runtime_branch,
                        ),
                        '--subject=Update',
                        '--tree=tar={}'.format(output),
                        '--fsync=false',
                        '--tar-autocreate-parents',
                        '--add-metadata-string',
                        ('xa.metadata='
                         + self.metadata_sources.to_data()[0]),
                    ])

            if self.ostree_commit:
                # Don't keep the history in this working repository:
                # if history is desired, mirror the commits into a public
                # repository and maintain history there.
                subprocess.check_call([
                    'time',
                    'ostree',
                    '--repo=' + self.ostree_repo,
                    'prune',
                    '--refs-only',
                    '--depth=1',
                ])

                subprocess.check_call([
                    'time',
                    'flatpak',
                    'build-update-repo',
                    self.ostree_repo,
                ])

    def ensure_local_repo(self):
        # type: () -> None
        os.makedirs(os.path.dirname(self.ostree_repo), 0o755, exist_ok=True)
        subprocess.check_call([
            'ostree',
            '--repo=' + self.ostree_repo,
            'init',
            '--mode={}'.format(self.ostree_mode),
        ])

    def escape_variant_id(self, variant_id):
        # type: (str) -> str
        """
        Return a version of the variant_id that fits in the restricted
        character set documented in os-release(5).
        """
        buf = bytearray(variant_id.lower(), 'ascii', 'replace')

        for i, b in enumerate(buf):
            c = chr(b)

            if not c.isalnum() and c not in '._-':
                buf[i] = ord('_')

        return buf.decode('ascii')

    def get_runtime_packages(
        self,
        descriptors,        # type: typing.Iterable[typing.Any]
        multiarch=False
    ):
        # type: (...) -> typing.Iterable[str]

        for d in descriptors:
            if isinstance(d, dict):
                assert len(d) == 1
                p = next(iter(d))
                details = d[p]
            else:
                assert isinstance(d, str)
                p = d
                details = {}

            if (
                details.get('debug_symbols', False)
                and not self.debug_symbols
            ):
                continue

            if details.get('multiarch', multiarch):
                for a in self.dpkg_archs:
                    yield p + ':' + a
            else:
                yield p

    def command_runtimes(
        self,
        *,
        yaml_file,                          # type: str
        ddeb_directory='',
        ddeb_include_executables=False,
        dbgsym_tarball=None,
        generate_source_directory='',
        generate_source_tarball=True,
        generate_platform_sysroot_tarball=False,
        generate_sdk_sysroot_tarball=False,
        **kwargs
    ):
        # type: (...) -> None
        if self.ostree_commit:
            self.ensure_local_repo()

        if self.runtime_branch is None:
            self.runtime_branch = self.apt_suite

        with open(yaml_file, encoding='utf-8') as reader:
            self.runtime_details = yaml.safe_load(reader)

        tarball = 'base-{}-{}.tar.gz'.format(
            self.apt_suite,
            ','.join(self.dpkg_archs),
        )
        source_required = 'base-{}-{}.source-required.txt'.format(
            self.apt_suite,
            ','.join(self.dpkg_archs),
        )

        with ExitStack() as stack:
            scratch = stack.enter_context(
                TemporaryDirectory(prefix='flatdeb.')
            )
            self.ensure_build_area()

            dest_recipe = os.path.join(scratch, 'flatdeb.yaml')
            shutil.copyfile(_DEBOS_RUNTIMES_RECIPE, dest_recipe)

            for helper in (
                'apt-install',
                'clean-up-base',
                'clean-up-before-pack',
                'collect-dbgsym',
                'collect-source-code',
                'dbgsym-use-build-id',
                'disable-services',
                'list-required-source-code',
                'make-flatpak-friendly',
                'platformize',
                'prepare-runtime',
                'purge-conffiles',
                'put-ldconfig-in-path',
                'set-build-id',
                'symlink-alternatives',
                'unpack-dbgsym',
                'usrmerge',
                'write-manifest',
            ):
                dest = os.path.join(scratch, helper)
                shutil.copyfile(
                    os.path.join(
                        os.path.dirname(__file__),
                        'flatdeb',
                        helper,
                    ),
                    dest,
                )
                os.chmod(dest, 0o755)

            prefix = self.runtime_details['id_prefix']

            # Do the Platform first, because we download its source
            # packages as part of preparing the Sdk
            for sdk in (False, True):
                if sdk and not self.do_sdk:
                    continue

                if not sdk and not self.do_platform:
                    continue

                packages = list(self.get_runtime_packages(
                    self.runtime_details.get('add_packages', [])
                ))
                packages.extend(self.get_runtime_packages(
                    self.runtime_details.get('add_packages_multiarch', []),
                    multiarch=True,
                ))

                if sdk:
                    runtime = prefix + '.Sdk'
                else:
                    runtime = prefix + '.Platform'

                artifact_prefix = '{}-{}-{}'.format(
                    runtime,
                    ','.join(self.dpkg_archs),
                    self.runtime_branch,
                )
                ostree_prefix = artifact_prefix + '-runtime'
                out_tarball = ostree_prefix + '.tar.gz'
                sources_prefix = artifact_prefix + '-sources'
                sysroot_prefix = None       # type: typing.Optional[str]
                sysroot_tarball = None      # type: typing.Optional[str]

                argv = [
                    'debos',
                    '--artifactdir={}'.format(self.build_area),
                    '--scratchsize=8G',
                    '-t', 'architecture:{}'.format(self.primary_dpkg_arch),
                    '-t', 'foreignarchs:{}'.format(
                        ' '.join(self.dpkg_archs[1:]),
                    ),
                    '-t', 'flatpak_arch:{}'.format(self.flatpak_arch),
                    '-t', 'suite:{}'.format(self.apt_suite),
                    '-t', 'ospack:{}'.format(tarball),
                    '-t', 'ospack_source_required:{}'.format(source_required),
                    '-t', 'artifact_prefix:{}'.format(artifact_prefix),
                    '-t', 'ostree_prefix:{}'.format(ostree_prefix),
                    '-t', 'ostree_tarball:{}'.format(out_tarball + '.new'),
                    '-t', 'runtime:{}'.format(runtime),
                    '-t', 'runtime_branch:{}'.format(self.runtime_branch),
                    '-t', 'strip_source_version_suffix:{}'.format(
                        self.strip_source_version_suffix),
                ]

                if self.apt_debug:
                    argv.append('-t')
                    argv.append('apt_debug:true')

                if self.build_id is not None:
                    argv.append('-t')
                    argv.append('build_id:{}'.format(self.build_id))

                if sdk:
                    variant_name = self.sdk_variant_name
                    variant_id = self.sdk_variant_id

                    if variant_name is None and self.variant_name is not None:
                        variant_name = self.variant_name + ' (SDK)'
                else:
                    variant_name = self.variant_name
                    variant_id = self.variant_id

                if variant_name is None:
                    variant_name = artifact_prefix

                if variant_id is None:
                    variant_id = artifact_prefix

                argv.append('-t')
                argv.append('variant:{}'.format(variant_name))
                argv.append('-t')
                argv.append('variant_id:{}'.format(
                    self.escape_variant_id(variant_id)
                ))

                if packages:
                    logger.info('Installing packages:')
                    packages.sort()

                    for p in packages:
                        logger.info('- %s', p)

                    argv.append('-t')
                    argv.append('packages:{}'.format(
                        self.yaml_dump_one_line(packages)))

                    dest = os.path.join(scratch, 'runtimes', runtime)
                    os.makedirs(dest, 0o755, exist_ok=True)
                    dest = os.path.join(dest, 'packages.yaml')

                    with open(dest, 'w', encoding='utf-8') as writer:
                        yaml.safe_dump(packages, stream=writer)

                script = self.runtime_details.get('post_script', '')

                if script:
                    dest = os.path.join(scratch, 'post_script')

                    with open(dest, 'w', encoding='utf-8') as writer:
                        writer.write('#!/bin/sh\n')
                        writer.write(script)
                        writer.write('\n')

                    os.chmod(dest, 0o755)
                    argv.append('-t')
                    argv.append('post_script:post_script')

                pre_apt_script = self.runtime_details.get('pre_apt_script', '')

                if pre_apt_script:
                    dest = os.path.join(scratch, 'pre_apt_script')

                    with open(dest, 'w', encoding='utf-8') as writer:
                        writer.write('#!/bin/sh\n')
                        writer.write(pre_apt_script)
                        writer.write('\n')

                    os.chmod(dest, 0o755)
                    argv.append('-t')
                    argv.append('pre_apt_script:pre_apt_script')

                if sdk:
                    sources_tarball = sources_prefix + '.tar.gz'

                    debug_prefix = artifact_prefix + '-debug'
                    debug_tarball = debug_prefix + '.tar.gz'

                    if generate_sdk_sysroot_tarball:
                        sysroot_prefix = artifact_prefix + '-sysroot'
                        sysroot_tarball = sysroot_prefix + '.tar.gz'
                        sysroot_mtree = sysroot_prefix + '.mtree.gz'
                        argv.append('-t')
                        argv.append('sysroot_prefix:{}'.format(sysroot_prefix))
                        argv.append('-t')
                        argv.append(
                            'sysroot_tarball:{}'.format(
                                sysroot_tarball + '.new'))

                    if generate_source_directory:
                        os.makedirs(
                            os.path.join(
                                self.build_area,
                                generate_source_directory,
                            ),
                            0o755,
                            exist_ok=True,
                        )
                        argv.append('-t')
                        argv.append(
                            'sources_directory:{}'.format(
                                generate_source_directory))

                    if generate_source_tarball is None:
                        generate_source_tarball = not generate_source_directory

                    if self.collect_source_code and generate_source_tarball:
                        sources_tarball = sources_prefix + '.tar.gz'
                        argv.append('-t')
                        argv.append(
                            'sources_tarball:{}'.format(
                                sources_tarball + '.new'))

                    sdk_details = self.runtime_details.get('sdk', {})
                    argv.append('-t')
                    argv.append('sdk:yes')
                    argv.append('-t')

                    if self.debug_symbols:
                        argv.append('debug_symbols:yes')
                    else:
                        argv.append('debug_symbols:')

                    argv.append('-t')

                    if self.collect_source_code:
                        argv.append('collect_source_code:yes')
                    else:
                        argv.append('collect_source_code:')

                    argv.append('-t')

                    if self.automatic_dbgsym:
                        argv.append('automatic_dbgsym:yes')
                    else:
                        argv.append('automatic_dbgsym:')

                    if ddeb_directory:
                        os.makedirs(
                            os.path.join(
                                self.build_area,
                                ddeb_directory,
                            ),
                            0o755,
                            exist_ok=True,
                        )
                        argv.append('-t')
                        argv.append(
                            'ddeb_directory:{}'.format(
                                ddeb_directory))
                        argv.append('-t')

                        if ddeb_include_executables:
                            argv.append('ddeb_include_executables:yes')
                        else:
                            argv.append('ddeb_include_executables:')

                    if dbgsym_tarball is None:
                        dbgsym_tarball = not ddeb_directory

                    if dbgsym_tarball:
                        argv.append('-t')
                        argv.append('debug_tarball:' + debug_tarball + '.new')

                    argv.append('-t')
                    argv.append('debug_prefix:' + debug_prefix)
                    argv.append('-t')
                    argv.append('sources_prefix:' + sources_prefix)

                    sdk_packages = list(self.get_runtime_packages(
                        sdk_details.get('add_packages', [])
                    ))
                    sdk_packages.extend(self.get_runtime_packages(
                        sdk_details.get('add_packages_multiarch', []),
                        multiarch=True,
                    ))

                    # We probably have this anyway, but we need it for
                    # dpkg-scansources
                    if 'dpkg-dev' not in sdk_packages:
                        sdk_packages.append('dpkg-dev')

                    if sdk_packages:
                        logger.info('Installing extra packages for SDK:')
                        sdk_packages.sort()

                        for p in sdk_packages:
                            logger.info('- %s', p)

                        argv.append('-t')
                        argv.append(
                            'sdk_packages:{}'.format(
                                self.yaml_dump_one_line(sdk_packages)))

                        dest = os.path.join(scratch, 'runtimes', runtime)
                        os.makedirs(dest, 0o755, exist_ok=True)
                        dest = os.path.join(dest, 'sdk_packages.yaml')

                        with open(dest, 'w', encoding='utf-8') as writer:
                            yaml.safe_dump(sdk_packages, stream=writer)

                    script = sdk_details.get('post_script', '')

                    if script:
                        dest = os.path.join(scratch, 'sdk_post_script')

                        with open(dest, 'w', encoding='utf-8') as writer:
                            writer.write('#!/bin/sh\n')
                            writer.write(script)
                            writer.write('\n')

                        os.chmod(dest, 0o755)
                        argv.append('-t')
                        argv.append('sdk_post_script:sdk_post_script')
                else:   # not sdk
                    if generate_platform_sysroot_tarball:
                        sysroot_prefix = artifact_prefix + '-sysroot'
                        sysroot_tarball = sysroot_prefix + '.tar.gz'
                        sysroot_mtree = sysroot_prefix + '.mtree.gz'
                        argv.append('-t')
                        argv.append('sysroot_prefix:{}'.format(sysroot_prefix))
                        argv.append('-t')
                        argv.append(
                            'sysroot_tarball:{}'.format(
                                sysroot_tarball + '.new'))

                    platform_details = self.runtime_details.get('platform', {})
                    script = platform_details.get('post_script', '')

                    if script:
                        dest = os.path.join(scratch, 'platform_post_script')

                        with open(dest, 'w', encoding='utf-8') as writer:
                            writer.write('#!/bin/sh\n')
                            writer.write(script)
                            writer.write('\n')

                        os.chmod(dest, 0o755)
                        argv.append('-t')
                        argv.append(
                            'platform_post_script:platform_post_script')

                overlay = os.path.join(
                    scratch, 'runtimes', runtime, 'flatpak-overlay')
                self.create_flatpak_manifest_overlay(
                    overlay, prefix, runtime, sdk=sdk)
                overlay = os.path.join(
                    scratch, 'runtimes', runtime, 'apt-overlay')
                self.configure_apt(
                    overlay,
                    self.final_apt_sources,
                    self.final_apt_keyrings,
                )

                argv.append(dest_recipe)
                logger.info('%r', argv)
                subprocess.check_call(argv)

                if sdk:
                    output = os.path.join(
                        self.build_area,
                        sources_prefix + '.MISSING.txt',
                    )

                    if self.collect_source_code:
                        if os.path.exists(output) and self.strict:
                            raise SystemExit(
                                'Some source code was missing: aborting'
                            )

                if sysroot_prefix is not None:
                    assert sysroot_tarball is not None
                    assert sysroot_mtree is not None
                    output = os.path.join(self.build_area, sysroot_tarball)
                    os.rename(output + '.new', output)

                    mtree = os.path.join(self.build_area, sysroot_mtree)

                    if self.do_mtree:
                        self.generate_mtree(output, mtree)

                    output = os.path.join(
                        self.build_area, sysroot_prefix + '.Dockerfile')

                    cpp = ['cpp', '-E', '-P']
                    cpp.append(f'-DSYSROOT_TARBALL={sysroot_tarball}')

                    toolbx = self.runtime_details.get('toolbx', False)

                    if sdk:
                        toolbx = sdk_details.get('toolbx', toolbx)
                    else:
                        toolbx = platform_details.get('toolbx', toolbx)

                    if toolbx:
                        cpp.append('-DNOPASSWD')
                        cpp.append('-DTOOLBX')
                    else:
                        cpp.append('-UNOPASSWD')
                        cpp.append('-UTOOLBX')

                    os_release_labels = []      # type: typing.List[str]
                    os_release = os.path.join(
                        self.build_area,
                        artifact_prefix + '.os-release.txt',
                    )

                    with open(os_release, 'r', encoding='utf-8') as reader:
                        for line in reader:
                            assert '=' in line
                            key, value = line.split('=', 1)
                            value = value.rstrip('\n')
                            os_release_labels.append(
                                f'os_release.{key.lower()}={value}'
                            )

                    cpp.append(
                        '-DOS_RELEASE_LABELS=LABEL '
                        + ' '.join(sorted(os_release_labels))
                    )

                    cpp.append(
                        os.path.join(
                            os.path.dirname(__file__), 'flatdeb',
                            'Dockerfile.in',
                        ),
                    )

                    with open(output + '.new', 'wb') as writer:
                        logger.info('%r', cpp)
                        subprocess.run(
                            cpp,
                            check=True,
                            stdout=writer,
                        )

                    os.rename(output + '.new', output)

                if sdk:
                    if self.debug_symbols and dbgsym_tarball:
                        output = os.path.join(self.build_area, debug_tarball)
                        os.rename(output + '.new', output)

                        if self.ostree_commit:
                            logger.info(
                                'Committing %s to OSTree', debug_tarball,
                            )
                            subprocess.check_call([
                                'time',
                                'ostree',
                                '--repo=' + self.ostree_repo,
                                'commit',
                                '--branch=runtime/{}.Debug/{}/{}'.format(
                                    runtime,
                                    self.flatpak_arch,
                                    self.runtime_branch,
                                ),
                                '--subject=Update',
                                '--tree=tar={}'.format(output),
                                '--fsync=false',
                                '--tar-autocreate-parents',
                                '--add-metadata-string',
                                ('xa.metadata='
                                 + self.metadata_debug.to_data()[0]),
                            ])

                    if self.collect_source_code and generate_source_tarball:
                        output = os.path.join(self.build_area, sources_tarball)
                        os.rename(output + '.new', output)

                        if self.ostree_commit:
                            logger.info(
                                'Committing %s to OSTree', sources_tarball)
                            subprocess.check_call([
                                'time',
                                'ostree',
                                '--repo=' + self.ostree_repo,
                                'commit',
                                '--branch=runtime/{}.Sources/{}/{}'.format(
                                    runtime,
                                    self.flatpak_arch,
                                    self.runtime_branch,
                                ),
                                '--subject=Update',
                                '--tree=tar={}'.format(output),
                                '--fsync=false',
                                '--tar-autocreate-parents',
                                '--add-metadata-string',
                                ('xa.metadata='
                                 + self.metadata_sources.to_data()[0]),
                            ])

                output = os.path.join(self.build_area, out_tarball)
                os.rename(output + '.new', output)

                mtree = os.path.join(
                    self.build_area,
                    ostree_prefix + '.mtree.gz')

                if self.do_mtree:
                    self.generate_mtree(output, mtree)

                if self.ostree_commit:
                    logger.info('Committing %s to OSTree', out_tarball)
                    subprocess.check_call([
                        'time',
                        'ostree',
                        '--repo=' + self.ostree_repo,
                        'commit',
                        '--branch=runtime/{}/{}/{}'.format(
                            runtime,
                            self.flatpak_arch,
                            self.runtime_branch,
                        ),
                        '--subject=Update',
                        '--tree=tar={}'.format(output),
                        '--fsync=false',
                        '--tar-autocreate-parents',
                        '--add-metadata-string',
                        'xa.metadata=' + self.metadata.to_data()[0],
                    ])

            if self.ostree_commit:
                # Don't keep the history in this working repository:
                # if history is desired, mirror the commits into a public
                # repository and maintain history there.
                subprocess.check_call([
                    'time',
                    'ostree',
                    '--repo=' + self.ostree_repo,
                    'prune',
                    '--refs-only',
                    '--depth=1',
                ])

                subprocess.check_call([
                    'time',
                    'flatpak',
                    'build-update-repo',
                    self.ostree_repo,
                ])

                if self.export_bundles:
                    for suffix in ('.Platform', '.Sdk'):
                        bundle = '{}-{}-{}.bundle'.format(
                            prefix + suffix,
                            ','.join(self.dpkg_archs),
                            self.runtime_branch,
                        )
                        output = os.path.join(self.build_area, bundle)

                        subprocess.check_call([
                            'time',
                            'flatpak',
                            'build-bundle',
                            '--runtime',
                            self.ostree_repo,
                            output + '.new',
                            prefix + suffix,
                            self.runtime_branch,
                        ])

                        os.rename(output + '.new', output)

    def configure_apt(
        self,
        overlay,        # type: str
        apt_sources,    # type: typing.Iterable[AptSource]
        apt_keyrings,   # type: typing.Iterable[str]
        apt_keyring_prefix='',
    ):
        # type: (...) -> None
        """
        Configure apt. We only do this once, so that all chroots
        created from the same base have their version numbers
        aligned.
        """
        for d in (
            'apt.conf.d',
            'keyrings',
            'sources.list.d',
            'trusted.gpg.d',
        ):
            os.makedirs(
                os.path.join(overlay, 'etc', 'apt', d),
                0o755,
                exist_ok=True,
            )

        with open(
            os.path.join(overlay, 'etc', 'apt', 'sources.list'),
            'w',
            encoding='utf-8'
        ) as writer:
            for source in apt_sources:
                writer.write('{}\n'.format(source))

            for keyring in apt_keyrings:
                if os.path.exists(os.path.join('suites', keyring)):
                    keyring = os.path.join('suites', keyring)
                elif os.path.exists(keyring):
                    pass
                else:
                    raise RuntimeError('Cannot open {}'.format(keyring))

                if self.use_signed_by:
                    keyring_dir = 'keyrings'
                else:
                    keyring_dir = 'trusted.gpg.d'

                shutil.copyfile(
                    os.path.abspath(keyring),
                    os.path.join(
                        overlay,
                        'etc', 'apt', keyring_dir,
                        apt_keyring_prefix + os.path.basename(keyring),
                    ),
                )

    def create_flatpak_manifest_overlay(
        self,
        overlay,        # type: str
        prefix,         # type: str
        runtime,        # type: str
        sdk=False,
    ):
        # type: (...) -> None
        metadata = os.path.join(overlay, 'metadata')
        os.makedirs(os.path.dirname(metadata), 0o755, exist_ok=True)

        keyfile = self.metadata
        keyfile.set_string('Runtime', 'name', runtime)
        keyfile.set_string(
            'Runtime', 'runtime',
            '{}.Platform/{}/{}'.format(
                prefix,
                self.flatpak_arch,
                self.runtime_branch,
            )
        )
        keyfile.set_string(
            'Runtime', 'sdk',
            '{}.Sdk/{}/{}'.format(
                prefix,
                self.flatpak_arch,
                self.runtime_branch,
            )
        )

        keyfile.set_string(
            'Runtime', 'x-flatdeb-sources',
            '{}.Sdk.Sources/{}/{}'.format(
                prefix,
                self.flatpak_arch,
                self.runtime_branch,
            ),
        )

        keyfile.set_string(
            'Environment', 'XDG_DATA_DIRS',
            ':'.join([
                '/app/share', '/usr/share', '/usr/share/runtime/share',
            ]),
        )

        if sdk:
            keyfile.set_string(
                'Extension {}.Sdk.Debug'.format(prefix),
                'directory', 'lib/debug',
            )
            keyfile.set_boolean(
                'Extension {}.Sdk.Debug'.format(prefix),
                'autodelete', True,
            )
            keyfile.set_boolean(
                'Extension {}.Sdk.Debug'.format(prefix),
                'no-autodownload', True,
            )

            keyfile.set_string(
                'Extension {}.Sdk.Sources'.format(prefix),
                'directory', 'runtime/src',
            )
            keyfile.set_boolean(
                'Extension {}.Sdk.Sources'.format(prefix),
                'autodelete', True,
            )
            keyfile.set_boolean(
                'Extension {}.Sdk.Sources'.format(prefix),
                'no-autodownload', True,
            )

        search_path = []

        for arch in self.dpkg_archs:
            search_path.append('/app/lib/{}'.format(
                self.multiarch_tuple(arch)))

        search_path.append('/app/lib')

        keyfile.set_string(
            'Environment', 'LD_LIBRARY_PATH', ':'.join(search_path),
        )

        if True:    # TODO: 'libgstreamer1.0-0' in installed:
            search_path = []

            for arch in self.dpkg_archs:
                search_path.append(
                    '/app/lib/{}/gstreamer-1.0'.format(
                        self.multiarch_tuple(arch)))

            search_path.append('/app/lib/gstreamer-1.0')

            for arch in self.dpkg_archs:
                search_path.append(
                    '/usr/lib/extensions/{}/gstreamer-1.0'.format(
                        self.multiarch_tuple(arch)))

            search_path.append('/usr/lib/extensions/gstreamer-1.0')

            for arch in self.dpkg_archs:
                search_path.append(
                    '/usr/lib/{}/gstreamer-1.0'.format(
                        self.multiarch_tuple(arch)))

            search_path.append('/usr/lib/gstreamer-1.0')

            keyfile.set_string(
                'Environment', 'GST_PLUGIN_SYSTEM_PATH',
                ':'.join(search_path),
            )

        if True:    # TODO: 'libgirepository-1.0-1' in installed:
            search_path = []

            for arch in self.dpkg_archs:
                search_path.append(
                    '/app/lib/{}/girepository-1.0'.format(
                        self.multiarch_tuple(arch)))

            search_path.append('/app/lib/girepository-1.0')

            keyfile.set_string(
                'Environment', 'GI_TYPELIB_PATH',
                ':'.join(search_path),
            )

        keyfile.set_string(
            'Runtime', 'x-flatdeb-version', VERSION,
        )

        if self.build_id is not None:
            keyfile.set_string(
                'Runtime', 'x-flatdeb-build-id', self.build_id,
            )

        for ext, detail in self.runtime_details.get(
                'add-extensions', {}
                ).items():
            group = 'Extension {}'.format(ext)

            os.makedirs(
                os.path.join(
                    overlay, 'usr',
                    detail['directory'],
                ),
                0o755,
                exist_ok=True,
            )

            for k, v in detail.items():
                if isinstance(v, str):
                    keyfile.set_string(group, k, v)
                elif isinstance(v, bool):
                    keyfile.set_boolean(group, k, v)
                else:
                    raise RuntimeError(
                        'Unknown type {} in {}'.format(v, ext))

        keyfile.save_to_file(metadata)

        if sdk:
            metadata = os.path.join(overlay, 'debug', 'metadata')
            os.makedirs(os.path.dirname(metadata), 0o755, exist_ok=True)

            keyfile = self.metadata_debug
            keyfile.set_string('Runtime', 'name', runtime + '.Debug')
            keyfile.set_string(
                'Runtime', 'runtime',
                '{}.Platform/{}/{}'.format(
                    prefix,
                    self.flatpak_arch,
                    self.runtime_branch,
                )
            )
            keyfile.set_string(
                'Runtime', 'sdk',
                '{}.Sdk/{}/{}'.format(
                    prefix,
                    self.flatpak_arch,
                    self.runtime_branch,
                )
            )

            keyfile.set_string(
                'Runtime', 'x-flatdeb-version', VERSION,
            )

            if self.build_id is not None:
                keyfile.set_string(
                    'Runtime', 'x-flatdeb-build-id', self.build_id,
                )

            keyfile.save_to_file(metadata)

            metadata = os.path.join(overlay, 'src', 'metadata')
            os.makedirs(os.path.dirname(metadata), 0o755, exist_ok=True)

            keyfile = self.metadata_sources
            keyfile.set_string('Runtime', 'name', runtime + '.Sources')
            keyfile.set_string(
                'Runtime', 'runtime',
                '{}.Platform/{}/{}'.format(
                    prefix,
                    self.flatpak_arch,
                    self.runtime_branch,
                )
            )
            keyfile.set_string(
                'Runtime', 'sdk',
                '{}.Sdk/{}/{}'.format(
                    prefix,
                    self.flatpak_arch,
                    self.runtime_branch,
                )
            )

            keyfile.set_string(
                'Runtime', 'x-flatdeb-version', VERSION,
            )

            if self.build_id is not None:
                keyfile.set_string(
                    'Runtime', 'x-flatdeb-build-id', self.build_id,
                )

            keyfile.save_to_file(metadata)

    def command_app(
        self,
        *,
        app_branch,         # type: str
        yaml_manifest,      # type: str
        **kwargs
    ):
        # type: (...) -> None

        if not self.ostree_commit:
            logger.error(
                'flatdeb app --no-ostree-commit cannot work')
            raise SystemExit(1)

        self.ensure_local_repo()

        with open(yaml_manifest, encoding='utf-8') as reader:
            manifest = yaml.safe_load(reader)

        if self.runtime_branch is None:
            self.runtime_branch = manifest.get('runtime-version')

        if self.runtime_branch is None:
            self.runtime_branch = self.apt_suite

        self.app_branch = app_branch

        if self.app_branch is None:
            self.app_branch = manifest.get('branch')

        if self.app_branch is None:
            self.app_branch = 'master'

        manifest['branch'] = self.app_branch
        manifest['runtime-version'] = self.runtime_branch

        if self.remote_url is None:
            self.remote_url = 'file://{}'.format(
                urllib.parse.quote(self.ostree_repo))

        with ExitStack() as stack:
            # We assume the build area has xattr support
            self.ensure_build_area()
            self.ensure_local_repo()
            scratch = stack.enter_context(
                TemporaryDirectory(
                    prefix='flatdeb.',
                    dir=os.path.join(self.build_area, 'tmp'),
                )
            )

            os.makedirs(os.path.join(scratch, 'home'), 0o755, exist_ok=True)
            subprocess.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(scratch),
                'flatpak', '--user',
                'remote-add', '--if-not-exists', '--no-gpg-verify',
                'flatdeb',
                '{}'.format(self.remote_url),
            ])
            subprocess.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(scratch),
                'flatpak', '--user',
                'remote-modify', '--no-gpg-verify',
                '--url={}'.format(self.remote_url),
                'flatdeb',
            ])

            for runtime in (manifest['sdk'], manifest['runtime']):
                # This may fail: we might already have it.
                subprocess.call([
                    'env',
                    'XDG_DATA_HOME={}/home'.format(scratch),
                    'flatpak', '--user',
                    'install', '-y', 'flatdeb',
                    '{}/{}/{}'.format(
                        runtime,
                        self.flatpak_arch,
                        self.runtime_branch,
                    ),
                ])
                subprocess.check_call([
                    'env',
                    'XDG_DATA_HOME={}/home'.format(scratch),
                    'flatpak', '--user',
                    'update',
                    '{}/{}/{}'.format(
                        runtime,
                        self.flatpak_arch,
                        self.runtime_branch,
                    ),
                ])

            for module in manifest.get('modules', []):
                if isinstance(module, dict):
                    sources = module.setdefault('sources', [])

                    for source in sources:
                        if 'path' in source:
                            if source.get('type') == 'git':
                                clone = stack.enter_context(
                                    TemporaryDirectory(
                                        prefix='flatdeb-git.',
                                        dir=scratch,
                                    ),
                                )
                                uploader = subprocess.Popen([
                                    'tar',
                                    '-cf-',
                                    '-C', source['path'],
                                    '.',
                                ], stdout=subprocess.PIPE)
                                subprocess.check_call([
                                    'tar',
                                    '-xf-',
                                    '-C', clone,
                                ], stdin=uploader.stdout)
                                uploader.wait()
                                source['path'] = clone
                            else:
                                d = stack.enter_context(
                                    TemporaryDirectory(
                                        prefix='flatdeb-path.',
                                        dir=scratch,
                                    ),
                                )
                                clone = os.path.join(
                                    d, os.path.basename(source['path']),
                                )
                                shutil.copyfile(
                                    source['path'],
                                    clone,
                                )

                                if GLib.file_test(
                                        source['path'],
                                        GLib.FileTest.IS_EXECUTABLE,
                                ):
                                    os.chmod(clone, 0o755)
                                else:
                                    os.chmod(clone, 0o644)

                                source['path'] = clone

                    if 'x-flatdeb-apt-packages' in module:
                        packages = stack.enter_context(
                            TemporaryDirectory(
                                prefix='flatdeb-debs.',
                                dir=scratch,
                            ),
                        )
                        shutil.copy2(
                            os.path.join(
                                os.path.dirname(__file__),
                                'flatdeb',
                                'collect-app-source-code',
                            ),
                            packages
                        )
                        subprocess.check_call([
                            'env',
                            'XDG_DATA_HOME={}/home'.format(scratch),
                            'flatpak', 'run',
                            '--filesystem={}'.format(packages),
                            '--share=network',
                            '--command=/usr/bin/env',
                            '{}/{}/{}'.format(
                                manifest['sdk'],
                                self.flatpak_arch,
                                self.runtime_branch,
                            ),
                            'DEBIAN_FRONTEND=noninteractive',
                            '{}/collect-app-source-code'.format(packages),
                            '--export={}'.format(packages),
                            '--strip-source-version-suffix={}'.format(
                                self.strip_source_version_suffix),
                        ] + module['x-flatdeb-apt-packages'])
                        os.remove(
                            os.path.join(packages, 'collect-app-source-code')
                        )

                        obtained = subprocess.check_output([
                            'sh', '-euc',
                            'cd "$1"\n'
                            'find * -type f -print0 | xargs -0 sha256sum -b\n'
                            '',
                            'sh',   # argv[0]
                            packages,
                        ]).decode('utf-8').splitlines()

                        for line in obtained:
                            sha256, f = line.split(' *', 1)
                            path = '{}/{}'.format(packages, f)

                            sources.append({
                                'dest': (os.path.dirname(f) or '.'),
                                'type': 'file',
                                'sha256': sha256,
                                'url': urllib.parse.urlunsplit((
                                    'file',
                                    '',
                                    urllib.parse.quote(path),
                                    '',
                                    '',
                                ))
                            })

            json_manifest = os.path.join(scratch, manifest['id'] + '.json')
            os.makedirs(
                os.path.join(self.build_area, '.flatpak-builder'),
                exist_ok=True,
            )

            if self.build_area != scratch:
                subprocess.check_call([
                    'ln', '-nsf',
                    os.path.join(self.build_area, '.flatpak-builder'),
                    '{}/'.format(scratch),
                ])

            with open(json_manifest, 'w', encoding='utf-8') as writer:
                json.dump(manifest, writer, indent=2, sort_keys=True)

            subprocess.check_call([
                'env',
                'DEBIAN_FRONTEND=noninteractive',
                'XDG_DATA_HOME={}/home'.format(scratch),
                'sh', '-euc',
                'cd "$1"; shift; exec "$@"',
                'sh',                   # argv[0]
                scratch,                # directory to cd into
                'flatpak-builder',
                '--arch={}'.format(self.flatpak_arch),
                '--repo={}'.format(self.ostree_repo),
                '--bundle-sources',
                os.path.join(scratch, 'workdir'),
                json_manifest,
            ])

            if self.export_bundles:
                bundle = '{}-{}-{}.bundle'.format(
                    manifest['id'],
                    self.flatpak_arch,
                    manifest['branch'],
                )
                output = os.path.join(self.build_area, bundle)
                subprocess.check_call([
                    'time',
                    'env',
                    'XDG_DATA_HOME={}/home'.format(scratch),
                    'flatpak',
                    'build-bundle',
                    self.ostree_repo,
                    output + '.new',
                    manifest['id'],
                    manifest['branch'],
                ])
                os.rename(output + '.new', output)


if __name__ == '__main__':
    if sys.stderr.isatty():
        try:
            import colorlog
        except ImportError:
            logging.basicConfig()
        else:
            formatter = colorlog.ColoredFormatter(
                '%(log_color)s%(levelname)s:%(name)s:%(reset)s %(message)s')
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            logging.getLogger().addHandler(handler)
    else:
        logging.basicConfig()

    logging.getLogger().setLevel(logging.DEBUG)

    try:
        Builder().run_command_line()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as e:
        logger.error('%s', e)
        raise SystemExit(1)
