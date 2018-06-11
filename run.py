#!/usr/bin/python3

# flatdeb — build Flatpak runtimes from Debian packages
#
# Copyright © 2016-2017 Simon McVittie
# Copyright © 2017 Collabora Ltd.
#
# Partially derived from vectis, copyright © 2015-2017 Simon McVittie
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
import json
import logging
import os
import re
import subprocess
import sys
import urllib.parse
from contextlib import ExitStack
from tempfile import TemporaryDirectory

import yaml
from gi.repository import GLib

from flatdeb.worker import HostWorker


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
_DEBOS_RUNTIMES_RECIPE = os.path.join(
    os.path.dirname(__file__), 'flatdeb', 'debos-runtimes.yaml')

class Builder:

    """
    Main object
    """

    __multiarch_tuple_cache = {}

    def __init__(self):
        #: The Debian suite to use
        self.apt_suite = 'stretch'
        #: The Flatpak branch to use for the runtime, or None for apt_suite
        self.runtime_branch = None
        #: The Flatpak branch to use for the app
        self.app_branch = None
        #: The freedesktop.org cache directory
        self.xdg_cache_dir = os.getenv(
            'XDG_CACHE_HOME', os.path.expanduser('~/.cache'))
        #: Where to write output
        self.build_area = os.path.join(
            self.xdg_cache_dir, 'flatdeb',
        )
        self.repo = os.path.join(self.build_area, 'repo')

        self.__dpkg_archs = []
        self.flatpak_arch = None

        self.__primary_dpkg_arch_matches_cache = {}
        self.suite_details = {}
        self.runtime_details = {}
        self.worker = None
        self.host_worker = HostWorker()
        self.ostree_mode = 'archive-z2'
        self.export_bundles = False
        self.sources_required = set()
        self.strip_source_version_suffix = None

        self.logger = logger.getChild('Builder')

    @staticmethod
    def yaml_dump_one_line(data, stream=None):
        return yaml.safe_dump(
            data,
            stream=stream,
            default_flow_style=True,
            width=0xFFFFFFFF,
        ).replace('\n', ' ')

    @staticmethod
    def get_flatpak_arch(arch=None):
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
        """
        The Debian architecture we are building a runtime for, such as
        i386 or amd64.
        """
        return self.__dpkg_archs[0]

    @property
    def dpkg_archs(self):
        """
        The Debian architectures we support via multiarch, such as
        ['amd64', 'i386'].
        """
        return self.__dpkg_archs

    @dpkg_archs.setter
    def dpkg_archs(self, value):
        self.__primary_dpkg_arch_matches_cache = {}
        self.__dpkg_archs = value

    def primary_dpkg_arch_matches(self, arch_spec):
        """
        Return True if arch_spec matches primary_dpkg_arch (or
        equivalently, if primary_dpkg_arch is one of the architectures
        described by arch_spec). For example, any-amd64 matches amd64
        but not i386.
        """
        if arch_spec not in self.__primary_dpkg_arch_matches_cache:
            exit_code = self.worker.call(
                ['dpkg-architecture', '--host-arch', self.primary_dpkg_arch,
                 '--is', arch_spec])
            self.__primary_dpkg_arch_matches_cache[arch_spec] = (exit_code == 0)

        return self.__primary_dpkg_arch_matches_cache[arch_spec]

    def run_command_line(self):
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
        parser.add_argument('--repo', default=self.repo)
        parser.add_argument('--suite', '-d', default=self.apt_suite)
        parser.add_argument('--architecture', '--arch', '-a')
        parser.add_argument('--runtime-branch', default=self.runtime_branch)
        subparsers = parser.add_subparsers(dest='command', metavar='command')

        subparser = subparsers.add_parser(
            'base',
            help='Build a fresh base tarball',
        )

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

        if args.chdir is not None:
            os.chdir(args.chdir)

        self.build_area = args.build_area
        self.apt_suite = args.suite
        self.runtime_branch = args.runtime_branch
        self.repo = args.repo
        self.export_bundles = args.export_bundles
        self.ostree_mode = args.ostree_mode
        self.worker = HostWorker()

        if args.architecture is None:
            self.dpkg_archs = [
                self.worker.check_output(
                    ['dpkg-architecture', '-q', 'DEB_HOST_ARCH'],
                ).decode('utf-8').rstrip('\n')
            ]
        else:
            self.dpkg_archs = args.architecture.split(',')

        self.flatpak_arch = self.dpkg_to_flatpak_arch(self.primary_dpkg_arch)

        os.makedirs(self.build_area, exist_ok=True)
        os.makedirs(os.path.dirname(self.repo), exist_ok=True)

        if args.command is None:
            parser.error('A command is required')

        with open(
                os.path.join('suites', self.apt_suite + '.yaml'),
                encoding='utf-8') as reader:
            self.suite_details = yaml.safe_load(reader)

        self.strip_source_version_suffix = self.suite_details.get(
            'strip_source_version_suffix', '')

        getattr(
            self, 'command_' + args.command.replace('-', '_'))(**vars(args))

    def command_print_flatpak_architecture(self, **kwargs):
        print(self.flatpak_arch)

    @property
    def apt_uris(self):
        for source in self.suite_details['sources']:
            yield source['apt_uri']

    def ensure_build_area(self):
        self.worker.check_call([
            'sh', '-euc',
            'mkdir -p "${XDG_CACHE_HOME:="$HOME/.cache"}/flatdeb"',
        ])

    def command_base(self, **kwargs):
        with ExitStack() as stack:
            stack.enter_context(self.worker)
            self.ensure_build_area()

            apt_suite = self.suite_details['sources'][0].get(
                'apt_suite', self.apt_suite)

            dest_recipe = '{}/{}'.format(
                self.worker.scratch,
                'flatdeb.yaml',
            )
            self.worker.install_file(_DEBOS_BASE_RECIPE, dest_recipe)

            for helper in (
                'add-foreign-architectures',
                'clean-up-base',
                'clean-up-before-pack',
                'disable-services',
                'usrmerge',
            ):
                dest = '{}/{}'.format(
                    self.worker.scratch,
                    helper,
                )
                self.worker.install_file(
                    os.path.join(
                        os.path.dirname(__file__),
                        'flatdeb',
                        helper,
                    ),
                    dest,
                    permissions=0o755,
                )

            self.worker.check_call([
                'mkdir', '-p',
                '{}/suites/{}/overlay/etc/apt/trusted.gpg.d'.format(
                    self.worker.scratch,
                    apt_suite,
                ),
            ])

            tarball = 'base-{}-{}.tar.gz'.format(
                self.apt_suite,
                ','.join(self.dpkg_archs),
            )
            output = os.path.join(self.build_area, tarball)

            script = self.suite_details.get('debootstrap_script')

            if script is not None:
                # TODO: flatdeb has historically used a configurable
                # debootstrap_script, but debos doesn't support scripts other
                # than 'unstable'. Does the Debian script work for precise and
                # produce the same results as the 'precise' script?
                # https://github.com/go-debos/debos/issues/16
                logger.debug(
                    'Ignoring /usr/share/debootstrap/scripts/%s', script)

            self.configure_apt(
                '{}/suites/{}/overlay'.format(self.worker.scratch, apt_suite))

            argv = [
                'debos',
                '--artifactdir={}'.format(self.build_area),
                '-t', 'architecture:{}'.format(self.primary_dpkg_arch),
                '-t', 'suite:{}'.format(apt_suite),
                '-t', 'mirror:{}'.format(
                    self.suite_details['sources'][0]['apt_uri'],
                ),
                '-t', 'ospack:{}'.format(tarball + '.new'),
                '-t', 'foreignarchs:{}'.format(
                    ' '.join(self.dpkg_archs[1:]),
                ),
                '-t', 'mergedusr:{}'.format(
                    str(
                        self.suite_details.get('can_merge_usr', False),
                    ).lower(),
                ),
            ]

            keyring = self.suite_details['sources'][0].get('keyring')

            if keyring is not None:
                if os.path.exists(os.path.join('suites', keyring)):
                    keyring = os.path.join('suites', keyring)
                elif os.path.exists(keyring):
                    pass
                else:
                    raise RuntimeError('Cannot open {}'.format(keyring))

                dest = '{}/suites/{}/overlay/etc/apt/trusted.gpg.d/{}'.format(
                    self.worker.scratch,
                    apt_suite,
                    os.path.basename(keyring),
                )
                self.worker.install_file(os.path.abspath(keyring), dest)

                argv.append('-t')
                argv.append(
                    'keyring:suites/{}/overlay/etc/apt/trusted.gpg.d/{}'.format(
                        apt_suite,
                        os.path.basename(keyring),
                    )
                )
            else:
                keyring = ''

            components = self.suite_details.get('apt_components', ['main'])

            if components:
                argv.append('-t')
                argv.append('components:{}'.format(
                    self.yaml_dump_one_line(components)))

            argv.append(dest_recipe)
            self.worker.check_call(argv)

            os.rename(output + '.new', output)

    def ensure_local_repo(self):
        self.host_worker.check_call([
            'install',
            '-d',
            os.path.dirname(self.repo),
        ])
        self.host_worker.check_call([
            'ostree',
            '--repo=' + self.repo,
            'init',
            '--mode={}'.format(self.ostree_mode),
        ])

    def command_runtimes(self, *, yaml_file, **kwargs):
        self.ensure_local_repo()

        if self.runtime_branch is None:
            self.runtime_branch = self.apt_suite

        with open(yaml_file, encoding='utf-8') as reader:
            self.runtime_details = yaml.safe_load(reader)

        tarball = 'base-{}-{}.tar.gz'.format(
            self.apt_suite,
            ','.join(self.dpkg_archs),
        )

        with ExitStack() as stack:
            stack.enter_context(self.worker)
            self.ensure_build_area()

            dest_recipe = '{}/{}'.format(
                self.worker.scratch,
                'flatdeb.yaml',
            )
            self.worker.install_file(_DEBOS_RUNTIMES_RECIPE, dest_recipe)

            for helper in (
                'apt-install',
                'clean-up-base',
                'collect-source-code',
                'disable-services',
                'hard-link-alternatives',
                'make-flatpak-friendly',
                'platformize',
                'prepare-runtime',
                'put-ldconfig-in-path',
                'usrmerge',
                'write-manifest',
            ):
                dest = '{}/{}'.format(
                    self.worker.scratch,
                    helper,
                )
                self.worker.install_file(
                    os.path.join(
                        os.path.dirname(__file__),
                        'flatdeb',
                        helper,
                    ),
                    dest,
                    permissions=0o755,
                )

            prefix = self.runtime_details['id_prefix']

            # Do the Platform first, because we download its source
            # packages as part of preparing the Sdk
            for sdk in (False, True):
                packages = list(self.runtime_details.get('add_packages', []))

                for p in self.runtime_details.get('add_packages_multiarch', []):
                    for a in self.dpkg_archs:
                        packages.append(p + ':' + a)

                if sdk:
                    runtime = prefix + '.Sdk'
                else:
                    runtime = prefix + '.Platform'

                out_tarball = '{}-ostree-{}-{}.tar.gz'.format(
                    runtime,
                    self.flatpak_arch,
                    self.runtime_branch,
                )

                argv = [
                    'debos',
                    '--artifactdir={}'.format(self.build_area),
                    '--scratchsize=8G',
                    '-t', 'architecture:{}'.format(self.primary_dpkg_arch),
                    '-t', 'flatpak_arch:{}'.format(self.flatpak_arch),
                    '-t', 'suite:{}'.format(self.apt_suite),
                    '-t', 'ospack:{}'.format(tarball),
                    '-t', 'ostree_tarball:{}'.format(out_tarball + '.new'),
                    '-t', 'runtime:{}'.format(runtime),
                    '-t', 'runtime_branch:{}'.format(self.runtime_branch),
                    '-t', 'strip_source_version_suffix:{}'.format(
                        self.strip_source_version_suffix),
                    '-t', 'repo:repo',
                ]

                if packages:
                    logger.info('Installing packages:')
                    packages.sort()

                    for p in packages:
                        logger.info('- %s', p)

                    argv.append('-t')
                    argv.append('packages:{}'.format(
                        self.yaml_dump_one_line(packages)))

                    dest = '{}/runtimes/{}'.format(
                        self.worker.scratch,
                        runtime,
                    )
                    subprocess.check_call([
                        'install', '-d', dest,
                    ])
                    dest = dest + '/packages.yaml'

                    with open(dest, 'w', encoding='utf-8') as writer:
                        yaml.safe_dump(packages, stream=writer)

                script = self.runtime_details.get('post_script', '')

                if script:
                    dest = '{}/{}'.format(
                        self.worker.scratch,
                        'post_script',
                    )

                    with open(dest, 'w', encoding='utf-8') as writer:
                        writer.write('#!/bin/sh\n')
                        writer.write(script)
                        writer.write('\n')

                    os.chmod(dest, 0o755)
                    argv.append('-t')
                    argv.append('post_script:post_script')

                if sdk:
                    sources_tarball = '{}-sources-{}-{}.tar.gz'.format(
                        runtime,
                        self.flatpak_arch,
                        self.runtime_branch,
                    )

                    sdk_details = self.runtime_details.get('sdk', {})
                    sdk_packages = list(sdk_details.get('add_packages', []))
                    argv.append('-t')
                    argv.append('sdk:yes')
                    argv.append('-t')
                    argv.append('sources_tarball:' + sources_tarball + '.new')

                    for p in sdk_details.get('add_packages_multiarch', []):
                        for a in self.dpkg_archs:
                            sdk_packages.append(p + ':' + a)

                    if sdk_packages:
                        logger.info('Installing extra packages for SDK:')
                        sdk_packages.sort()

                        for p in sdk_packages:
                            logger.info('- %s', p)

                        argv.append('-t')
                        argv.append(
                            'sdk_packages:{}'.format(
                                self.yaml_dump_one_line(sdk_packages)))

                        dest = '{}/runtimes/{}'.format(
                            self.worker.scratch,
                            runtime,
                        )
                        subprocess.check_call([
                            'install', '-d', dest,
                        ])
                        dest = dest + '/sdk_packages.yaml'

                        with open(dest, 'w', encoding='utf-8') as writer:
                            yaml.safe_dump(sdk_packages, stream=writer)

                    script = sdk_details.get('post_script', '')

                    if script:
                        dest = '{}/{}'.format(
                            self.worker.scratch,
                            'sdk_post_script',
                        )

                        with open(dest, 'w', encoding='utf-8') as writer:
                            writer.write('#!/bin/sh\n')
                            writer.write(script)
                            writer.write('\n')

                        os.chmod(dest, 0o755)
                        argv.append('-t')
                        argv.append('sdk_post_script:sdk_post_script')
                else:   # not sdk
                    platform_details = self.runtime_details.get('platform', {})
                    script = platform_details.get('post_script', '')

                    if script:
                        dest = '{}/{}'.format(
                            self.worker.scratch,
                            'platform_post_script',
                        )

                        with open(dest, 'w', encoding='utf-8') as writer:
                            writer.write('#!/bin/sh\n')
                            writer.write(script)
                            writer.write('\n')

                        os.chmod(dest, 0o755)
                        argv.append('-t')
                        argv.append('platform_post_script:platform_post_script')

                self.create_flatpak_manifest_overlay(prefix, runtime, sdk=sdk)

                argv.append(dest_recipe)
                self.worker.check_call(argv)

                if sdk:
                    output = os.path.join(self.build_area, sources_tarball)
                    os.rename(output + '.new', output)

                output = os.path.join(self.build_area, out_tarball)
                os.rename(output + '.new', output)

            # Don't keep the history in this working repository:
            # if history is desired, mirror the commits into a public
            # repository and maintain history there.
            self.worker.check_call([
                'time',
                'ostree',
                '--repo=' + self.repo,
                'prune',
                '--refs-only',
                '--depth=1',
            ])

            self.worker.check_call([
                'time',
                'flatpak',
                'build-update-repo',
                self.repo,
            ])

            if self.export_bundles:
                for suffix in ('.Platform', '.Sdk'):
                    bundle = '{}-{}-{}.bundle'.format(
                        prefix + suffix,
                        self.flatpak_arch,
                        self.runtime_branch,
                    )
                    output = os.path.join(self.build_area, bundle)

                    self.worker.check_call([
                        'time',
                        'flatpak',
                        'build-bundle',
                        '--runtime',
                        self.repo,
                        output + '.new',
                        prefix + suffix,
                        self.runtime_branch,
                    ])

                    os.rename(output + '.new', output)

    def configure_apt(self, overlay):
        """
        Configure apt. We only do this once, so that all chroots
        created from the same base have their version numbers
        aligned.
        """
        with TemporaryDirectory(prefix='flatdeb-apt.') as t:
            # Set up the apt sources

            to_copy = os.path.join(t, 'sources.list')

            with open(to_copy, 'w', encoding='utf-8') as writer:
                for source in self.suite_details['sources']:
                    suite = source.get('apt_suite', self.apt_suite)
                    suite = suite.replace('*', self.apt_suite)
                    components = source.get(
                        'apt_components',
                        self.suite_details.get(
                            'apt_components',
                            ['main']))

                    options = []

                    if source.get('apt_trusted', False):
                        options.append('trusted=yes')

                    if options:
                        options_str = ' [' + ' '.join(options) + ']'
                    else:
                        options_str = ''

                    for prefix in ('deb', 'deb-src'):
                        writer.write('{}{} {} {} {}\n'.format(
                            prefix,
                            options_str,
                            source['apt_uri'],
                            suite,
                            ' '.join(components),
                        ))

                    keyring = source.get('keyring')

                    if keyring is not None:
                        if os.path.exists(os.path.join('suites', keyring)):
                            keyring = os.path.join('suites', keyring)
                        elif os.path.exists(keyring):
                            pass
                        else:
                            raise RuntimeError('Cannot open {}'.format(keyring))

                        self.worker.install_file(
                            os.path.abspath(keyring),
                            '{}/etc/apt/trusted.gpg.d/{}'.format(
                                overlay,
                                os.path.basename(keyring),
                            ),
                        )

            self.worker.install_file(
                to_copy,
                '{}/etc/apt/sources.list'.format(overlay),
            )

    def create_flatpak_manifest_overlay(self, prefix, runtime, sdk=False):
        overlay = '{}/runtimes/{}/overlay'.format(
            self.worker.scratch,
            runtime,
        )

        with TemporaryDirectory(prefix='flatdeb-ostreeify.') as t:
            metadata = os.path.join(t, 'metadata')

            keyfile = GLib.KeyFile()
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

            search_path = []

            for arch in self.dpkg_archs:
                search_path.append('/app/lib/{}'.format(self.multiarch_tuple(arch)))

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

            for ext, detail in self.runtime_details.get(
                    'add-extensions', {}
                    ).items():
                group = 'Extension {}'.format(ext)

                self.worker.check_call([
                    'install', '-d',
                    '{}/ostree/main/files/{}'.format(
                        overlay, detail['directory']),
                ])

                for k, v in detail.items():
                    if isinstance(v, str):
                        keyfile.set_string(group, k, v)
                    elif isinstance(v, bool):
                        keyfile.set_boolean(group, k, v)
                    else:
                        raise RuntimeError(
                            'Unknown type {} in {}'.format(v, ext))

            keyfile.save_to_file(metadata)

            self.worker.check_call([
                'install', '-d', '{}/ostree/main'.format(overlay),
            ])
            self.worker.install_file(
                metadata,
                '{}/ostree/main/metadata'.format(overlay),
            )

        if sdk:
            with TemporaryDirectory(prefix='flatdeb-ostreeify.') as t:
                metadata = os.path.join(t, 'metadata')

                keyfile = GLib.KeyFile()
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

                keyfile.save_to_file(metadata)

                self.worker.check_call([
                    'install', '-d', '{}/ostree/source'.format(overlay),
                ])
                self.worker.install_file(
                    metadata,
                    '{}/ostree/source/metadata'.format(overlay),
                )

    def command_app(self, *, app_branch, yaml_manifest, **kwargs):
        self.worker.require_extended_attributes()
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

        with ExitStack() as stack:
            stack.enter_context(self.worker)
            self.ensure_build_area()
            self.ensure_local_repo()
            t = stack.enter_context(
                TemporaryDirectory(prefix='flatpak-app.')
            )

            self.worker.check_call([
                'mkdir', '-p', '{}/home'.format(self.worker.scratch),
            ])

            self.worker.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
                'flatpak', '--user',
                'remote-add', '--if-not-exists', '--no-gpg-verify',
                'flatdeb',
                'http://192.168.122.1:3142/local/flatdeb/repo',
            ])
            self.worker.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
                'flatpak', '--user',
                'remote-modify', '--no-gpg-verify',
                '--url=http://192.168.122.1:3142/local/flatdeb/repo',
                'flatdeb',
            ])

            for runtime in (manifest['sdk'], manifest['runtime']):
                # This may fail: we might already have it.
                self.worker.call([
                    'env',
                    'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
                    'flatpak', '--user',
                    'install', 'flatdeb',
                    '{}/{}/{}'.format(
                        runtime,
                        self.flatpak_arch,
                        self.runtime_branch,
                    ),
                ])
                self.worker.check_call([
                    'env',
                    'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
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
                                clone = self.worker.check_output([
                                    'mktemp', '-d',
                                    '-p', self.worker.scratch,
                                    'flatdeb-git.XXXXXX',
                                ]).decode('utf-8').rstrip('\n')
                                uploader = self.host_worker.Popen([
                                    'tar',
                                    '-cf-',
                                    '-C', source['path'],
                                    '.',
                                ], stdout=subprocess.PIPE)
                                self.worker.check_call([
                                    'tar',
                                    '-xf-',
                                    '-C', clone,
                                ], stdin=uploader.stdout)
                                uploader.wait()
                                source['path'] = clone
                            else:
                                d = self.worker.check_output([
                                    'mktemp', '-d',
                                    '-p', self.worker.scratch,
                                    'flatdeb-path.XXXXXX',
                                ]).decode('utf-8').rstrip('\n')
                                clone = '{}/{}'.format(
                                    d, os.path.basename(source['path']),
                                )

                                permissions = 0o644

                                if GLib.file_test(
                                        source['path'],
                                        GLib.FileTest.IS_EXECUTABLE,
                                ):
                                    permissions = 0o755

                                self.worker.install_file(
                                    source['path'],
                                    clone,
                                    permissions,
                                )
                                source['path'] = clone

                    if 'x-flatdeb-apt-packages' in module:
                        packages = self.worker.check_output([
                            'mktemp', '-d',
                            '-p', self.worker.scratch,
                            'flatdeb-debs.XXXXXX',
                        ]).decode('utf-8').rstrip('\n')

                        self.worker.check_call([
                            'env',
                            'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
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
                            'http_proxy=http://192.168.122.1:3142',
                            'export={}'.format(packages),
                            'sh',
                            '-euc',

                            'cp -a /usr/var /\n'
                            'install -d /var/cache/apt/archives/partial\n'
                            'fakeroot apt-get update\n'
                            'fakeroot apt-get -y --download-only \\\n'
                            '    --no-install-recommends install "$@"\n'
                            'for x in /var/cache/apt/archives/*.deb; do\n'
                            '    package="$(dpkg-deb -f "$x" Package)"\n'
                            '    source="$(dpkg-deb -f "$x" Source)"\n'
                            '    bu="$(dpkg-deb -f "$x" Built-Using)"\n'
                            '    version="$(dpkg-deb -f "$x" Version)"\n'
                            '    if [ -z "$source" ]; then\n'
                            '        source="$package"\n'
                            '    fi\n'
                            '    if [ "${source% (*}" != "$source" ]; then\n'
                            '        version="${source#* (}"\n'
                            '        version="${version%)}"\n'
                            '        source="${source% (*}"\n'
                            '    fi\n'
                            '    ( cd "$export" && \\\n'
                            '         apt-get -y --download-only \\\n'
                            '         -oAPT::Get::Only-Source=true source \\\n'
                            '         "$source=$version"\n'
                            '    )\n'
                            '    if [ -n "$bu" ]; then\n'
                            '        oldIFS="$IFS"\n'
                            '        IFS=","\n'
                            '        for dep in $bu; do\n'
                            '            bu="$(echo "$bu" | tr -d " ")"\n'
                            '            version="${bu#*(=}"\n'
                            '            version="${version%)}"\n'
                            '            source="${bu%(*}"\n'
                            '            ( cd "$export" && \\\n'
                            '                 apt-get -y --download-only \\\n'
                            '                 -oAPT::Get::Only-Source=true \\\n'
                            '                 source "$source=$version"\n'
                            '            )\n'
                            '        done\n'
                            '        IFS="$oldIFS"\n'
                            '    fi\n'
                            'done\n'
                            'mv /var/cache/apt/archives/*.deb "$export"\n'
                            'mv /var/lib/apt/lists "$export"\n'
                            '',

                            'sh',   # argv[0]
                        ] + module['x-flatdeb-apt-packages'])

                        obtained = self.worker.check_output([
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

            remote_manifest = '{}/{}.json'.format(
                self.worker.scratch,
                manifest['id'],
            )

            self.worker.check_call([
                'mkdir', '-p',
                '{}/.flatpak-builder'.format(self.build_area),
            ])
            if self.build_area != self.worker.scratch:
                self.worker.check_call([
                    'ln', '-nsf',
                    '{}/.flatpak-builder'.format(self.build_area),
                    '{}/'.format(self.worker.scratch),
                ])

            with TemporaryDirectory(prefix='flatdeb-manifest.') as t:
                json_manifest = os.path.join(t, manifest['id'] + '.json')

                with open(
                        json_manifest, 'w', encoding='utf-8',
                ) as writer:
                    json.dump(manifest, writer, indent=2, sort_keys=True)

                self.worker.install_file(json_manifest, remote_manifest)

            self.worker.check_call([
                'env',
                'DEBIAN_FRONTEND=noninteractive',
                'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
                'http_proxy=http://192.168.122.1:3142',
                'sh', '-euc',
                'cd "$1"; shift; exec "$@"',
                'sh',                   # argv[0]
                self.worker.scratch,    # directory to cd into
                'flatpak-builder',
                '--arch={}'.format(self.flatpak_arch),
                '--repo={}'.format(self.repo),
                '--bundle-sources',
                '{}/workdir'.format(self.worker.scratch),
                remote_manifest,
            ])

            if self.export_bundles:
                self.worker.check_call([
                    'time',
                    'env',
                    'XDG_DATA_HOME={}/home'.format(self.worker.scratch),
                    'flatpak',
                    'build-bundle',
                    self.repo,
                    '{}/bundle'.format(self.worker.scratch),
                    manifest['id'],
                    manifest['branch'],
                ])

                bundle = '{}-{}-{}.bundle'.format(
                    manifest['id'],
                    self.flatpak_arch,
                    manifest['branch'],
                )
                output = os.path.join(self.build_area, bundle)

                with open(output + '.new', 'wb') as writer:
                    self.worker.check_call([
                        'cat',
                        '{}/bundle'.format(self.worker.scratch),
                    ], stdout=writer)

                os.rename(output + '.new', output)

if __name__ == '__main__':
    if sys.stderr.isatty():
        try:
            import colorlog
        except ImportError:
            pass
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
