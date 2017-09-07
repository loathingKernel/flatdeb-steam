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

Requires (on host):
    - flatpak
    - ostree
    - python3
    - python3-debian
    - python3-gi
    - python3-yaml
    - sshfs (if worker is remote)

Requires (on worker, possibly the same machine as the host):
    - Debian 9 'stretch'
    - /tmp not a tmpfs, or flatpak >= 0.9.6
    - debootstrap
    - flatpak
    - flatpak-builder
    - ostree
    - sudo
    - systemd-container
    - time
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import urllib.parse
from contextlib import ExitStack, suppress
from tempfile import TemporaryDirectory

import yaml
from gi.repository import GLib

from flatdeb.worker import HostWorker, NspawnWorker, SshWorker, SudoWorker


logger = logging.getLogger('flatdeb')


class Builder:

    """
    Main object
    """

    def __init__(self):
        #: The Debian suite to use
        self.apt_suite = 'stretch'
        #: The Flatpak branch to use for the runtime, or None for apt_suite
        self.runtime_branch = None
        #: The Flatpak branch to use for the app
        self.app_branch = 'master'
        #: The freedesktop.org cache directory
        self.xdg_cache_dir = os.getenv(
            'XDG_CACHE_DIR', os.path.expanduser('~/.cache'))
        self.remote_repo = None
        #: Where to write output
        self.build_area = os.path.join(
            self.xdg_cache_dir, 'flatdeb',
        )
        self.remote_build_area = None
        self.repo = os.path.join(self.build_area, 'repo')

        self.__dpkg_archs = []
        self.flatpak_arch = None

        self.__primary_dpkg_arch_matches_cache = {}
        self.suite_details = {}
        self.runtime_details = {}
        self.root_worker = None
        self.worker = None
        self.host_worker = HostWorker()
        self.remote_ostree_mode = None
        self.ostree_mode = 'archive-z2'
        self.export_bundles = False

        self.logger = logger.getChild('Builder')

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
        parser.add_argument('--remote', default=None)
        parser.add_argument(
            '--ostree-mode', default=self.ostree_mode,
        )
        parser.add_argument(
            '--remote-ostree-mode', default=None,
        )
        parser.add_argument(
            '--export-bundles', action='store_true', default=False,
        )
        parser.add_argument('--build-area', default=self.build_area)
        parser.add_argument('--repo', default=self.repo)
        parser.add_argument('--remote-repo', default=self.remote_repo)
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
        parser.add_argument('--app-branch', default=self.app_branch)
        subparser.add_argument('yaml_manifest')

        subparser = subparsers.add_parser(
            'print-flatpak-architecture',
            help='Print the Flatpak architecture',
        )

        args = parser.parse_args()

        self.build_area = args.build_area
        self.apt_suite = args.suite
        self.runtime_branch = args.runtime_branch
        self.repo = args.repo
        self.remote_repo = args.remote_repo
        self.export_bundles = args.export_bundles
        self.ostree_mode = args.ostree_mode

        if args.remote is not None:
            self.worker = SshWorker(args.remote)

            self.remote_ostree_mode = args.remote_ostree_mode

            if self.remote_ostree_mode is None:
                self.remote_ostree_mode = self.ostree_mode
        else:
            self.worker = HostWorker()
            self.remote_build_area = self.build_area
            self.remote_repo = self.repo
            self.remote_ostree_mode = self.ostree_mode

        self.root_worker = SudoWorker(self.worker)

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

        with open(os.path.join('suites', self.apt_suite + '.yaml')) as reader:
            self.suite_details = yaml.safe_load(reader)

        getattr(
            self, 'command_' + args.command.replace('-', '_'))(**vars(args))

    def command_print_flatpak_architecture(self, **kwargs):
        print(self.flatpak_arch)

    @property
    def apt_uris(self):
        for source in self.suite_details['sources']:
            yield source['apt_uri']

    def ensure_build_area(self):
        if self.remote_build_area is None:
            self.remote_build_area = self.worker.scratch

        if self.remote_repo is None:
            self.remote_repo = '{}/repo'.format(self.worker.scratch)

    def command_base(self, **kwargs):
        with ExitStack() as stack:
            stack.enter_context(self.worker)
            self.ensure_build_area()
            stack.enter_context(self.root_worker)

            base_chroot = '{}/base'.format(self.root_worker.scratch)

            argv = [
                'env',
                'DEBIAN_FRONTEND=noninteractive',
                'http_proxy=http://192.168.122.1:3142',
                'debootstrap',
                '--variant=minbase',
                '--arch={}'.format(self.primary_dpkg_arch),
                '--include=apt-transport-https',
            ]

            if self.suite_details.get('can_merge_usr', False) is True:
                argv.append('--merged-usr')

            keyring = self.suite_details['sources'][0].get('keyring')

            if keyring is not None:
                if os.path.exists(os.path.join('suites', keyring)):
                    keyring = os.path.join('suites', keyring)
                elif os.path.exists(keyring):
                    pass
                else:
                    raise RuntimeError('Cannot open {}'.format(keyring))

                dest = '{}/{}'.format(
                    self.root_worker.scratch,
                    os.path.basename(keyring),
                )
                self.root_worker.install_file(os.path.abspath(keyring), dest)
                argv.append('--keyring=' + dest)

            argv.append(self.suite_details['sources'][0].get(
                'apt_suite', self.apt_suite,
            ))
            argv.append(base_chroot)
            argv.append(self.suite_details['sources'][0]['apt_uri'])

            script = self.suite_details.get('debootstrap_script')

            if script is not None:
                argv.append('/usr/share/debootstrap/scripts/' + script)

            try:
                self.root_worker.check_call(argv)
            except:
                with suppress(Exception):
                    self.root_worker.check_call([
                        'cat',
                        '{}/debootstrap/debootstrap.log'.format(base_chroot),
                    ])
                raise

            self.configure_base(base_chroot)
            self.configure_apt(base_chroot)

            if self.suite_details.get('can_merge_usr', False) == 'after_debootstrap':
                self.usrmerge(base_chroot)

            tarball = 'base-{}-{}.tar.gz'.format(
                self.apt_suite,
                ','.join(self.dpkg_archs),
            )

            self.root_worker.check_call([
                'time',
                'tar', '-zcf', '{}/{}'.format(
                    self.remote_build_area, tarball,
                ),
                '-C', base_chroot,
                '--exclude=./etc/.pwd.lock',
                '--exclude=./etc/group-',
                '--exclude=./etc/passwd-',
                '--exclude=./etc/shadow-',
                '--exclude=./home',
                '--exclude=./root',
                '--exclude=./tmp',
                '--exclude=./var/cache',
                '--exclude=./var/lock',
                '--exclude=./var/tmp',
                '.',
            ])

            if not isinstance(self.worker, HostWorker):
                output = os.path.join(self.build_area, tarball)

                with open(output + '.new', 'wb') as writer:
                    self.root_worker.check_call([
                        'cat',
                        '{}/{}'.format(self.remote_build_area, tarball),
                    ], stdout=writer)

                os.rename(output + '.new', output)

    def ensure_remote_repo(self):
        self.worker.check_call([
            'ostree',
            '--repo=' + self.remote_repo,
            'init',
            '--mode={}'.format(self.remote_ostree_mode),
        ])

    def ensure_local_repo(self):
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

        with open(yaml_file) as reader:
            self.runtime_details = yaml.safe_load(reader)

        tarball = 'base-{}-{}.tar.gz'.format(
            self.apt_suite,
            ','.join(self.dpkg_archs),
        )

        with ExitStack() as stack:
            stack.enter_context(self.worker)
            self.ensure_build_area()
            self.ensure_remote_repo()
            stack.enter_context(self.root_worker)

            base_chroot = '{}/base'.format(self.root_worker.scratch)
            self.root_worker.check_call([
                'install', '-d', base_chroot,
            ])
            self.root_worker.check_call([
                'time',
                'tar', '-zxf',
                '-',
                '-C', base_chroot,
                '.',
            ], stdin=open(os.path.join(self.build_area, tarball), 'rb'))

            # We do common steps for both the Platform and the Sdk
            # in the base directory, then copy it.
            self.configure_base(base_chroot)

            platform_chroot = '{}/platform'.format(self.root_worker.scratch)
            sdk_chroot = '{}/sdk'.format(self.root_worker.scratch)

            self.root_worker.check_call([
                'time',
                'cp', '-a', '--reflink=auto', base_chroot, platform_chroot,
            ])
            self.root_worker.check_call([
                'mv', base_chroot, sdk_chroot,
            ])

            prefix = self.runtime_details['id_prefix']

            self.ostreeify(
                prefix,
                platform_chroot,
            )
            self.ostreeify(
                prefix,
                sdk_chroot,
                sdk=True,
            )

            self.worker.check_call([
                'time',
                'flatpak',
                'build-update-repo',
                self.remote_repo,
            ])

            if self.export_bundles:
                for suffix in ('.Platform', '.Sdk'):
                    self.worker.check_call([
                        'time',
                        'flatpak',
                        'build-bundle',
                        '--runtime',
                        self.remote_repo,
                        '{}/bundle'.format(self.worker.scratch),
                        prefix + suffix,
                        self.runtime_branch,
                    ])

                    bundle = '{}-{}-{}.bundle'.format(
                        prefix + suffix,
                        self.flatpak_arch,
                        self.runtime_branch,
                    )
                    output = os.path.join(self.build_area, bundle)

                    with open(output + '.new', 'wb') as writer:
                        self.worker.check_call([
                            'time',
                            'cat',
                            '{}/bundle'.format(self.worker.scratch),
                        ], stdout=writer)

                        os.rename(output + '.new', output)

    def configure_apt(self, base_chroot):
        """
        Configure apt. We only do this once, so that all chroots
        created from the same base have their version numbers
        aligned.
        """
        with TemporaryDirectory(prefix='flatdeb-apt.') as t:
            # Set up the apt sources

            to_copy = os.path.join(t, 'sources.list')

            with open(to_copy, 'w') as writer:
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

                        self.root_worker.install_file(
                            os.path.abspath(keyring),
                            '{}/etc/apt/trusted.gpg.d/{}'.format(
                                base_chroot,
                                os.path.basename(keyring),
                            ),
                        )

            self.root_worker.install_file(
                to_copy,
                '{}/etc/apt/sources.list'.format(base_chroot),
            )
            self.root_worker.check_call([
                'rm', '-fr',
                '{}/etc/apt/sources.list.d'.format(base_chroot),
            ])

        with NspawnWorker(
            self.root_worker,
            base_chroot,
            env=[
                'DEBIAN_FRONTEND=noninteractive',
                'http_proxy=http://192.168.122.1:3142',
            ],
        ) as nspawn:
            for other_arch in self.dpkg_archs[1:]:
                try:
                    nspawn.check_call([
                        'dpkg', '--add-architecture', other_arch,
                    ])
                except subprocess.CalledProcessError:
                    # Older syntax for Ubuntu precise
                    # https://wiki.debian.org/Multiarch/HOWTO
                    nspawn.check_call([
                        'sh', '-euc',
                        'echo "foreign-architecture $1" > ' +
                        '/etc/dpkg/dpkg.cfg.d/architectures',
                        'sh', # argv[0]
                        other_arch,
                    ])

            nspawn.check_call([
                'apt-get', '-y', '-q', 'update',
            ])
            nspawn.check_call([
                'DEBIAN_FRONTEND=noninteractive',
                'apt-get', '-y', '-q', 'dist-upgrade',
            ])

    def configure_base(self, base_chroot):
        """
        Configure the common chroot that will be copied to make both the
        Platform and the Sdk.
        """

        with TemporaryDirectory(prefix='flatdeb-base-install.') as t:
            # Disable starting services. This container has no init
            # anyway.

            to_copy = os.path.join(t, 'policy-rc.d')

            with open(to_copy, 'w') as writer:
                writer.write('#!/bin/sh\n')
                writer.write('exit 101\n')

            self.root_worker.install_file(
                to_copy,
                '{}/usr/sbin/policy-rc.d'.format(base_chroot),
                permissions=0o755,
            )

            with open(to_copy, 'w') as writer:
                writer.write('#!/bin/sh\n')
                writer.write('exit 0\n')

            self.root_worker.install_file(
                to_copy,
                '{}/sbin/initctl'.format(base_chroot),
                permissions=0o755,
            )
            self.root_worker.install_file(
                to_copy,
                '{}/usr/local/sbin/initctl'.format(base_chroot),
                permissions=0o755,
            )

            with open(to_copy, 'w') as writer:
                writer.write('#!/bin/sh\n')
                writer.write('exit 0\n')

            self.root_worker.install_file(
                to_copy,
                '{}/usr/local/sbin/update-rc.d'.format(base_chroot),
                permissions=0o755,
            )

            # There is some cleanup that we can do in the base
            # tarball rather than in every runtime individually.
            # See https://github.com/debuerreotype/debuerreotype
            # for further ideas.

            to_copy = os.path.join(t, 'flatpak-runtime')

            with open(to_copy, 'w') as writer:
                writer.write('force-unsafe-io\n')

                writer.write('path-exclude /usr/share/doc/*/*\n')
                # For license compliance, we should keep the copyright
                # files intact
                writer.write('path-include /usr/share/doc/*/copyright\n')
                self.root_worker.check_call([
                    'find', '{}/usr/share/doc'.format(base_chroot), '-xdev',
                    '-not', '-name', 'copyright', '-not', '-type', 'd',
                    '-delete'
                ])
                self.root_worker.check_call([
                    'find', '{}/usr/share/doc'.format(base_chroot), '-depth',
                    '-xdev', '-type', 'd', '-empty', '-delete'
                ])

                for d in (
                        'doc-base', 'groff', 'info', 'linda', 'lintian', 'man',
                ):
                    writer.write(
                        'path-exclude /usr/share/{}/*\n'.format(d),
                    )
                    self.root_worker.check_call([
                        'rm', '-fr', '{}/usr/share/{}'.format(base_chroot, d),
                    ])

            self.root_worker.check_call([
                'install', '-d',
                '{}/etc/dpkg/dpkg.cfg.d'.format(base_chroot),
            ])
            self.root_worker.install_file(
                to_copy,
                '{}/etc/dpkg/dpkg.cfg.d/flatpak-runtime'.format(base_chroot),
            )

            to_copy = os.path.join(t, 'flatpak-runtime')

            with open(to_copy, 'w') as writer:
                writer.write('Acquire::Languages "none";\n')
                writer.write('Acquire::GzipIndexes "true";\n')
                writer.write('Acquire::CompressionTypes::Order:: "gz";\n')
                # TODO: This doesn't seem to be working in precise,
                # is it newer?
                writer.write('APT::InstallRecommends "false";\n')
                writer.write(
                    'APT::AutoRemove::SuggestsImportant "false";\n')
                # We rely on autoremove not taking effect immediately
                writer.write('APT::Get::AutomaticRemove "false";\n')
                writer.write('Aptitude::Delete-Unused "false";\n')

            self.root_worker.check_call([
                'install', '-d',
                '{}/etc/apt/apt.conf.d'.format(base_chroot),
            ])
            self.root_worker.install_file(
                to_copy,
                '{}/etc/apt/apt.conf.d/flatpak-runtime'.format(base_chroot),
            )

        if not self.runtime_details:
            return

        with NspawnWorker(
            self.root_worker,
            base_chroot,
            env=[
                'http_proxy=http://192.168.122.1:3142',
                'DEBIAN_FRONTEND=noninteractive',
            ],
        ) as nspawn:
            nspawn.check_call([
                'install', '-d',
                '/var/cache/apt/archives/partial',
                '/var/lock',
            ])

            # We use aptitude to help prepare the Platform runtime, and
            # it's a useful thing to have in the Sdk runtime
            nspawn.check_call([
                'apt-get', '-q', '-y',
                '--no-install-recommends',
                'install', 'aptitude',
            ])

            # All packages will be removed from the platform runtime
            # unless they are Essential, depended-on, or in the
            # add_packages list.
            nspawn.check_call([
                'aptitude', '-y', 'markauto', '?installed'
            ])
            # Ubuntu precise doesn't like apt being up for autoremoval.
            nspawn.check_call([
                'aptitude', '-y', 'unmarkauto', 'apt'
            ])

            packages = list(self.runtime_details.get('add_packages', []))

            for p in self.runtime_details.get('add_packages_multiarch', []):
                for a in self.dpkg_archs:
                    packages.append(p + ':' + a)

            if packages:
                nspawn.check_call([
                    'apt-get', '-q', '-y', 'install',
                    '--no-install-recommends',
                ] + packages)


    def sdkize(self, sdk_chroot):
        """
        Transform a copy of the chroot into a Sdk runtime.
        """
        logger = self.logger.getChild('sdkize')

        sdk_details = self.runtime_details.get('sdk', {})

        with NspawnWorker(
            self.root_worker,
            sdk_chroot,
            env=[
                'http_proxy=http://192.168.122.1:3142',
                'DEBIAN_FRONTEND=noninteractive',
            ],
        ) as nspawn:
            packages = list(sdk_details.get('add_packages', []))

            for p in sdk_details.get('add_packages_multiarch', []):
                for a in self.dpkg_archs:
                    packages.append(p + ':' + a)

            if packages:
                logger.info('Installing extra packages for SDK:')

                for p in sorted(packages):
                    logger.info('- %s', p)

                nspawn.check_call([
                    'apt-get', '-q', '-y', 'install',
                    '--no-install-recommends',
                ] + packages)

            script = sdk_details.get('post_script', [])

            if script:
                logger.info('Running custom SDK script...')
                nspawn.check_call([
                    'sh', '-c', script,
                ])
                logger.info('... done')

            nspawn.write_manifest()
            installed = nspawn.list_packages_ignore_arch()

            logger.info('Packages included in SDK:')

            for p in sorted(installed):
                logger.info('- %s', p)

        return installed

    def platformize(self, platform_chroot):
        """
        Transform a copy of the chroot into a Platform runtime.
        """
        logger = self.logger.getChild('platformize')
        platform_details = self.runtime_details.get('platform', {})

        with NspawnWorker(
            self.root_worker,
            platform_chroot,
            env=[
                'DEBIAN_FRONTEND=noninteractive',
                'SUDO_FORCE_REMOVE=yes',
                'http_proxy=http://192.168.122.1:3142',
            ],
        ) as nspawn:
            # TODO: For the SteamRuntime this removes dbus,
            # libsasl2-modules and python-debian and I have no idea why
            #nspawn.check_call([
            #    'aptitude', '-y', 'purge',
            #    '?and(?installed,?section(devel))',
            #    '?and(?installed,?section(libdevel))',
            #])

            installed = nspawn.list_packages_ignore_arch()

            logger.info('Packages installed at the moment:')

            for p in sorted(installed):
                logger.info('- %s', p)

            unwanted = []

            for package in [
                    'aptitude',
                    'fakeroot',
                    'libfakeroot',
            ]:
                if package in installed:
                    unwanted.append(package)

            if unwanted:
                logger.info('Removing unwanted packages')

                nspawn.check_call([
                    'apt-get', '-y', 'purge',
                ] + unwanted)

            logger.info('Autoremoving packages')
            nspawn.check_call([
                'apt-get', '-y', '--purge', 'autoremove',
            ])

            installed = nspawn.list_packages_ignore_arch()

            logger.info('Packages installed before destroying Essential set:')

            for p in sorted(installed):
                logger.info('- %s', p)

            unwanted = []

            # These are Essential (or at least important) but serve no
            # purpose in an immutable runtime with no init. Note that
            # order is important: adduser needs to be removed before
            # debconf. We remove these particular packages first because
            # they try to invoke other packages we want to remove in
            # their postrm maintainer scripts.
            for package in [
                    'adduser',
                    'apt',
                    'gnupg',
                    'ifupdown',
                    'initramfs-tools',
                    'initramfs-tools-bin',
                    'initscripts',
                    'lsb-base',
                    'module-init-tools',
                    'plymouth',
                    'tcpd',
            ]:
                if package in installed:
                    unwanted.append(package)

            if 'python' not in installed:
                unwanted.append('python-minimal')
                unwanted.append('python2.7-minimal')

            logger.info('Packages we will forcibly remove (first round):')

            for p in sorted(unwanted):
                logger.info('- %s', p)

            if unwanted:
                nspawn.check_call([
                    'dpkg', '--purge', '--force-remove-essential',
                    '--force-depends',
                ] + unwanted)

            # Second round of removals.
            for package in [
                    'busybox-initramfs',
                    'debconf',
                    'debian-archive-keyring',
                    'e2fsprogs',
                    'init',
                    'init-system-helpers',
                    'insserv',
                    'iproute',
                    'login',
                    'mount',
                    'mountall',
                    'passwd',
                    'systemd',
                    'systemd-sysv',
                    'sysv-rc',
                    'ubuntu-archive-keyring',
                    'ubuntu-keyring',
                    'udev',
                    'upstart',
            ]:
                if package in installed:
                    unwanted.append(package)

            if 'perl' not in installed:
                unwanted.append('perl-base')

            logger.info('Packages we will forcibly remove (second round):')

            for p in sorted(unwanted):
                logger.info('- %s', p)

            if unwanted:
                nspawn.check_call([
                    'dpkg', '--purge', '--force-remove-essential',
                    '--force-depends',
                ] + unwanted)

            installed = nspawn.list_packages_ignore_arch()

            logger.info('Packages included in platform:')

            for p in sorted(installed):
                if p != 'dpkg':
                    logger.info('- %s', p)

            # We have to do this before removing dpkg :-)
            nspawn.write_manifest()

            # This has to be last for obvious reasons!
            nspawn.check_call([
                'dpkg', '--purge', '--force-remove-essential',
                '--force-depends',
                'dpkg',
            ])

        return installed

    def ostreeify(self, prefix, chroot, sdk=False, packages=()):
        """
        Move things around to turn a chroot into a runtime.
        """
        if sdk:
            installed = self.sdkize(chroot)
        else:
            installed = self.platformize(chroot)

        with NspawnWorker(
            self.root_worker,
            chroot,
        ) as nspawn:
            nspawn.check_call([
                'find', '/', '-xdev', '(',
                '-lname', '/etc/alternatives/*', '-o',
                '-lname', '/etc/locale.alias',
                ')', '-exec', 'sh', '-euc',

                'set -e\n'
                'while [ $# -gt 0 ]; do\n'
                '    old="$(readlink "$1")"\n'
                '    if target="$(readlink -f "$1")"; then\n'
                '        echo "Making $1 a hard link to $target (was $old)"\n'
                '        rm -f "$1"\n'
                '        cp -al "$target" "$1"\n'
                '    fi\n'
                '    shift\n'
                'done'
                '',

                'sh', # argv[0] for the one-line shell script
                '{}', '+',
            ])
        self.root_worker.check_call([
            'chmod', '-R', '--changes', 'a-s,o-t,u=rwX,og=rX', chroot,
        ])
        self.root_worker.check_call([
            'chown', '-R', '--changes', 'root:root', chroot,
        ])
        self.root_worker.check_call([
            'rm', '-fr', '--one-file-system',
            '{}/usr/local'.format(chroot),
        ])

        # Merge /usr the hard way, if necessary.
        if not self.suite_details.get('can_merge_usr', False):
            self.usrmerge(chroot)

        if sdk:
            runtime = prefix + '.Sdk'

            self.root_worker.check_call([
                'rm', '-fr', '--one-file-system',
                '{}/etc/group-'.format(chroot),
                '{}/etc/gshadow-'.format(chroot),
                '{}/etc/passwd-'.format(chroot),
                '{}/etc/shadow-'.format(chroot),
                '{}/etc/subuid-'.format(chroot),
                '{}/etc/subgid-'.format(chroot),
                '{}/var/backups'.format(chroot),
                '{}/var/cache'.format(chroot),
                '{}/var/lib/dpkg/status-old'.format(chroot),
                '{}/var/lib/dpkg/statoverride'.format(chroot),
            ])
            self.root_worker.check_call([
                'install', '-d',
                '{}/var/cache/apt/archives/partial'.format(chroot),
                '{}/var/lib/extrausers'.format(chroot),
            ])
            self.root_worker.check_call([
                'touch', '{}/var/cache/apt/archives/partial/.exists'.format(chroot),
            ])

            # This is only useful if the SDK has libnss-extrausers
            self.root_worker.check_call([
                'cp', '{}/etc/passwd'.format(chroot),
                '{}/var/lib/extrausers/passwd'.format(chroot),
            ])
            self.root_worker.check_call([
                'cp', '{}/etc/group'.format(chroot),
                '{}/var/lib/extrausers/groups'.format(chroot),
            ])

            self.root_worker.check_call([
                'mv', '{}/etc'.format(chroot),
                '{}/usr/etc'.format(chroot),
            ])
            self.root_worker.check_call([
                'mv', '{}/var'.format(chroot),
                '{}/usr/var'.format(chroot),
            ])
        else:
            runtime = prefix + '.Platform'

            self.root_worker.check_call([
                'rm', '-fr', '--one-file-system',
                '{}/etc'.format(chroot),
                '{}/share/bash-completion'.format(chroot),
                '{}/share/bug'.format(chroot),
                '{}/var'.format(chroot),
            ])

        # TODO: Move lib/debug, zoneinfo, locales into extensions
        # TODO: Hook point for GL, instead of just Mesa
        # TODO: GStreamer extension
        # TODO: Icon theme, Gtk theme extension
        # TODO: VAAPI extension
        # TODO: SDK extension

        self.root_worker.check_call([
            'install', '-d', '{}/ostree/main'.format(chroot),
        ])
        self.root_worker.check_call([
            'mv', '{}/usr'.format(chroot),
            '{}/ostree/main/files'.format(chroot),
        ])

        ref = 'runtime/{}/{}/{}'.format(
            runtime, self.flatpak_arch, self.runtime_branch,
        )

        with TemporaryDirectory(prefix='flatdeb-ostreeify.') as t:
            metadata = os.path.join(t, 'metadata')

            keyfile = GLib.KeyFile()
            keyfile.set_string('Runtime', 'name', runtime)
            keyfile.set_string(
                'Runtime', 'runtime',
                '{}.Platform/{}/{}\n'.format(
                    prefix,
                    self.flatpak_arch,
                    self.runtime_branch,
                )
            )
            keyfile.set_string(
                'Runtime', 'sdk',
                '{}.Sdk/{}/{}\n'.format(
                    prefix,
                    self.flatpak_arch,
                    self.runtime_branch,
                )
            )

            keyfile.set_string(
                'Environment', 'XDG_DATA_DIRS',
                ':'.join([
                    '/app/share', '/usr/share', '/usr/share/runtime/share',
                ]),
            )

            if 'libgstreamer1.0-0' in installed:
                keyfile.set_string(
                    'Environment', 'GST_PLUGIN_SYSTEM_PATH',
                    ':'.join([
                        '/app/lib/gstreamer-1.0',
                        '/usr/lib/extensions/gstreamer-1.0',
                        '/usr/lib/gstreamer-1.0',
                    ]),
                )

            if 'libgirepository-1.0-1' in installed:
                keyfile.set_string(
                    'Environment', 'GI_TYPELIB_PATH',
                    ':'.join([
                        '/app/lib/girepository-1.0',
                    ]),
                )

            keyfile.save_to_file(metadata)

            self.root_worker.install_file(
                metadata,
                '{}/ostree/main/metadata'.format(chroot),
            )

        self.worker.check_call([
            'time',
            'ostree',
            '--repo=' + self.remote_repo,
            'commit',
            '--branch=' + ref,
            '--subject=Update',
            '--tree=dir={}/ostree/main'.format(chroot),
            '--fsync=false',
        ])

        # Don't keep the history in this working repository:
        # if history is desired, mirror the commits into a public
        # repository and maintain history there.
        self.worker.check_call([
            'time',
            'ostree',
            '--repo=' + self.remote_repo,
            'prune',
            '--refs-only',
            '--depth=1',
        ])

        if not isinstance(self.worker, HostWorker):
            self.worker.check_call([
                'time',
                'flatpak',
                'build-update-repo',
                self.remote_repo,
            ])

            with self.worker.remote_dir_context(self.remote_repo) as mount:
                self.host_worker.call([
                    'ostree',
                    '--repo={}'.format(self.repo),
                    'remote',
                    'delete',
                    'flatdeb-worker',
                ])
                print('^ It is OK if that failed with "remote not found"')
                self.host_worker.check_call([
                    'ostree',
                    '--repo={}'.format(self.repo),
                    'remote',
                    'add',
                    '--no-gpg-verify',
                    'flatdeb-worker',
                    'file://' + urllib.parse.quote(mount),
                ])
                self.host_worker.check_call([
                    'ostree',
                    '--repo={}'.format(self.repo),
                    'pull',
                    '--disable-fsync',
                    '--mirror',
                    '--untrusted',
                    'flatdeb-worker',
                    'runtime/{}/{}/{}'.format(
                        runtime,
                        self.flatpak_arch,
                        self.runtime_branch,
                    ),
                ])
                self.host_worker.check_call([
                    'ostree',
                    '--repo={}'.format(self.repo),
                    'remote',
                    'delete',
                    'flatdeb-worker',
                ])

            self.host_worker.check_call([
                'time',
                'flatpak',
                'build-update-repo',
                self.repo,
            ])

    def command_app(self, *, app_branch, yaml_manifest, **kwargs):
        self.ensure_local_repo()

        with open(yaml_manifest) as reader:
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
            self.ensure_remote_repo()
            t = stack.enter_context(
                TemporaryDirectory(prefix='flatpak-app.')
            )

            self.worker.check_call([
                'mkdir', '-p', '{}/home'.format(self.remote_build_area),
            ])

            if isinstance(self.worker, SshWorker):
                # ostree over sshfs is painfully slow so do something different
                self.host_worker.call([
                    'time',
                    'rsync',
                    '-aW',
                    '--no-i-r',
                    '--info=progress2',
                    '{}/'.format(self.repo),
                    '{}:{}/'.format(self.worker.remote, self.remote_repo),
                ])
            elif not isinstance(self.worker, HostWorker):
                with self.worker.remote_dir_context(self.remote_repo) as mount:
                    self.host_worker.call([
                        'ostree',
                        '--repo={}'.format(mount),
                        'remote',
                        'delete',
                        'flatdeb-host',
                    ])
                    print('^ It is OK if that failed with "remote not found"')
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(mount),
                        'remote',
                        'add',
                        '--no-gpg-verify',
                        'flatdeb-host',
                        'file://' + urllib.parse.quote(self.repo),
                    ])
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(mount),
                        'pull',
                        '--disable-fsync',
                        '--mirror',
                        'flatdeb-host',
                        'runtime/{}/{}/{}'.format(
                            manifest['sdk'],
                            self.flatpak_arch,
                            manifest['runtime-version'],
                        ),
                    ])
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(mount),
                        'pull',
                        '--disable-fsync',
                        '--mirror',
                        'flatdeb-host',
                        'runtime/{}/{}/{}'.format(
                            manifest['runtime'],
                            self.flatpak_arch,
                            manifest['runtime-version'],
                        ),
                    ])
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(mount),
                        'remote',
                        'delete',
                        'flatdeb-host',
                    ])
                    self.worker.check_call([
                        'time',
                        'flatpak',
                        'build-update-repo',
                        self.remote_repo,
                    ])

            self.worker.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
                'flatpak', '--user',
                'remote-add', '--if-not-exists', '--no-gpg-verify',
                'flatdeb',
                'file://{}'.format(urllib.parse.quote(self.remote_repo)),
            ])
            self.worker.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
                'flatpak', '--user',
                'remote-modify', '--no-gpg-verify',
                '--url=file://{}'.format(urllib.parse.quote(self.remote_repo)),
                'flatdeb',
            ])
            self.worker.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
                'flatpak', '--user',
                'install', 'flatdeb',
                '{}/{}/{}'.format(
                    manifest['sdk'],
                    self.flatpak_arch,
                    self.runtime_branch,
                ),
            ])
            self.worker.check_call([
                'env',
                'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
                'flatpak', '--user',
                'install', 'flatdeb',
                '{}/{}/{}'.format(
                    manifest['runtime'],
                    self.flatpak_arch,
                    manifest['runtime-version'],
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
                            'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
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
                            'mv /var/cache/apt/archives/*.deb "$export"\n'
                            'mv /var/lib/apt/lists "$export"\n'
                            '',

                            'sh',   # argv[0]
                        ] + module['x-flatdeb-apt-packages'])

                        obtained = self.worker.check_output([
                            'ls', packages,
                        ]).decode('utf-8').splitlines()

                        for f in obtained:
                            path = '{}/{}'.format(packages, f)

                            if f.endswith('.deb'):
                                sources.append({
                                    'dest': '.',
                                    'type': 'file',
                                    'path': path,
                                })

            remote_manifest = '{}/{}.json'.format(
                self.worker.scratch,
                manifest['id'],
            )

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
                'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
                'http_proxy=http://192.168.122.1:3142',
                'flatpak-builder',
                '--repo={}'.format(self.remote_repo),
                '{}/workdir'.format(self.worker.scratch),
                remote_manifest,
            ])

            if not isinstance(self.worker, HostWorker):
                self.worker.check_call([
                    'time',
                    'flatpak',
                    'build-update-repo',
                    self.remote_repo,
                ])

                with self.worker.remote_dir_context(self.remote_repo) as mount:
                    self.host_worker.call([
                        'ostree',
                        '--repo={}'.format(self.repo),
                        'remote',
                        'delete',
                        'flatdeb-worker',
                    ])
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(self.repo),
                        'remote',
                        'add',
                        '--no-gpg-verify',
                        'flatdeb-worker',
                        'file://' + urllib.parse.quote(mount),
                    ])
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(self.repo),
                        'pull',
                        '--disable-fsync',
                        '--mirror',
                        '--untrusted',
                        'flatdeb-worker',
                        'app/{}/{}/{}'.format(
                            manifest['id'],
                            self.flatpak_arch,
                            manifest['branch'],
                        ),
                    ])
                    self.host_worker.check_call([
                        'ostree',
                        '--repo={}'.format(self.repo),
                        'remote',
                        'delete',
                        'flatdeb-worker',
                    ])

                self.host_worker.check_call([
                    'time',
                    'flatpak',
                    'build-update-repo',
                    self.repo,
                ])

            if self.export_bundles:
                self.worker.check_call([
                    'time',
                    'env',
                    'XDG_DATA_HOME={}/home'.format(self.remote_build_area),
                    'flatpak',
                    'build-bundle',
                    self.remote_repo,
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

    def usrmerge(self, chroot):
        self.root_worker.check_call([
            'time',
            'chroot', chroot,
            'sh',
            '-euc',

            'usrmerge () {\n'
            '    local f="$1"\n'
            '\n'
            '    ls -dl "$f" "/usr$f" >&2 || true\n'
            '    if [ "$(readlink "$f")" = "/usr$f" ]; then\n'
            '        echo "Removing $f in favour of /usr$f" >&2\n'
            '        rm -v -f "$f"\n'
            '    elif [ "$(readlink "/usr$f")" = "$f" ]; then\n'
            '        echo "Removing /usr$f in favour of $f" >&2\n'
            '        rm -v -f "/usr$f"\n'
            '    elif [ "$(readlink -f "/usr$f")" = \\\n'
            '           "$(readlink -f "$f")" ]; then\n'
            '        echo "/usr$f and $f are functionally identical" >&2\n'
            '        rm -v -f "$f"\n'
            '    else\n'
            '        echo "Cannot merge $f with /usr$f" >&2\n'
            '        exit 1\n'
            '    fi\n'
            '}\n'
            '\n'
            'find /bin /sbin /lib* -not -xtype d |\n'
            'while read f; do\n'
            '    if [ -e "/usr$f" ]; then\n'
            '        usrmerge "$f"\n'
            '    fi\n'
            'done\n'
            '',

            'sh',   # argv[0]
            chroot,
        ])
        self.root_worker.check_call([
            'time',
            'sh', '-euc',
            'cd "$1"; tar -cf- bin sbin lib* | tar -C usr -xf-',
            'sh', chroot,
        ])
        self.root_worker.check_call([
            'time',
            'sh', '-euc', 'cd "$1"; rm -fr bin sbin lib*',
            'sh', chroot,
        ])
        self.root_worker.check_call([
            'time',
            'sh', '-euc', 'cd "$1"; ln -vs usr/bin usr/sbin usr/lib* .',
            'sh', chroot,
        ])

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)

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

    try:
        Builder().run_command_line()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as e:
        logger.error('%s', e)
        raise SystemExit(1)
