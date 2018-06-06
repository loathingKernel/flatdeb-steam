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

import logging
import os
import subprocess
from abc import abstractmethod, ABCMeta
from contextlib import ExitStack
from tempfile import TemporaryDirectory

from debian.debian_support import Version


logger = logging.getLogger(__name__)


class Worker(metaclass=ABCMeta):

    """
    A (possibly remote) machine to which we have shell access.
    It is a context manager.
    """

    def __init__(self):
        super().__init__()
        self.__depth = 0
        self.stack = ExitStack()
        self._temporary_directory = '/tmp'

    def __enter__(self):
        self.__depth += 1

        if self.__depth == 1:
            self._open()

        return self

    def __exit__(self, et, ev, tb):
        self.__depth -= 1
        if self.__depth:
            return False
        else:
            return self.stack.__exit__(et, ev, tb)

    def require_extended_attributes(self):
        assert self.__depth == 0, "Must not have been opened yet"
        assert self.scratch is None, "Must not have been opened yet"

        # We assume /var/tmp has xattr support
        self._temporary_directory = '/var/tmp'

    @property
    @abstractmethod
    def scratch(self):
        pass

    @abstractmethod
    def _open(self):
        pass

    @abstractmethod
    def call(self, argv, **kwargs):
        pass

    @abstractmethod
    def check_call(self, argv, **kwargs):
        pass

    @abstractmethod
    def check_output(self, argv, **kwargs):
        pass

    @abstractmethod
    def install_file(self, source, destination, permissions=0o644):
        pass

    def list_packages_ignore_arch(self):
        installed = set()

        for line in self.check_output([
                    'dpkg-query', '--show', '-f',
                    '${Package}\\n',
        ]).splitlines():
            package = line.strip().decode('utf-8')
            if package:
                installed.add(package)

        return installed


class InstalledPackage:
    def __init__(self, fields):
        self.binary = fields[0]
        self.binary_version = fields[1]
        self.source = fields[2]

        if self.source.endswith(')'):
            self.source, self.source_version = self.source.rstrip(')').split(' (')
        else:
            self.source_version = self.binary_version

            if not self.source:
                self.source = self.binary

        self.installed_size = fields[3]

    def __eq__(self, other):
        if isinstance(other, InstalledPackage):
            return (
                self.binary,
                self.binary_version,
            ) == (
                other.binary,
                other.binary_version,
            )
        else:
            return NotImplemented


class NspawnWorker(Worker):
    def __init__(self, worker, path, env=()):
        super().__init__()
        self.worker = worker
        self.path = path
        self.env = list(env)

    def _open(self):
        pass

    @property
    def scratch(self):
        return self.worker.scratch

    def call(self, argv, **kwargs):
        return self.worker.check_call(
            [
                'systemd-nspawn',
                '--directory={}'.format(self.path),
                '--as-pid2',
                'env',
            ] + self.env + list(argv),
            **kwargs,
        )

    def check_call(self, argv, **kwargs):
        self.worker.check_call(
            [
                'systemd-nspawn',
                '--directory={}'.format(self.path),
                '--as-pid2',
                'env',
            ] + self.env + list(argv),
            **kwargs,
        )

    def check_output(self, argv, **kwargs):
        return self.worker.check_output(
            [
                'systemd-nspawn',
                '--directory={}'.format(self.path),
                '--as-pid2',
                'env',
            ] + self.env + list(argv),
            **kwargs,
        )

    def install_file(self, source, destination, permissions=0o644):
        self.worker.install_file(
            source,
            '{}/{}'.format(self.path, destination),
            permissions,
        )

    def write_manifest(self):
        ret = []

        with TemporaryDirectory(prefix='flatdeb-manifest.') as t:
            manifest = os.path.join(t, 'manifest')

            with open(manifest, 'w', encoding='utf-8') as writer:
                writer.write(
                    '#Package[:Architecture]\t'
                    '#Version\t'
                    '#Source\t'
                    '#Installed-Size\n'
                )
                writer.flush()

                dpkg_version = self.check_output([
                    'dpkg-query', '-W', '-f', '${Version}', 'dpkg',
                ]).decode('utf-8')

                if Version(dpkg_version) >= Version('1.16.2'):
                    self.check_call([
                        'dpkg-query', '-W',
                        '-f', (
                            r'${binary:Package}\t'
                            r'${Version}\t'
                            r'${Source}\t'
                            r'${Installed-Size}\n'
                        ),
                    ], stdout=writer)
                else:
                    self.check_call([
                        'dpkg-query', '-W',
                        '-f', (
                            r'${Package}:${Architecture}\t'
                            r'${Version}\t'
                            r'${Source}\t'
                            r'${Installed-Size}\n'
                        ),
                    ], stdout=writer)

            self.install_file(manifest, '/usr/manifest.dpkg')

            with open(manifest, encoding='utf-8') as reader:
                for line in reader:
                    line = line.rstrip('\n')

                    if not line:
                        continue

                    if line.startswith('#'):
                        continue

                    assert '\t' in line, repr(line)
                    ret.append(InstalledPackage(line.rstrip('\n').split('\t')))

        return ret

    def list_built_using(self):
        for line in self.check_output([
                    'dpkg-query', '-W', '-f',
                    r'${Package}\t${Built-Using}\n',
                ]).decode('utf-8').splitlines():
            built_using = line.rstrip('\n')

            if not built_using:
                continue

            assert '\t' in built_using, built_using
            package, built_using = built_using.split('\t', 1)
            built_using = built_using.split(',')

            if not built_using:
                continue

            for field in built_using:
                # The example given in Policy is:
                # Built-Using: gcc-4.6 (= 4.6.0-11)
                f = field.replace(' ', '')      # gcc-4.6(=4.6.0-11)

                if not f:
                    continue

                assert '(=' in f, f
                source, version = f.split('(=', 1) # gcc-4.6, 4.6.0-11)
                assert version.endswith(')'), version
                version = version[:-1]          # 4.6.0-11
                yield package, source, version


class SudoWorker(Worker):

    """
    Adapter to get root using sudo.
    """

    def __init__(self, worker):
        super().__init__()
        self.__scratch = None
        self.__worker = worker

    def _open(self):
        self.stack.enter_context(self.__worker)
        self.stack.callback(
            lambda:
            self.check_call([
                'rm', '-fr', '--one-file-system',
                os.path.join(self.scratch),
            ]),
        )
        self.__worker.check_call([
            'mkdir', '-p', os.path.join(self.__worker.scratch, 'root')
        ])

    @property
    def scratch(self):
        return os.path.join(self.__worker.scratch, 'root')

    def call(self, argv, **kwargs):
        return self.__worker.call(
            ['env', '-', '/usr/bin/sudo', '-H'] + argv,
            **kwargs,
        )

    def check_call(self, argv, **kwargs):
        self.__worker.check_call(
            ['env', '-', '/usr/bin/sudo', '-H'] + argv,
            **kwargs,
        )

    def check_output(self, argv, **kwargs):
        return self.__worker.check_output(
            ['env', '-', '/usr/bin/sudo', '-H'] + argv,
            **kwargs,
        )

    def install_file(self, source, destination, permissions=0o644):
        permissions = oct(permissions)

        if permissions.startswith('0o'):
            permissions = permissions[2:]

        self.check_call([
            'sh', '-euc',
            'exec cat > "$1"/install',
            'sh',
            self.scratch,
        ], stdin=open(source, 'rb'))
        self.check_call([
            'install', '-m' + permissions,
            '{}/install'.format(self.scratch),
            destination,
        ])


class HostWorker(Worker):

    """
    The host machine, with unprivileged access.
    """

    def __init__(self):
        super().__init__()
        self.__scratch = None

    def _open(self):
        self.__scratch = self.stack.enter_context(
            TemporaryDirectory(
                prefix='flatdeb-host.',
                dir=self._temporary_directory,
            )
        )

    @property
    def scratch(self):
        return self.__scratch

    @staticmethod
    def check_call(argv, **kwargs):
        logger.debug('host:%r', argv)
        subprocess.check_call(argv, **kwargs)

    @staticmethod
    def Popen(argv, **kwargs):
        logger.debug('host:%r', argv)
        return subprocess.Popen(argv, **kwargs)

    @staticmethod
    def call(argv, **kwargs):
        logger.debug('host:%r', argv)
        return subprocess.call(argv, **kwargs)

    @staticmethod
    def check_output(argv, **kwargs):
        logger.debug('host:%r', argv)
        return subprocess.check_output(argv, **kwargs)

    def install_file(self, source, destination, permissions=0o644):
        permissions = oct(permissions)

        if permissions.startswith('0o'):
            permissions = permissions[2:]

        self.check_call([
            'install', '-m' + permissions, source, destination,
        ])
