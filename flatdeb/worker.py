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
import shlex
import subprocess
import sys
from abc import abstractmethod, ABCMeta
from contextlib import ExitStack, contextmanager
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

    @abstractmethod
    def remote_dir_context(self, path):
        """
        Return a context manager. Entering the context manager makes path
        available as a filesystem directory for the caller, returning
        the transformed path (possibly a sshfs or similar). Leaving the
        context manager cleans up.
        """

    def list_packages_ignore_arch(self):
        installed = set()

        for line in self.check_output([
                    'dpkg-query', '--show', '-f',
                    '${Package}\\n',
        ]).splitlines():
            installed.add(line.strip().decode('utf-8'))

        return installed


class NspawnWorker(Worker):
    def __init__(self, worker, path, env=()):
        super().__init__()
        self.worker = worker
        self.path = path
        self.env = list(env)

    def _open(self):
        pass

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
        with TemporaryDirectory(prefix='flatdeb-manifest.') as t:
            manifest = os.path.join(t, 'manifest')

            dpkg_version = self.check_output([
                'dpkg-query', '-W', '-f', '${Version}', 'dpkg',
            ]).decode('utf-8')

            with open(manifest, 'w') as writer:
                writer.write(
                    '#Package[:Architecture]\t'
                    '#Version\t'
                    '#Source\t'
                    '#Installed-Size\n'
                )

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

    @contextmanager
    def remote_dir_context(self, path):
        yield os.path.normpath(os.path.join(self.path, './' + path))


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

    @contextmanager
    def remote_dir_context(self, path):
        yield path


class HostWorker(Worker):

    """
    The host machine, with unprivileged access.
    """

    def __init__(self):
        super().__init__()
        self.__scratch = None

    def _open(self):
        self.__scratch = self.stack.enter_context(
            TemporaryDirectory(prefix='flatdeb-host.')
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

    @contextmanager
    def remote_dir_context(self, path):
        yield path


class SshWorker(Worker):

    """
    A machine we can ssh to.
    """

    def __init__(self, remote):
        super().__init__()
        self.remote = remote
        self.__scratch = None

    def _open(self):
        self.__scratch = self.check_output(
            ['mktemp', '-d', '-p', '/tmp', 'flatdeb-ssh-worker.XXXXXX'],
            universal_newlines=True,
        ).rstrip('\n')
        self.stack.callback(
            lambda:
            self.check_call([
                'rm', '-fr', '--one-file-system', self.__scratch,
            ]),
        )

    @property
    def scratch(self):
        return self.__scratch

    def call(self, argv, **kwargs):
        logger.debug('%s:%r', self.remote, argv)
        if isinstance(argv, str):
            command_line = argv
        else:
            command_line = ' '.join(map(shlex.quote, argv))
        return subprocess.call(
            ['ssh', self.remote, command_line],
            **kwargs,
        )

    def check_call(self, argv, **kwargs):
        logger.debug('%s:%r', self.remote, argv)
        if isinstance(argv, str):
            command_line = argv
        else:
            command_line = ' '.join(map(shlex.quote, argv))
        subprocess.check_call(
            ['ssh', self.remote, command_line],
            **kwargs,
        )

    def check_output(self, argv, **kwargs):
        logger.debug('%s:%r', self.remote, argv)
        command_line = ' '.join(map(shlex.quote, argv))
        return subprocess.check_output(
            ['ssh', self.remote, command_line],
            **kwargs,
        )

    def install_file(self, source, destination, permissions=0o644):
        permissions = oct(permissions)

        if permissions.startswith('0o'):
            permissions = permissions[2:]

        self.check_call(
            'cat > {}/install'.format(shlex.quote(self.scratch)),
            stdin=open(source, 'rb'),
        )
        self.check_call([
            'install', '-m' + permissions,
            '{}/install'.format(self.scratch),
            destination,
        ])

    @contextmanager
    def remote_dir_context(self, path):
        with TemporaryDirectory(prefix='flatdeb-mount.') as t:
            subprocess.check_call([
                'sshfs',
                '{}:{}'.format(self.remote, path),
                t,
            ])
            try:
                yield t
            finally:
                subprocess.check_call([
                    'fusermount',
                    '-u',
                    t,
                ])
