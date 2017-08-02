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

import os
import shlex
import subprocess
from abc import abstractmethod, ABCMeta
from contextlib import ExitStack
from tempfile import TemporaryDirectory


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
    def check_call(self, argv, **kwargs):
        pass

    @abstractmethod
    def check_output(self, argv, **kwargs):
        pass

    @abstractmethod
    def install_file(self, source, destination, permissions=0o644):
        pass


class NspawnWorker(Worker):
    def __init__(self, worker, path, env=()):
        super().__init__()
        self.worker = worker
        self.path = path
        self.env = list(env)

    def _open(self):
        pass

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
        with TemporaryDirectory() as t:
            manifest = os.path.join(t, 'manifest')

            with open(manifest, 'w') as writer:
                self.check_call([
                    'dpkg-query', '-W',
                    '-f', (
                        r'${binary:Package}\t${Version}\t'
                        r'${source:Package}\t${source:Version}\t'
                        r'${Installed-Size}\t${Status}\n'
                    ),
                ], stdout=writer)

            self.install_file(manifest, '/usr/manifest.dpkg')


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

    def check_call(self, argv, **kwargs):
        print(repr(argv))
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
        self.__scratch = self.stack.enter_context(TemporaryDirectory())

    @property
    def scratch(self):
        return self.__scratch

    @staticmethod
    def check_call(argv, **kwargs):
        try:
            subprocess.check_call(argv, **kwargs)
        except Exception as e:
            print(e)
            print('Exit shell to continue')
            subprocess.check_call(
                ['/bin/bash', '-i'],
                stdin=open('/dev/tty'),
                stdout=open('/dev/tty', 'w'),
                stderr=subprocess.STDOUT,
            )
            raise

    @staticmethod
    def check_output(argv, **kwargs):
        return subprocess.check_output(argv, **kwargs)

    def install_file(self, source, destination, permissions=0o644):
        permissions = oct(permissions)

        if permissions.startswith('0o'):
            permissions = permissions[2:]

        self.check_call([
            'install', '-m' + permissions, source, destination,
        ])


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
            ['mktemp', '-d'],
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

    def check_call(self, argv, **kwargs):
        print(repr(argv))
        if isinstance(argv, str):
            command_line = argv
        else:
            command_line = ' '.join(map(shlex.quote, argv))
        try:
            subprocess.check_call(
                ['ssh', self.remote, command_line],
                **kwargs,
            )
        except Exception as e:
            print(e)
            subprocess.check_call(
                ['ssh', self.remote],
                stdin=open('/dev/tty'),
                stdout=open('/dev/tty', 'w'),
                stderr=subprocess.STDOUT,
            )
            raise

    def check_output(self, argv, **kwargs):
        print(repr(argv))
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
