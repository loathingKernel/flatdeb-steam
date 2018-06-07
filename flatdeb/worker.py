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
import subprocess
from abc import abstractmethod, ABCMeta
from contextlib import ExitStack
from tempfile import TemporaryDirectory


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
