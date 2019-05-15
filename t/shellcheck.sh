#!/bin/sh
#
# Copyright © 2018-2019 Collabora Ltd
#
# SPDX-License-Identifier: MIT

set -e
set -u

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "1..0 # SKIP shellcheck not available"
    exit 0
fi

n=0
for shell_script in \
        deb-buildapi/configure \
        flatdeb/add-foreign-architectures \
        flatdeb/clean-up-base \
        flatdeb/clean-up-before-pack \
        flatdeb/disable-services \
        flatdeb/make-flatpak-friendly \
        flatdeb/platformize \
        flatdeb/prepare-runtime \
        flatdeb/put-ldconfig-in-path \
        flatdeb/symlink-alternatives \
        flatdeb/usrmerge \
        flatdeb/write-manifest \
        run-in-fakemachine \
        t/*.sh \
        ; do
    n=$((n + 1))

    # Ignore SC2039: we assume a Debian-style shell that has 'local'.
    if shellcheck --exclude=SC2039 "$shell_script"; then
        echo "ok $n - $shell_script"
    else
        echo "not ok $n # TODO - $shell_script"
    fi
done

echo "1..$n"

# vim:set sw=4 sts=4 et ft=sh:
