#!/bin/sh
# Copyright © 2016-2018 Simon McVittie
# Copyright © 2018 Collabora Ltd.
#
# SPDX-License-Identifier: MIT

set -e
set -u

export MYPYPATH="${PYTHONPATH:=$(pwd)}"

i=0
for script in \
    ./*.py \
    flatdeb/apt-install \
    flatdeb/collect-dbgsym \
    flatdeb/collect-app-source-code \
    flatdeb/collect-source-code \
    flatdeb/dbgsym-use-build-id \
    flatdeb/debootstrap \
    flatdeb/list-required-source-code \
    flatdeb/purge-conffiles \
    flatdeb/set-build-id \
    flatdeb/unpack-dbgsym \
; do
    i=$((i + 1))
    if [ "${MYPY:="$(command -v mypy || echo false)"}" = false ]; then
        echo "ok $i - $script # SKIP mypy not found"
    elif "${MYPY}" \
            --python-executable="${PYTHON:=python3}" \
            --follow-imports=skip \
            --ignore-missing-imports \
            "$script"; then
        echo "ok $i - $script"
    else
        echo "not ok $i - $script # TODO mypy issues reported"
    fi
done
echo "1..$i"

# vim:set sw=4 sts=4 et:
