#!/bin/sh
# Copyright © 2016-2018 Simon McVittie
# Copyright © 2018 Collabora Ltd.
#
# SPDX-License-Identifier: MIT

set -e
set -u

if [ "${PYCODESTYLE:=pycodestyle}" = false ] || \
        [ -z "$(command -v "$PYCODESTYLE")" ]; then
    echo "1..0 # SKIP pycodestyle not found"
elif "${PYCODESTYLE}" \
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
    >&2; then
    echo "1..1"
    echo "ok 1 - $PYCODESTYLE reported no issues"
else
    echo "1..1"
    echo "not ok 1 # TODO $PYCODESTYLE issues reported"
fi

# vim:set sw=4 sts=4 et:
