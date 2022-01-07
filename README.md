flatdeb - Steam
===============

<!-- This document:
Copyright 2020 Collabora Ltd.
SPDX-License-Identifier: MIT
-->

[flatdeb](https://salsa.debian.org/smcv/flatdeb) builds Flatpak-style
runtimes from Debian packages. This repository sets it up for the
Steam Runtime.

How this fits into the overall Steam Runtime project
----------------------------------------------------

1. Build .deb packages for the content of the Steam Runtime, from
    the source code in e.g.
    <https://repo.steampowered.com/steamrt-images-scout/snapshots/latest-container-runtime-depot/sources/>.
    This is not part of this git repository.

2. For `scout` and `heavy` only: Put together the .deb packages into the
    `LD_LIBRARY_PATH`-based Steam Runtime.
    This git repository is not relevant for this step.

3. Put together the .deb packages into a Flatpak-style container runtime.
    This step is done by the code in this git repository. The choice of
    the actual packages to include is mostly delegated to
    [steamrt](https://gitlab.steamos.cloud/steamrt/steamrt), which has
    a branch for each major version of the Steam Runtime.

4. To make the runtime suitable for running Steam games and Proton on
    (almost) any GNU/Linux machine, turn it into a Steampipe depot
    with the runtime itself, the pressure-vessel container runtime tool,
    all of the pressure-vessel tool's dependencies except glibc, and some
    scripts and Steam manifests to hold the whole thing together.
    This is controlled by
    [steamlinuxruntime](https://gitlab.steamos.cloud/steamrt/steamlinuxruntime).

Building Flatpak-style runtimes
-------------------------------

On a Debian 10 'buster' machine:

    apt install \
    binutils \
    debootstrap \
    debos \
    dpkg-dev \
    flatpak \
    flatpak-builder \
    ostree \
    pigz \
    python3 \
    python3-debian \
    python3-gi \
    python3-yaml \
    systemd-container \
    time \
    ${NULL}

You will probably want to use a caching proxy such as apt-cacher-ng to
download `.deb` packages, which you can do by prefixing all the commands
below with `env http_proxy=http://192.168.122.1:3142` or similar.

Have lots of space in `${XDG_CACHE_HOME}` (defaulting to `~/.cache`
as usual).

Then you can run something like this:

    flatdeb/run.py --suite=scout_beta --arch=amd64,i386 base
    flatdeb/run.py --suite=scout_beta --arch=amd64,i386 \
        --no-collect-source-code \
        --no-debug-symbols \
        --no-generate-source-tarball \
        --no-ostree-commit \
        runtimes \
        runtimes/scout.yaml

Depending on the current state of the Steam Runtime development cycle,
the `scout` runtime as configured here might require unreleased packages;
roll back recent commits if necessary.

Some of the runtimes visible in `suites/` and `runtimes/` are not
currently available to the public: they represent possible future
development. Please see
<https://gitlab.steamos.cloud/steamrt/steamrt/> for more information
about the various branches of the Steam Runtime.

Options
-------

See the flatdeb source code for details. Potentially interesting options
include:

* `--collect-source-code`: Gather up the complete corresponding source
    code, ready to publish. For copyleft (GPL and LGPL) software,
    publishing source code that corresponds to each binary build is
    the easiest way to comply with the license.

    You can either use `--generate-source-tarball` to collect it into a
    very large tar archive (slow!), or `--generate-source-directory=DIR`
    to put it all in the directory *DIR*.

    Official builds use `--generate-source-directory=sources`, resulting
    in the `./sources` directory, for example
    <https://repo.steampowered.com/steamrt-images-scout/snapshots/latest-container-runtime-depot/sources/>.

* `--debug-symbols`: Gather up detached debugging symbols in the SDK's
    `/usr/lib/debug`, but break them off into `*-debug.tar.gz` instead
    of including them in the SDK itself.

    Official builds do this.

* `--generate-sysroot-tarball`: Generate a `-sysroot.tar.gz` for the SDK.
    This is not "merged-/usr" (which sometimes matters when building new
    .deb packages, especially in scout), and doesn't have some tweaks that
    make it better for pressure-vessel.

    Official builds do this, to produce the `-sysroot.tar.gz` that we
    publish. It's also what we use to make the official Docker containers
    ([scout](https://gitlab.steamos.cloud/steamrt/scout/sdk),
    [soldier](https://gitlab.steamos.cloud/steamrt/soldier/sdk)).

* `--ostree-commit`: Commit a Flatpak runtime to an OSTree repository
    in `~/.cache/flatdeb/repo`. It's the same as what you would get by
    committing the contents of the `-runtime.tar.gz` as a tree.

    Official builds don't do this. We originally did, but it's quite slow
    and we don't need it at the moment.

* `--sdk`, `--no-sdk`, `--platform`, `--no-platform`:
    Build the SDK (used for debugging and development), or the Platform
    (used to run games), or both. The default is to include both, and
    that's what official builds do.

* `--replace-build-apt-source`:
    Replace one of the apt sources listed in `suites/*.yaml` with a
    different apt source.

    Official builds use this to replace all the apt sources with
    equivalents on Valve infrastructure containing packages that haven't
    been published or released yet, so that we can test the resulting
    build, and if it's good, publish it (together with the packages
    it includes).

* `--add-apt-source`: Add a PPA-style additional layer of packages.

    Official builds don't use this option, but we use it during development
    as a way to incorporate unreleased packages into a runtime for testing.

Building Flatpak apps
---------------------

The original concept for this code was to use Steam Runtime 1 'scout'
to make a Flatpak runtime, then package the Steam client (the main Steam app)
to run as a Flatpak app in that runtime. For various reasons, this never
happened, and the focus shifted towards running individual games in
Flatpak-style containers.

The "app" stage (which builds Flatpak apps) is not regularly tested but
might still work if you're lucky.

First, you'll need to build runtimes with `--ostree-commit`, to get a
Flatpak runtime to work from. Then you can try building apps on top
of that:

    flatdeb/run.py --arch=amd64,i386 app \
        apps/org.debian.packages.mesa_utils.yaml
    flatdeb/run.py --arch=i386 app \
        apps/org.debian.packages.mesa_utils.yaml
    flatdeb/run.py --arch=amd64,i386 app \
        apps/com.valvesoftware.Steam.yaml
    flatdeb/run.py --arch=i386 app \
        apps/com.valvesoftware.Steam.yaml

On the host, or a test machine onto which you have copied
`$HOME/.cache/flatdeb/repo` with `rsync` or similar:

    flatpak --user remote-add --no-gpg-verify flatdeb $HOME/.cache/flatdeb/repo
    flatpak --user install flatdeb org.debian.packages.mesa_utils
    flatpak run org.debian.packages.mesa_utils
    flatpak --user install flatdeb com.valvesoftware.Steam
    flatpak run com.valvesoftware.Steam

Note that the Steam Flatpak app that is built this way is very much a
proof-of-concept, and does not have all the necessary permissions and
workarounds for the Steam client and games to work particularly reliably. The
[community Steam package on Flathub](https://github.com/flathub/com.valvesoftware.Steam)
is likely to work better in practice.
