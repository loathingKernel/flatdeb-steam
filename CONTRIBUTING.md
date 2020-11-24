Contributing to flatdeb-steam
=============================

Reporting bugs
--------------

We use <https://github.com/ValveSoftware/steam-runtime> for general
issue tracking for the Steam Runtime. If you are not completely sure
what the best way to resolve an issue is, please report issues there
so that they can be triaged.

If you are sure that an issue specifically deals with the code and
configuration in this repository, the issue tracker for what's in
this repository is at
<https://gitlab.steamos.cloud/steamrt/flatdeb-steam/-/issues>.

Proposed patches are welcome, but please describe what the issue is first
(including the steps that can be used to reproduce the issue, the expected
result of those steps, and the actual result). That way, even if the
patch you propose isn't suitable, we can think about other solutions to
the issue.

The flatdeb/ directory
----------------------

The actual flatdeb program is maintained in Debian's infrastructure:
[flatdeb](https://salsa.debian.org/smcv/flatdeb). You can create a fork
and open merge requests there. Our policy is that all changes to the
`flatdeb/` directory in the `flatdeb-steam` project should usually be
merges from the `flatdeb` project.

If a bug in flatdeb is causing Steam Runtime issues, please report an
issue at <https://gitlab.steamos.cloud/steamrt/flatdeb-steam/-/issues>
and refer to it in the flatdeb merge request.

Because `flatdeb` is not yet stable, we "vendor" a known-good copy of
`flatdeb` into `flatdeb-steam`, so that we can keep track of which version
we are using, and so that incompatible changes in `flatdeb` (if any)
will not affect the Steam Runtime until we are ready to deal with them.

Controlling what goes into each runtime
---------------------------------------

The packages that will go into each runtime are mostly determined by
<https://gitlab.steamos.cloud/steamrt/steamrt/>. Shared libraries are
controlled by `abi/steam-runtime-abi.yaml`, and development libraries
for the SDK are listed in `debian/control`.

We prefer to keep the lists of packages mostly in `steamrt`, and only
change the recipes in `flatdeb-steam` if there is a structural change.
