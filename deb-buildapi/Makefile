all:
	set -e; \
	if test -d src; then \
		cd src && \
		dpkg-buildpackage -b -nc \
		--build-profiles=pkg.flatpak.app,nocheck,nodoc; \
	fi; \
	done

# This assumes we don't need to run maintainer scripts.
install:
	set -e; \
	PATH=/usr/sbin:$$PATH \
	fakeroot \
	dpkg --root=/app --unpack --force-script-chrootless --no-triggers \
	*.deb \
	$(NULL)
