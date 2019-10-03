check:
	prove -v t/*.sh
	$(MAKE) -C flatdeb check
