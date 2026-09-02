.PHONY: prefetch meta-conformance build-reproducible zero-bill acceptance-package-contract campaign evidence-verify acceptance-package

prefetch:
	@python3 ci/run_make_target.py prefetch

meta-conformance:
	@python3 ci/run_make_target.py meta-conformance

build-reproducible:
	@python3 ci/run_make_target.py build-reproducible

zero-bill:
	@python3 ci/run_make_target.py zero-bill

acceptance-package-contract:
	@python3 ci/run_make_target.py acceptance-package-contract

campaign:
	@python3 ci/run_make_target.py campaign

evidence-verify:
	@python3 ci/run_make_target.py evidence-verify

acceptance-package:
	@python3 ci/run_make_target.py acceptance-package
