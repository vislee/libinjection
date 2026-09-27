
SUBDIRS=src

all:  ## build c library
	(cd src; ${MAKE} all)
check:  ## run tests
	(cd src; ${MAKE} check)
benchmark:  ## detection recall / false-positive benchmark
	./run-benchmark.sh
coverage:  ## measure line coverage (requires clang + llvm-cov), 95% gate
	./run-coverage.sh
clean:  ## clean up
	@(cd src; ${MAKE} clean)
	rm -rf src/coverage-data
	git gc --aggressive

.PHONY: all check benchmark coverage clean

docker-console:  ## log into the docker test image
	docker run --rm -it \
		-e COVERALLS_REPO_TOKEN=$COVERALLS_REPO_TOKEN \
		-v $(PWD):/build \
		-w /build \
		nickg/libinjection-docker \
		sh

docker-ci:   ## run the tests in docker, as travis-ci does
	docker run --rm \
		-e COVERALLS_REPO_TOKEN=$COVERALLS_REPO_TOKEN \
		-v $(PWD):/build \
		-w /build \
		nickg/libinjection-docker \
		./make-ci.sh

# https://www.client9.com/self-documenting-makefiles/
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help
.DEFAULT_GOAL := help

