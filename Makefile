PYTHON := /usr/bin/python3

PROJECTPATH=$(dir $(realpath $(MAKEFILE_LIST)))
ifndef CHARM_BUILD_DIR
	CHARM_BUILD_DIR=${PROJECTPATH}/build
endif
METADATA_FILE="metadata.yaml"
CHARM_NAME=$(shell cat ${PROJECTPATH}/${METADATA_FILE} | grep -E '^name:' | awk '{print $$2}')

help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make clean - remove unneeded files"
	@echo " make submodules - make sure that the submodules are up-to-date"
	@echo " make submodules-update - update submodules to latest changes on remote branch"
	@echo " make build - build the charm"
	@echo " make release - run clean and build targets"
	@echo " make lint - run flake8 and black --check"
	@echo " make black - run black and reformat files"
	@echo " make proof - run charm proof"
	@echo " make unittests - run the tests defined in the unittest subdirectory"
	@echo " make functional - run the tests defined in the functional subdirectory"
	@echo " make test - run lint, proof, unittests and functional targets"
	@echo ""

clean:
	@echo "Cleaning charmcraft"
	@charmcraft clean
	@echo "Cleaning existing chamr files"
	@rm -rf ${PROJECTPATH}/${CHARM_NAME}.charm

submodules:
	@echo "Cloning submodules"
	@git submodule update --init --recursive

submodules-update:
	@echo "Pulling latest updates for submodules"
	@git submodule update --init --recursive --remote --merge

bundled-packages-update:
	@pip install --target bundled_packages/ --upgrade python-hosts

build: clean bundled-packages-update
	@echo "Building charm to base directory ${CHARM_BUILD_DIR}/${CHARM_NAME}.charm"
	@-git rev-parse --abbrev-ref HEAD > ./repo-info
	@-git describe --always > ./version
	@charmcraft -v pack
	@bash -c ./rename.sh

release: clean build
	@charmcraft upload ${PROJECTPATH}/${CHARM_NAME}.charm --release edge

lint:
	@echo "Running lint checks"
	@tox -e lint

black:
	@echo "Reformat files with black"
	@tox -e black

proof:
	@echo "Running charm proof"
	@charm proof

unittests:
	@echo "Running unit tests"
	@tox -e unit

functional: build
	@echo "Executing functional tests"
	@CHARM_LOCATION=${PROJECTPATH} tox -e func

test: lint proof unittests functional
	@echo "Charm ${CHARM_NAME} has been tested"

# The targets below don't depend on a file
.PHONY: help submodules submodules-update clean build release lint black proof unittests functional test
