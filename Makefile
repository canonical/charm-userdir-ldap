help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make test - run the unittests and lint"
	@echo " make unittest - run the tests defined in the unittest subdirectory"
	@echo " make functional - run the tests defined in the functional subdirectory"
	@echo " make clean - remove unneeded files"
	@echo ""

lint:
	@echo "Running flake8"
	@-tox -e lint

test: lint unittest functional

unittest:
	@tox -e unittest

functional:
	@tox -e func

clean:
	@echo "Cleaning files"
	@rm -rf .tox
	@find . -type d -name '__pycache__' -prune -exec rm -rf "{}" \;

# The targets below don't depend on a file
.PHONY: lint test unittest functional clean help

