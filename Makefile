.PHONY: lint test coverage clean clean-pyc clean-build docs

lint:
	@flake8 flask-oauthlib tests

test:
	@DEBUG=1 nosetests -s --nologcapture

coverage:
	@rm -f .coverage
	@DEBUG=1 nosetests --with-coverage --cover-package=flask_oauthlib --cover-html

clean: clean-build clean-pyc clean-docs


clean-build:
	@rm -fr build/
	@rm -fr dist/
	@rm -fr *.egg-info


clean-pyc:
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +
	@find . -name '__pycache__' -exec rm -fr {} +

clean-docs:
	@rm -fr  docs/_build

docs:
	@$(MAKE) -C docs html
