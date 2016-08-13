.PHONY: lint test coverage clean clean-pyc clean-build docs

lint:
	@which flake8 || pip install flake8
	@flake8 flask_oauthlib tests

test:
	@which nosetests || pip install nose
	@nosetests -s --nologcapture

coverage:
	@which nosetests || pip install nose
	@rm -f .coverage
	@nosetests --with-coverage --cover-package=flask_oauthlib --cover-html

clean: clean-build clean-pyc clean-docs clean-tox


clean-build:
	@rm -fr build/
	@rm -fr dist/
	@rm -fr *.egg
	@rm -fr *.egg-info


clean-pyc:
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +
	@find . -name '__pycache__' -exec rm -fr {} +

clean-docs:
	@rm -fr  docs/_build

clean-tox:
	@rm -rf .tox/

docs:
	@$(MAKE) -C docs html
