clean:
	@rm -rf ./build ./dist .cache .eggs *.egg-info
	@find . -type f -name '*.pyc' -exec rm {} \;
	@find . -type d -name '__pycache__' | xargs rm -rf

docs:
	@pandoc --from markdown_github --to rst README.md -o README.rst

test:
	@python setup.py test

build: clean
	@python setup.py sdist bdist_egg

install:
	@python setup.py install --user

release: build test docs
	@python setup.py sdist register upload

