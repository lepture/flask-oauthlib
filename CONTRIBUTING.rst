Contributing
=============

First, please do contribute! There are more than one way to contribute, and I will
appreciate any way you choose.

* introduce Flask-OAuthlib to your friends, let Flask-OAuthlib to be known
* discuss Flask-OAuthlib , and submit bugs with github issues
* improve documentation for Flask-OAuthlib
* send patch with github pull request

English and Chinese issues are acceptable, talk in your favorite language.

Pull request and git commit message **must be in English**, if your commit message
is in other language, it will be rejected.


Issues
------

When you submit an issue, please format your content, a readable content helps a lot.
You should have a little knowledge on Markdown_.

.. _Markdown: http://github.github.com/github-flavored-markdown/

Code talks. If you can't make yourself understood, show me the code. Please make your
case as simple as possible.


Codebase
--------

The codebase of Flask-OAuthlib is highly tested and :pep:`8` compatible, as a way
to guarantee functionality and keep all code written in a good style.

You should follow the code style. Here are some tips to make things simple:

* When you cloned this repo, run ``pip install -r requirements.txt``
* Check the code style with ``make lint``
* Check the test with ``make test``
* Check the test coverage with ``make coverage``


Git Help
--------

Something you should know about git.

* don't add any code on the master branch, create a new one
* don't add too many code in one pull request
* all featured branches should be based on the master branch
* don't merge any code yourself

Take an example, if you want to add feature A and feature B, you should have two
branches::

    $ git branch feature-A
    $ git checkout feature-A

Now code on feature-A branch, and when you finish feature A::

    $ git checkout master
    $ git branch feature-B
    $ git checkout feature-B

All branches must be based on the master branch. If your feature-B needs feature-A,
you should send feature-A first, and wait for its merging. We may reject feature-A,
and you should stop feature-B.

Keep your master branch the same with upstream::

    $ git remote add upstream git@github.com:lepture/flask-oauthlib.git
    $ git pull upstream master

**And don't change any code on master branch.**
