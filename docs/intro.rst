************
Introduction
************

SpamPAD is a open-source drop-in replacement for SpamAssassin.

Compatibility
=============

SpamPAD is compatible with the following Python versions:

* Python 2.7
* Python 3.2 and later
* PyPy
* PyPy3

Contribute
==========

- `Issue Tracker <http://github.com/SpamExperts/SpamPAD/issues>`_
- `Source Code <http://github.com/SpamExperts/SpamPAD>`_

Getting the source
==================

To clone the repository using git simply run::

    git clone https://github.com/SpamExperts/SpamPAD

Please feel free to `fork us <https://github.com/SpamExperts/SpamPAD/fork>`_
and submit your pull requests.

Running tests
=============

To run the project's tests you will need to first:

#. Create a python virtualenv and activate it *(Recommended only)*
#. Clone the repository from GitHub.
#. Install sqlalchemy or pymysql package.
#. Install the base dependencies from `requirements/base.txt` with pip
#. Install the the dependencies for the python version you are using from the
   `requirements` folder
#. Install the dependencies for running tests from `requirements/tests.txt`
#. Download the GeoIP databases (for IPv4 and IPv6)
#. Run the `setup.py` script

.. note::

    Some requirements (e.g. Pillow) require some additional build
    dependencies when installing them.

The SpamPAD tests are split into *unittest* and *functional* tests.

*Unitests* perform checks against the current source code and **not**
the installed version of SpamPAD. To run all the unittests suite::

    py.test tests/unit/

*Functional* tests perform checks against the installed version of
SpamPAD and **not** the current source code. These are more extensive
and generally take longer to run. They also might need special setup.
To run the full suite of functional tests::

    env USE_PICKLES=0 py.test tests/functional/ (or py.test tests/functional/)


If you want to compile rules and avoid re-parsing:

    env USE_PICKLES=1 py.test tests/functional/

Or you can run *all* the tests with just::

    py.test


An example for Python3 would be:

.. code-block:: bash

    sudo apt-get install python3-dev libjpeg-dev build-essential zlib1g-dev
    virtualenv -p /usr/bin/python3 ~/pad-env
    source ~/pad-env/bin/activate
    git clone https://github.com/SpamExperts/SpamPAD
    cd SpamPAD
    pip install sqlalchemy || pip install pymysql
    pip install -r requirements/base.txt
    pip install -r requirements/python3.txt
    pip install -r requirements/tests.txt
    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
    gunzip GeoIP.dat.gz
    wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
    gunzip GeoIPv6.dat.gz
    python setup.py install
    env USE_PICKLES=0 py.test
    env USE_PICKLES=0 py.test


.. note::

    See also the `.travis.yml` file where all these instructions are set
    for the automatic builds.

Building documentation
======================

In order to build the documentation based on the docs files from the
repository:

#. Run the same steps for running the tests (including installing all
   requirements, installing SpamPAD, etc.).
#. Install the documentation libraries from `requirements/docs.txt`
#. Change directory to `docs`
#. Run `make html`
#. The HTML version of the documentation will be generated in the
   `docs/_build/` directory.

See also the helper script `docs/generate_plugin_doc.py` that generates
a documentation page for the specified plugin. After adding a new plugin:

* Use the script to generate a new page for it
* Add a reference to the list from `docs/plugins.rst`
* Add autodoc to `docs/pad.plugins.rst`

License
=======

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License `version 2 <http://www.gnu.org/licenses/gpl-2.0.html>`_
only of the License.
