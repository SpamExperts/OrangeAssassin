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
- `Source Code <http://github.com/SpamExperts/SpaPAD>`_

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
#. Install the base dependencies from `requirements/base.txt` with pip
#. Install the the dependencies for the python version you are using from the
   `requirements` folder
#. Install the dependencies for running tests from `requirements/tests.txt`
#. Download the GeoIP database::

    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
    gunzip GeoIP.dat.gz
    wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
    gunzip GeoIPv6.dat.gz

#. Run the `setup.py` script

    python setup.py install

The SpamPAD tests are split into *unittest* and *functional* tests.

*Unitests* perform checks against the current source code and **not**
the installed version of SpamPAD. To run all the unittests suite::

    py.test tests/unit/

*Functional* tests perform checks against the installed version of
SpamPAD and **not** the current source code. These are more extensive
and generally take longer to run. They also might need special setup.
To run the full suite of functional tests::

    py.test tests/functional/

Or you can run *all* the tests with just::

    py.test

.. note::

    See also the `.travis.yml` file where all these instructions are set
    for the automatic builds.


License
=======

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License `version 2 <http://www.gnu.org/licenses/gpl-2.0.html>`_
only of the License.
