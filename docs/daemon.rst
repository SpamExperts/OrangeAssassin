******
Daemon
******

This page explains how to run SpamPAD in daemon mode.

Starting the daemon
===================

Starting the daemon can be done by running the ``oad.py`` script with the
``--daemonize`` option and specifying a pidfile::

    oad.py -d -r /var/run/oad.pid

It's also recommended to active preforking with an appropriate number of
workers depending on your system::

    oad.py -d -r /var/run/oad.pid --prefork 4

Depending on your distribution you might also want to change the path to the
configuration directory and the site configuration directory. E.g::

    oad.py -d -r /var/run/oad.pid --prefork 4 -C /usr/share/spamassassin -S /etc/mail/spamassassin


You can also change the port and IP on which the daemon is listenting on::

    oad.py -d -r /var/run/oad.pid --prefork 4 -i 127.0.0.2 -p 30783

For more info see the ``--help`` option of the script.

Reloading the daemon
====================

Reloading the daemon can be achieved by sending the USR1 signal to the main
process OR by using the option of the ``oad.py`` script::

    oad.py -r /var/run/oad.pid reload

Stopping the daemon
===================

Gracefully stopping the daemon and the workers can be achieved by sending the
TERM signal to the main process OR by using the option of the ``oad.py``
script::

    oad.py -r /var/run/oad.pid stop



