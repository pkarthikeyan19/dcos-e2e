.. code:: sh

    brew install https://raw.githubusercontent.com/dcos/dcos-e2e/master/dcosdocker.rb

To upgrade from an older version, run the following command:

.. code:: sh

    brew upgrade https://raw.githubusercontent.com/dcos/dcos-e2e/master/dcosdocker.rb

Or the latest ``master``:

Homebrew installs the dependencies for the latest released version and so installing ``master`` may not work.

.. code:: sh

    brew install --HEAD https://raw.githubusercontent.com/dcos/dcos-e2e/master/dcosdocker.rb

Run :ref:`dcos-docker-doctor` to make sure that your system is ready to go:

.. code-block:: console

   $ dcos-docker doctor
