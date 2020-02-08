.. _gcp_contribute:

Developer Guide
=================

The c7n developer install includes c7n_gcp.  A shortcut for creating a virtual env for development is available
in the makefile:

.. code-block:: bash

    $ make install
    $ source bin/activate

This creates a virtual env in your enlistment and installs all packages as editable.

Instead, you can do `pip install -r tools/c7n_gcp/requirements.txt` to install dependencies.

Adding New GCP Resources
==========================

Create New GCP Resource
-------------------------

Most resources extend the QueryResourceManager class. Each class definition will use the @resources.register('<resource_name>') decorator to register that class as a Custodian resource substituting <resource_name> with the new resource name. The name specified in the decorator is how the resource will be referenced within policies.

Each resource also contains an internal class called `resource_type`, which contains metadata about the resource definition, and has the following attributes:


- ``service`` is required field, part of the request to GCP resource,
    The name of GCP service.
- ``component`` is required field, part of the request to GCP resource,
    The name of GCP resource,
- ``version`` is required field, part of the request to GCP resource,
    It is the `version` of used resource API,
- ``enum_spec`` is a required field,
     It has a tuple of (`enum_operation`, `list_operation`, `extra_args`).

    - `enum_operation`: the name of the GCP resource method used to retrieve the list of resources,

    - `list_operation`: the JMESPath of the field name which contains the resource list in the JSON response body,

    - `extra_args`: can be used to set up additional params for a request to GCP.
- ``id`` is required field,
    It's a field name of the response field that have to be used as resource identifier. The `id` value is used for filtering.
- ``scope`` is optional field, default is None,
    The scope of the Custodian resource. There are available 2 options: `project` or `None`. If the `scope` has a value `project` the GOOGLE_CLOUD_PROJECT variable will be used for building request to GCP resource. If the scope is `None` the request to GCP is built ignoring the GOOGLE_CLOUD_PROJECT variable.
- ``parent_spec`` is an optional field that allows to build additional requests to parent resources, default is None.
    The field is used when the request to GCP resource should be created with extra parameters that can be loaded from parent resources.
    The resource should extend ChildResourceManager instead of QueryResourceManager and use ChildTypeInfo instead of TypeInfo to use the field.
    The `parent_spec` has following fields: `resource`, `child_enum_params`, `parent_get_params`, `use_child_query`.

    - The field `resource` has value of the `resource_name` from @resources.register('<resource_name>') that is used for the target parent resource.

    - The field `child_enum_params` is an array of tuples each of which maps parent instance field (first tuple element) to child's list argument (second tuple element). The mappings are used for building `list` requests to parent resources. It works by the next scenario. First of all it loads a list of instances from parent resource. Further it loads instances for original resources using GCP resource field values from the loaded parent resources. It uses mappings for GCP resource fields from `child_enum_params`. The first field in a tuple is a field from parent resource, the second one is the mapped original resource field name.

    - The field `parent_get_params` is an array of tuples each of which maps child instance field (first tuple element) to parent's `resource_info` field. The `resource_info` object has fields like Stackdriver log has. There are 2 options for the fields set: either `resource.labels` and `protoPayload.resourceName` or a log of the full event. The mappings are used for building `get` requests to parent resources.

    - The field `use_child_query` controls whether the `query` block of the current resource should be copied to its parent.

An example that uses `parent_spec` is available below.

.. code-block:: python

    # the class extends ChildResourceManager
    @resources.register('bq-table')
    class BigQueryTable(ChildResourceManager):

        # the class extends ChildTypeInfo
        class resource_type(ChildTypeInfo):
            service = 'bigquery'  # the name of the GCP service
            version = 'v2'        # the version of the GCP service
            component = 'tables'  # the component of the GCP service
                # The `list` method in the resource. https://cloud.google.com/bigquery/docs/reference/rest/v2/tables/list
                # It requires 2 request params: `projectId` and `datasetId`. Since the resource has a parent the params will
                # be extracted from parent's instance
            enum_spec = ('list', 'tables[]', None)
            scope_key = 'projectId'
            id = 'id'
            parent_spec = {
                # the name of Custodian parent resource.
                'resource': 'bq-dataset',
                'child_enum_params': [
                    # Extract the `datasetReference.datasetId` field from a parent instance and use its value
                    # as the `datasetId` argument for child's `list` method (see `resource_type.enum_spec`)
                    ('datasetReference.datasetId', 'datasetId'),
                ],
                'parent_get_params': [
                    # Extract the `tableReference.projectId` field from a child instance and use its value
                    # as the `projectId` event's field for parent's `get` method (see `resource_type.get`)
                    ('tableReference.projectId', 'projectId'),
                    # Similar to above
                    ('tableReference.datasetId', 'datasetId'),
                ]
            }

            @staticmethod
            def get(client, event):
                return client.execute_query('get', {
                    'projectId': event['project_id'],
                    'datasetId': event['dataset_id'],
                    'tableId': event['resourceName'].rsplit('/', 1)[-1]
                })

Most resources have get methods that are created based on the corresponding `get` method of the actual GCP resource.
As a rule the Custodian `get` method has `resource_info` param. The param has fields that can be found in Stackdriver logs  in `protoPayload.resourceName` and `resource` fields. Examples of the Stackdriver logs are available in tools/c7n_gcp/tests/data/events folder.

There is an example of the resource below.

.. code-block:: python

    from c7n_gcp.provider import resources
    from c7n_gcp.query import QueryResourceManager, TypeInfo


    @resources.register('loadbalancer-address')
    class LoadBalancingAddress(QueryResourceManager):

        class resource_type(TypeInfo):
            service = 'compute'
            component = 'addresses'
            version = 'v1'
            enum_spec = ('aggregatedList', 'items.*.addresses[]', None)
            scope = 'project'
            id = 'name'

        @staticmethod
        def get(client, resource_info):
            return client.execute_command('get', {
                'project': resource_info['project_id'],
                'region': resource_info['location'],
                'address': resource_info[
                    'resourceName'].rsplit('/', 1)[-1]})

Load New GCP Resource
---------------------

If you created a new module for a GCP service (i.e. this was the first resource implemented for this service in Custodian),
then import the new service module in entry.py:

``entry.py``.

.. code-block:: python

    import c7n_gcp.resources.<name of a file with created resources>

Each resource has to have test cases. There are implemented test cases for resources list methods and get methods.

Testing
=========

Test cases for resources list methods
--------------------------------------

To create a test case for `list` method is used following scenario.

- A factory is created based on recording real data from a GCP project resource.

    .. code-block:: python

        factory = self.record_flight_data(<name of a file>, project_id=project_id)

The `name of a file` means the folder name that has JSON file(s) with expected response(s) on the request from a testing policy.

- The factory is used for creating the testing policy.

    .. code-block:: python

        policy = self.load_policy(
            {'name': '<policy name>',
             'resource': 'gcp.<name of the resource>'},
            session_factory=factory)

The `policy name` means the name of the policy. It can be used any name of the policy.
The `name of the resource` is the name of testing resource. It's the `resource_name` from @resources.register('<resource_name>').

- The result of the running policy is a list of resources. Below code can be used for the policy running:

    .. code-block:: python

        resources = policy.run()

- The next step is current results verification with expecting results.

- Last step is replacing `record_flight_data` in creating the factory by `replay_flight_data`. After that step recorded data in JSON files will be used instead of real data. Name of project in GOOGLE_CLOUD_PROJECT may be replaced on any one.


Test cases for resources get methods
-------------------------------------

To create a test case for `get` method is used following scenario.

- A factory was created based on recording real data from a GCP project resource.

    .. code-block:: python

        factory = self.record_flight_data(<name of a file>, project_id=project_id)

The `name of a file` means the folder name that has JSON file(s) with expected response(s) on the request from a testing policy.

- The factory is used for creating the testing policy.

    .. code-block:: python

        policy = self.load_policy(
            {'name': '<policy name>',
             'resource': 'gcp.<name of the resource>',
             'mode': {
                 'type': 'gcp-audit',
                 'methods': []
             }},
            session_factory=factory)

The `policy name` means the name of the policy. It can be used any name of the policy.
The `name of the resource` is the name of testing resource. It's the `resource_name` from @resources.register('<resource_name>').
The policy should also be tested in gcp-audit mode to ensure that testing the resource in a serverless environment is covered.

- The next step is invoking `get` method of GCP resource that is used for development. The result of invoking is logged in Stackdriver. The result should be copied from Stackdriver log and be put into a JSON file in tools/c7n_gcp/test/data/events folder.

- The next step is creating an event based on JSON file that was created in the previous step. The event is run within policy's execution mode. The sample is below.

    .. code-block:: python

        exec_mode = policy.get_execution_mode()
        event = event_data('<name of JSON file>')
        instances = exec_mode.run(event, None)

- Further current results should be verified with expecting results.

- Last step is replacing `record_flight_data` in creating the factory by `replay_flight_data`. After that step recorded data in JSON files will be used instead of real data. Name of project in GOOGLE_CLOUD_PROJECT may be replaced on any one.

Running tests
--------------

Tests for c7n_gcp run automatically with other Custodian tests. See :ref:`Testing for Developers <developer-tests>` for information on how to run Tox.

If you'd like to run tests at the command line or in your IDE then reference `tox.ini` to see the required
environment variables and command lines for running `pytest`.

You can use `tox` to run all tests or instead you can use `pytest` and run only GCP tests (or only specific set of tests). Running recorded tests still requires some authentication, it is possible to use fake data for credentials to GCP and name of Google Cloud project.

.. code-block:: bash

  export GOOGLE_CLOUD_PROJECT=cloud-custodian
  export GOOGLE_APPLICATION_CREDENTIALS=data/credentials.json
  pytest tools/c7n_gcp/tests
