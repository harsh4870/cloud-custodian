.. _lambda:

Lambda Support
--------------

Lambda provides for powerful realtime event based code execution in
response to infrastructure and application behavior. A number of
different Amazon services can be used as event sources.

CloudWatch Events
#################

`CloudWatch Events
<http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html>`_
(CWE) is a general event bus for AWS infrastructure. Currently, it covers
several major sources of information:

#. CloudTrail API calls over a poll period on CloudTrail delivery,
#. real-time instance status events,
#. autoscale group notifications, and
#. scheduled/periodic events.

CloudTrail provides a very rich data source over the entire range of AWS
services exposed via the audit trail that allows Custodian to define effective
realtime policies against any AWS product. Additionally, for EC2 instances we
can provide mandatory policy compliance - this means the non-compliant
resources never became available.

Cloud Custodian Integration
===========================

Custodian provides for policy level execution against any CWE event stream.
Each Custodian policy can be deployed as an independent Lambda function. The
only difference between a Custodian policy that runs in Lambda and one that
runs directly from the CLI in poll mode is the specification of the
subscription of the events in the mode config block of the policy.

Internally Custodian will reconstitute current state for all the resources
in the event, execute the policy against them, match against the
policy filters, and apply the policy actions to matching resources.


CloudTrail API Calls
++++++++++++++++++++

Lambdas can receive CWE over CloudTrail API calls with delay of 90s at P99.

.. code-block:: yaml

   policies:
     - name: ec2-tag-running
       resource: ec2
       mode:
         type: cloudtrail
         events:
          - RunInstances
       actions:
         - type: mark
           tag: foo
           msg: bar

Because the total AWS API surface area is so large most CloudTrail API
event subscriptions need two additional fields:

#. For CloudTrail events we need to reference the source API call.

#. To work transparently with existing resource policies, we also need to
   specify how to extract the resource IDs from the event via JMESPath so that
   the resources can be queried.

For very common API calls for policies, some `shortcuts
<https://github.com/cloud-custodian/cloud-custodian/blob/master/c7n/cwe.py#L28-L69>`_
have been defined to allow for easier policy writing as for the
``RunInstances`` API call above, which expands to:

.. code-block:: yaml

     events:
      - source: ec2.amazonaws.com
        event: RunInstances
        ids: "responseElements.instancesSet.items[].instanceId"


EC2 Instance State Events
+++++++++++++++++++++++++

Lambdas can receive EC2 instance state events in real time (seconds delay).

.. code-block:: yaml

   policies:
     - name: ec2-require-encrypted-volumes
       resource: ec2
       mode:
         type: ec2-instance-state
         events:
         - pending
       filters:
         - type: ebs
           key: Encrypted
           value: False
       actions:
         - mark
         - terminate


Periodic Function
+++++++++++++++++

We support both rate per unit time and cron expressions, per `scheduler syntax
<http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html>`_.

When using --assume on the custodian run cli command, the specified
role is also considered as the execution role to be attached to lambda
function that gets deployed. In such scenario it is not required to
specify the role attribute in the config block for mode. However, if
you are not using the --assume option, then it is required to add role
in the config-block of mode. When specifying role {account_id} is runtime
substituted so a policy can be used across accounts.

.. code-block:: yaml

   policies:
     - name: s3-bucket-check
       resource: s3
       mode:
         type: periodic
         schedule: "rate(1 day)"
         role: arn:aws:iam::{account_id}:role/some-role


Config Rules
############

`AWS Config rules
<http://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html>`_
allow you to invoke logic in response to configuration changes in your AWS
environment, and Cloud Custodian is the easiest way to write and provision
Config rules. Delay here is typically 1-15m (though the SLA on tag-only changes
is a bit higher).

In this section we'll look at how we would deploy the :ref:`quickstart
<quickstart>` example using Config. Before you proceed, make sure you've
removed the ``Custodian`` tag from any EC2 instance left over from the
quickstart.

First, modify ``custodian.yml`` to specify a mode type of ``config-rule``.
You'll also need the ARN of an IAM role to assume when running the Lambda that
Custodian is going to install for you. Sensible policies to add to that role would be
``AWSLambdaBasicExecutionRole`` and ``AWSConfigRulesExecutionRole``, on top of any permissions
your lambda is going to need to perform the actions you want it to perform.

.. code-block:: yaml

    policies:
      - name: my-first-policy
        mode:
            type: config-rule
            role: arn:aws:iam::123456789012:role/some-role
        resource: ec2
        filters:
          - "tag:Custodian": present
        actions:
          - stop

Then make sure that you've set up AWS Config. If you `go to the AWS Config console
<https://eu-west-1.console.aws.amazon.com/config/home>`_
and see the welcome screen instead of the dashboard, go through `the setup procedure first
<https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html>`_.

Now deploy the policy:

.. code-block:: bash

    custodian run -s . custodian.yml

That should give you log output like this::

    2017-01-25 05:43:01,539: custodian.policy:INFO Provisioning policy lambda my-first-policy
    2017-01-25 05:43:04,683: custodian.lambda:INFO Publishing custodian policy lambda function custodian-my-first-policy

Go check the AWS console to see the Lambda as well as the Config rule that
Custodian created. The Config rule should be listed as "Compliant" or "No
results reported" (if not, be sure you removed the ``Custodian`` tag from any
instance left over from the quickstart).

Now for the fun part! With your new policy installed, go ahead and create an
EC2 instance with a ``Custodian`` tag (any non-empty value), and wait (events
from Config are effectively delayed 15m up to 6hrs on tag changes). If all goes
well, you should eventually see that your new custom Config rule notices the
EC2 instance with the ``Custodian`` tag, and stops it according to your policy.

Congratulations! You have now installed your policy to run under Config rather
than from your command line.

Lambda Configuration
####################

Custodian lambdas support configuring all lambda options via keys on the lambda
mode in the YAML.  See AWS'
`AWS Lambda Function Configuration <https://docs.aws.amazon.com/lambda/latest/dg/resource-model.html>`_
page for the full list of configuration options avaible on a Lambda.

Refer to :ref:`aws-modes` for detailed explanation of the different ``type``
values and the corresponding additional configuration options each requires.

Here is an example YAML fragment that shows the options you are most likely to want or need to configure on a
lambda:

.. code-block:: yaml

    mode:
      type: cloudtrail
      events:
        - CreateBucket

      ##### ROLE #####
      # Specify the ARN role as either name or full ARN.  This shows
      # us running the lambda with the IAM role named Custodian.
      # Specifying role by name:
      role: Custodian
      # Or specifying using a full ARN
      # role: arn:aws:iam::123456789012:role/Custodian

      ##### TAGS #####
      # Specify the tags to assign to this Lambda.  We are setting a
      # tag named "Application" with a value of "Custodian", and a
      # "CreatedBy" tag with a value of "CloudCustodian".
      tags:
        Application: Custodian
        CreatedBy: CloudCustodian

Execution Options
#################

When running in Lambda you may want policy execution to run using particular 
options corresponding to those passed to the custodian CLI.

Execution in lambda comes with a default set of configuration which is 
different from the defaults you might set when running through the command line:

- Metrics are enabled
- Output dir is set to a random /tmp/ directory
- Caching of AWS resource state is disabled
- Account ID is automatically set with info from sts
- Region is automatically set to the region of the lambda (using the 
  AWS_DEFAULT_REGION environment variable in lambda)

When you want to override these settings, you must set 'execution-options' with
one of the following keys:

- region
- cache
- profile
- account_id
- assume_role
- log_group
- metrics
- output_dir
- cache_period
- dryrun

One useful thing we can do with these options is to make a policy execute in a 
different account using assume_role. A policy definition for this looks like:

.. code-block:: yaml

    policies:
      - name: my-first-policy-cross-account
        mode:
            type: periodic
            schedule: "rate(1 day)"
            role: arn:aws:iam::123456789012:role/lambda-role
            execution-options:
              assume_role: arn:aws:iam::210987654321:role/target-role
              metrics: aws
        resource: ec2
        filters:
          - "tag:Custodian": present
        actions:
          - stop

A couple of things to note here: 

#. Metrics are pushed using the assumed role which may or may not be desired
#. The mode must be periodic as there are restrictions on where policy 
   executions can run according to the mode:

   :Config: May run in a different region but not cross-account
   :Event: Only run in the same region and account
   :Periodic: May run in a different region and different account

