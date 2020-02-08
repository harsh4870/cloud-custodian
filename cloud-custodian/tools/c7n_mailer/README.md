# c7n-mailer: Custodian Mailer

[//]: # (         !!! IMPORTANT !!!                    )
[//]: # (This file is moved during document generation.)
[//]: # (Only edit the original document at ./tools/c7n_mailer/README.md)

A mailer implementation for Custodian. Outbound mail delivery is still somewhat
organization-specific, so this at the moment serves primarily as an example
implementation.

> The Cloud Custodian Mailer can now be easily run in a Docker container. Click [here](https://hub.docker.com/r/cloudcustodian/mailer) for details.


## Message Relay

Custodian Mailer subscribes to an SQS queue, looks up users, and sends email
via SES and/or send notification to DataDog. Custodian lambda and instance policies can send to it. SQS queues
should be cross-account enabled for sending between accounts.


## Tutorial

Our goal in starting out with the Custodian mailer is to install the mailer,
and run a policy that triggers an email to your inbox.

1. [Install](#developer-install-os-x-el-capitan) the mailer on your laptop (if you are not running as a [Docker container](https://hub.docker.com/r/cloudcustodian/mailer)
   - or use `pip install c7n-mailer`
2. In your text editor, create a `mailer.yml` file to hold your mailer config.
3. In the AWS console, create a new standard SQS queue (quick create is fine).
   Copy the queue URL to `queue_url` in `mailer.yml`.
4. In AWS, locate or create a role that has read access to the queue. Grab the
   role ARN and set it as `role` in `mailer.yml`.

There are different notification endpoints options, you can combine both.

### Email:
Make sure your email address is verified in SES, and set it as
`from_address` in `mailer.yml`. By default SES is in sandbox mode where you
must
[verify](http://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses.html)
every individual recipient of emails. If need be, make an AWS support ticket to
be taken out of SES sandbox mode.

Your `mailer.yml` should now look something like this:

```yaml
queue_url: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
role: arn:aws:iam::123456790:role/c7n-mailer-test
from_address: you@example.com
```

You can also set `region` if you are in a region other than `us-east-1` as well as `lambda_tags` to give the mailer tags.

```yaml
region: us-east-2
lambda_tags:
  owner: ops
```

Now let's make a Custodian policy to populate your mailer queue. Create a
`test-policy.yml` file with this content (update `to` and `queue` to match your
environment)

```yaml
  policies:
  - name: c7n-mailer-test
    resource: sqs
    filters:
      - "tag:MailerTest": absent
    actions:
      - type: notify
        template: default
        priority_header: '2'
        subject: testing the c7n mailer
        to:
          - you@example.com
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
```

### DataDog:
The standard way to do a DataDog integration is use the
c7n integration with AWS CloudWatch and use the
[DataDog integration with AWS](https://docs.datadoghq.com/integrations/amazon_web_services/)
to collect CloudWatch metrics. The mailer/messenger integration is only
for the case you don't want or you can't use AWS CloudWatch.

Note this integration requires the additional dependency of datadog python bindings:
```
pip install datadog
```

Your `mailer.yml` should now look something like this:

```yaml
queue_url: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
role: arn:aws:iam::123456790:role/c7n-mailer-test
datadog_api_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
datadog_application_key: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

(Also set `region` if you are in a region other than `us-east-1`.)

Now let's make a Custodian policy to populate your mailer queue. Create a
`test-policy.yml`:

```yaml
policies:
  - name: c7n-mailer-test
    resource: ebs
    filters:
     - Attachments: []
    actions:
      - type: notify
        to:
          - datadog://?metric_name=datadog.metric.name&metric_value_tag=Size
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
```

There is a special `to` format that specifies datadog delivery, and includes the datadog configuration via url parameters.
- metric_name: is the name of the metrics send to DataDog
- metric_value_tag: by default the metric value send to DataDog is `1` but if you want to use one of the tags returned in the policy you can set it with the attribute `metric_value_tag`, for example in the `test-policy.yml` the value used is the size of the EBS volume. The value must be a number and it's transformed to a float value.

### Slack:

The Custodian mailer supports Slack messaging as a separate notification mechanism for the SQS transport method. To enable Slack integration, you must specify a Slack token in the `slack_token` field under the `mailer.yml` file.

```yaml
queue_url: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
role: arn:aws:iam::123456790:role/c7n-mailer-test
slack_token: xoxo-token123
```

To enable Slack messaging, several unique fields are evaluated in the policy, as shown in the below example:

```
policies:
  - name: c7n-mailer-test
    resource: ebs
    filters:
     - Attachments: []
    actions:
      - type: notify
        slack_template: slack
        to:
          - slack://owners
          - slack://foo@bar.com
          - slack://#custodian-test
          - slack://webhook/#c7n-webhook-test
          - slack://tag/resource_tag
          - https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
```

Slack messages support use of a unique template field specified by `slack_template`. This field is unique and usage will not break
existing functionality for messages also specifying an email template in the `template` field. This field is optional, however,
and if not specified, the mailer will use the default value `slack_default`.

Slack integration for the mailer supports several flavors of messaging, listed below. These are not mutually exclusive and any combination of the types can be used, but the preferred method is [incoming webhooks](https://api.slack.com/incoming-webhooks).

| Requires&nbsp;`slack_token` | Key                                                                             | Type   | Notes                                                                                                                                                           |
|:---------------------------:|:--------------------------------------------------------------------------------|:-------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
|             No              | `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX` | string | **(PREFERRED)** Send to an [incoming webhook](https://api.slack.com/incoming-webhooks) (the channel is defined in the webhook)                                  |
|             Yes             | `slack://owners`                                                                | string | Send to the recipient list generated within email delivery logic                                                                                                |
|             Yes             | `slack://foo@bar.com`                                                           | string | Send to the recipient specified by email address foo@bar.com                                                                                                    |
|             Yes             | `slack://#custodian-test`                                                       | string | Send to the Slack channel indicated in string, i.e. #custodian-test                                                                                             |
|             No              | `slack://webhook/#c7n-webhook-test`                                             | string | **(DEPRECATED)** Send to a Slack webhook; appended with the target channel. **IMPORTANT**: *This requires a `slack_webhook` value defined in the `mailer.yml`.* |
|             Yes             | `slack://tag/resource-tag`                                                      | string | Send to target found in resource tag. Example of value in tag: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX                    |

Slack delivery can also be set via a resource's tag name. For example, using "slack://tag/slack_channel" will look for a tag name of 'slack_channel', and if matched on a resource will deliver the message to the value of that resource's tag:

`slack_channel:https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`

Delivery via tag has been tested with webhooks but should support all delivery methods.

### Splunk HTTP Event Collector (HEC)

The Custodian mailer supports delivery to the HTTP Event Collector (HEC) endpoint of a Splunk instance as a separate notification mechanism for the SQS transport method. To enable Splunk HEC integration, you must specify the URL to the HEC endpoint as well as a valid username and token:

```yaml
queue_url: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
role: arn:aws:iam::123456790:role/c7n-mailer-test
splunk_hec_url: https://http-inputs-foo.splunkcloud.com/services/collector/event
splunk_hec_token: 268b3cc2-f32e-4a19-a1e8-aee08d86ca7f
```

To send events for a policy to the Splunk HEC endpoint, add a ``to`` address notify action specifying the name of the Splunk index to send events to in the form ``splunkhec://indexName``:

```
policies:
  - name: c7n-mailer-test
    resource: ebs
    filters:
     - Attachments: []
    actions:
      - type: notify
        to:
          - splunkhec://myIndexName
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
```

The ``splunkhec://indexName`` address type can be combined in the same notify action with other destination types (e.g. email, Slack, DataDog, etc).

### Now run:

```
c7n-mailer --config mailer.yml --update-lambda && custodian run -c test-policy.yml -s .
```

Note: You can set the profile via environment variable e.g. `export AWS_DEFAULT_PROFILE=foo`

You should see output similar to the following:

```
(env) $ c7n-mailer --config mailer.yml --update-lambda && custodian run -c test-policy.yml -s .
DEBUG:custodian.lambda:Created custodian lambda archive size: 3.01mb
2017-01-12 07:55:16,227: custodian.policy:INFO Running policy c7n-mailer-test resource: sqs region:default c7n:0.8.22.0
2017-01-12 07:55:16,229: custodian.policy:INFO policy: c7n-mailer-test resource:sqs has count:1 time:0.00
2017-01-12 07:55:18,017: custodian.actions:INFO sent message:dead-beef policy:c7n-mailer-test template:default count:1
2017-01-12 07:55:18,017: custodian.policy:INFO policy: c7n-mailer-test action: notify resources: 1 execution_time: 1.79
(env) $
```

Check the AWS console for a new Lambda named `cloud-custodian-mailer`. The
mailer runs every five minutes, so wait a bit and then look for an email in
your inbox. If it doesn't appear, look in the lambda's logs for debugging
information. If it does, congratulations! You are off and running with the
Custodian mailer.


## Usage & Configuration

Once [installed](#developer-install-os-x-el-capitan) you should have a
`c7n-mailer` executable on your path:
aws
```
(env) $ c7n-mailer
usage: c7n-mailer [-h] -c CONFIG
c7n-mailer: error: argument -c/--config is required
(env) $
```

Fundamentally what `c7n-mailer` does is deploy a Lambda (using
[Mu](http://cloudcustodian.io/docs/policy/mu.html)) based on
configuration you specify in a YAML file.  Here is [the
schema](./c7n_mailer/cli.py#L11-L41) to which the file must conform,
and here is a description of the options:

| Required? | Key             | Type             | Notes                                                                                                                                                                               |
|:---------:|:----------------|:-----------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| &#x2705;  | `queue_url`     | string           | the queue to listen to for messages                                                                                                                                                 |
|           | `from_address`  | string           | default from address                                                                                                                                                                |
|           | `contact_tags`  | array of strings | tags that we should look at for address information                                                                                                                                 |

#### Standard Lambda Function Config

| Required? | Key                  | Type             |
|:---------:|:---------------------|:-----------------|
|           | `dead_letter_config` | object           |
|           | `memory`             | integer          |
|           | `region`             | string           |
| &#x2705;  | `role`               | string           |
|           | `runtime`            | string           |
|           | `security_groups`    | array of strings |
|           | `subnets`            | array of strings |
|           | `timeout`            | integer          |

#### Standard Azure Functions Config

| Required? | Key                   | Type   | Notes                                                                                  |
|:---------:|:----------------------|:-------|:---------------------------------------------------------------------------------------|
|           | `function_properties` | object | Contains `appInsights`, `storageAccount` and `servicePlan` objects                     |
|           | `appInsights`         | object | Contains `name`, `location` and `resourceGroupName` properties                       |
|           | `storageAccount`      | object | Contains `name`, `location` and `resourceGroupName` properties                       |
|           | `servicePlan`         | object | Contains `name`, `location`, `resourceGroupName`, `skuTier` and `skuName` properties |
|           | `name`                | string |                                                                                        |
|           | `location`            | string | Default: `west us 2`                                                                   |
|           | `resourceGroupName`   | string | Default `cloud-custodian`                                                              |
|           | `skuTier`             | string | Default: `Basic`                                                                       |
|           | `skuName`             | string | Default: `B1`                                                                          |




#### Mailer Infrastructure Config

| Required? | Key                         | Type    | Notes                                                                                                                                                                                              |
|:---------:|:----------------------------|:--------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|           | `cache_engine`              | string  | cache engine; either sqlite or redis                                                                                                                                                               |
|           | `cross_accounts`            | object  | account to assume back into for sending to SNS topics                                                                                                                                              |
|           | `debug`                     | boolean | debug on/off                                                                                                                                                                                       |
|           | `ldap_bind_dn`              | string  | eg: ou=people,dc=example,dc=com                                                                                                                                                                    |
|           | `ldap_bind_user`            | string  | eg: FOO\\BAR                                                                                                                                                                                       |
|           | `ldap_bind_password`        | string  | ldap bind password                                                                                                                                                                                 |
|           | `ldap_bind_password_in_kms` | boolean | defaults to true, most people (except capone) want to set this to false. If set to true, make sure `ldap_bind_password` contains your KMS encrypted ldap bind password as a base64-encoded string. |
|           | `ldap_email_attribute`      | string  |                                                                                                                                                                                                    |
|           | `ldap_email_key`            | string  | eg 'mail'                                                                                                                                                                                          |
|           | `ldap_manager_attribute`    | string  | eg 'manager'                                                                                                                                                                                       |
|           | `ldap_uid_attribute`        | string  |                                                                                                                                                                                                    |
|           | `ldap_uid_regex`            | string  |                                                                                                                                                                                                    |
|           | `ldap_uid_tags`             | string  |                                                                                                                                                                                                    |
|           | `ldap_uri`                  | string  | eg 'ldaps://example.com:636'                                                                                                                                                                       |
|           | `redis_host`                | string  | redis host if cache_engine == redis                                                                                                                                                                |
|           | `redis_port`                | integer | redis port, default: 6369                                                                                                                                                                          |
|           | `ses_region`                | string  | AWS region that handles SES API calls                                                                                                                                                              |

#### SMTP Config

| Required? | Key             | Type             | Notes                                                                                                                                                                               |
|:---------:|:----------------|:-----------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|           | `smtp_server`   | string           | to configure your lambda role to talk to smtpd in your private vpc, see [here](https://docs.aws.amazon.com/lambda/latest/dg/vpc.html) |                                             |
|           | `smtp_port`     | integer          | smtp port (default is 25)                                                                                                                                                           |
|           | `smtp_ssl`      | boolean          | this defaults to True                                                                                                                                                               |
|           | `smtp_username` | string           |                                                                                                                                                                                     |
|           | `smtp_password` | secured string   |                                                                                                                                                                                     |

If `smtp_server` is unset, `c7n_mailer` will use AWS SES or Azure SendGrid.

#### DataDog Config

| Required? | Key                       | Type   | Notes                    |
|:---------:|:--------------------------|:-------|:-------------------------|
|           | `datadog_api_key`         | string | DataDog API key.         |
|           | `datadog_application_key` | string | Datadog application key. |

These fields are not necessary if c7n_mailer is run in a instance/lambda/etc with the DataDog agent.

#### Slack Config

| Required? | Key           | Type   | Notes           |
|:---------:|:--------------|:-------|:----------------|
|           | `slack_token` | string | Slack API token |

#### SendGrid Config

| Required? | Key                | Type           | Notes              |
|:---------:|:-------------------|:---------------|:-------------------|
|           | `sendgrid_api_key` | secured string | SendGrid API token |
SendGrid is only supported for Azure Cloud use with Azure Storage Queue currently.

#### Splunk HEC Config

The following configuration items are *all* optional. The ones marked "Required for Splunk" are only required if you're sending notifications to ``splunkhec://`` destinations.

| Required for Splunk? | Key                     | Type             | Notes                                                                                                                              |
|:--------------------:|:------------------------|:-----------------|:-----------------------------------------------------------------------------------------------------------------------------------|
|       &#x2705;       | `splunk_hec_url`        | string           | URL to your Splunk HTTP Event Collector endpoint                                                                                   |
|       &#x2705;       | `splunk_hec_token`      | string           | Splunk HEC authentication token for specified username                                                                             |
|                      | `splunk_remove_paths`   | array of strings | List of [RFC6901](http://tools.ietf.org/html/rfc6901) JSON Pointers to remove from the event, if present, before sending to Splunk |
|                      | `splunk_actions_list`   | boolean          | If true, add an `actions` list to the top-level message sent to Splunk, containing the names of all non-notify actions taken       |
|                      | `splunk_max_attempts`   | integer          | Maximum number of times to try POSTing data to Splunk HEC (default 4)                                                              |
|                      | `splunk_hec_max_length` | integer          | Maximum data length that Splunk HEC accepts; an error will be logged for any message sent over this length                         |

#### SDK Config

| Required? | Key           | Type   | Notes |
|:---------:|:--------------|:-------|:------|
|           | `http_proxy`  | string |       |
|           | `https_proxy` | string |       |
|           | `profile`     | string |       |


#### Secured String

In order to ensure sensitive data is not stored plaintext in a policy, `c7n-mailer` supports secured
strings. You can treat it as a regular `string` or use `secured string` features.

##### AWS

You can use KMS to encrypt your secrets and use encrypted secret in mailer policy.
Custodian tries to decrypt the string using KMS, if it fails c7n treats it as a plaintext secret.

```yaml
    plaintext_secret: <raw_secret>
    secured_string: <encrypted_secret>
```

##### Azure

You can store your secrets in Azure Key Vault secrets and reference them from the policy.

```yaml
    plaintext_secret: <raw_secret>
    secured_string:
        type: azure.keyvault
        secret: https://your-vault.vault.azure.net/secrets/your-secret
```

Note: `secrets.get` permission on the KeyVault for the Service Principal is required.

## Configuring a policy to send email

Outbound email can be added to any policy by including the `notify` action.

```yaml

policies:
  - name: bad-apples
    resource: asg
    filters:
     - "tag:ASV": absent
    actions:
      - type: notify
        template: default
        template_format: 'html'
        priority_header: '1'
        subject: fix your tags
        to:
          - resource-owner
        owner_absent_contact:
          - foo@example.com
        transport:
          type: sqs
          queue: https://sqs.us-east-1.amazonaws.com/80101010101/cloud-custodian-message-relay
```

So breaking it down, you add an action of type `notify`. You can specify a
template that's used to format the email; customizing templates is described
[below](#writing-an-email-template).

The `to` list specifies the intended recipient for the email. You can specify
either an email address, an SNS topic, a Datadog Metric, or a special value. The special values
are either

- `resource-owner`, in which case the email will be sent to the listed
  `OwnerContact` tag on the resource that matched the policy, or
- `event-owner` for push-based/realtime policies that will send to the user
  that was responsible for the underlying event.
- `priority_header` to indicate the importance of an email with [headers](https://www.chilkatsoft.com/p/p_471.asp). Different emails clients will display stars, exclamation points or flags depending on the value. Should be an string from 1 to 5.

Both of these special values are best effort, i.e., if no `OwnerContact` tag is
specified then `resource-owner` email will not be delivered, and in the case of
`event-owner` an instance role or system account will not result in an email.

The optional `owner_absent_contact` list specifies email addresses to notify only if
the `resource-owner` special option was unable to find any matching owner contact
tags.

In addition, you may choose to use a custom tag instead of the default `OwnerContact`.  In order to configure this, the mailer.yaml must be modified to include the contact_tags and the custom tag.  The `resource-owner` will now email the custom tag instead of `OwnerContact`. 

```yaml
contact_tags:
  - "custom_tag"
```


For reference purposes, the JSON Schema of the `notify` action:

```json
{
  "type": "object",
  "required": ["type", "transport", "to"],
  "properties": {
    "type": {"enum": ["notify"]},
    "to": {"type": "array", "items": {"type": "string"}},
    "owner_absent_contact": {"type": "array", "items": {"type": "string"}},
    "subject": {"type": "string"},
    "priority_header": {"type": "string"},
    "template": {"type": "string"},
    "transport": {
      "type": "object",
      "required": ["type", "queue"],
      "properties": {
        "queue": {"type": "string"},
        "region": {"type": "string"},
        "type": {"enum": ["sqs"]}
      }
    }
  }
}
```

## Using on Azure

Requires:

- `c7n_azure` package.  See [Installing Azure Plugin](https://cloudcustodian.io/docs/azure/gettingstarted.html#azure-install-cc)
- SendGrid account. See [Using SendGrid with Azure](https://docs.microsoft.com/en-us/azure/sendgrid-dotnet-how-to-send-email)
- [Azure Storage Queue](https://azure.microsoft.com/en-us/services/storage/queues/)

The mailer supports an Azure Storage Queue transport and SendGrid delivery on Azure.
Configuration for this scenario requires only minor changes from AWS deployments.

You will need to grant `Storage Queue Data Contributor` role on the Queue for the identity
mailer is running under.

The notify action in your policy will reflect transport type `asq` with the URL
to an Azure Storage Queue.  For example:

```yaml
policies:
  - name: azure-notify
    resource: azure.resourcegroup
    description: send a message to a mailer instance
    actions:
      - type: notify
        template: default
        priority_header: '2'
        subject: Hello from C7N Mailer
        to:
          - you@youremail.com
        transport:
          type: asq
          queue: https://storageaccount.queue.core.windows.net/queuename
```

In your mailer configuration, you'll need to provide your SendGrid API key as well as
prefix your queue URL with `asq://` to let mailer know what type of queue it is:

```yaml
queue_url: asq://storageaccount.queue.core.windows.net/queuename
from_address: you@youremail.com
sendgrid_api_key: SENDGRID_API_KEY
```

The mailer will transmit all messages found on the queue on each execution, and will retry
sending 3 times in the event of a failure calling SendGrid.  After the retries the queue
message will be discarded.

In addition, SendGrid delivery on Azure supports using resource tags to send emails. For example, in the `to` field:

```yaml
to:
  - tag:OwnerEmail
```

This will find the email address associated with the resource's `OwnerEmail` tag, and send an email to the specified address.
If no tag is found, or the associated email address is invalid, no email will be sent. 

#### Deploying Azure Functions

The `--update-lambda` CLI option will also deploy Azure Functions if you have an Azure
mailer configuration.

`c7n-mailer --config mailer.yml --update-lambda`

where a simple `mailer.yml` using Consumption functions may look like:

```yaml
queue_url: asq://storage.queue.core.windows.net/custodian
from_address: foo@mail.com
sendgrid_api_key: <key>
function_properties:
  servicePlan:
    name: 'testmailer1'
```

## Writing an email template

Templates are authored in [jinja2](http://jinja.pocoo.org/docs/dev/templates/).
Drop a file with the `.j2` extension into the a templates directory, and send a pull request to this
repo. You can then reference it in the `notify` action as the `template`
variable by file name minus extension. Templates ending with `.html.j2` are
sent as HTML-formatted emails, all others are sent as plain text.

You can use `-t` or `--templates` cli argument to pass custom folder with your templates.

The following variables are available when rendering templates:

| variable          | value                                                        |
|:------------------|:-------------------------------------------------------------|
| `recipient`       | email address                                                |
| `resources`       | list of resources that matched the policy filters            |
| `event`           | for CWE-push-based lambda policies, the event that triggered |
| `action`          | `notify` action that generated this SQS message              |
| `policy`          | policy that triggered this notify action                     |
| `account`         | short name of the aws account                                |
| `region`          | region the policy was executing in                           |
| `execution_start` | The time policy started executing                            |

The following extra global functions are available:

| signature                                                                    | behavior                                                                                          |
|:-----------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------|
| `format_struct(struct)`                                                      | pretty print a json structure                                                                     |
| `resource_tag(resource, key)`                                                | retrieve a tag value from a resource or return an empty string, aliased as get_resource_tag_value |
| `format_resource(resource, resource_type)`                                   | renders a one line summary of a resource                                                          |
| `date_time_format(utc_str, tz_str='US/Eastern', format='%Y %b %d %H:%M %Z')` | customize rendering of an utc datetime string                                                     |
| `search(expression, value)`                                                  | jmespath search value using expression                                                            |
| `yaml_safe(value)`                                                           | yaml dumper                                                                                       |

The following extra jinja filters are available:

| filter                                                                                         | behavior                                                                                                                                                                                      |
|:-----------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| <code>utc_string&#124;date_time_format(tz_str='US/Pacific', format='%Y %b %d %H:%M %Z')</code> | pretty [format](https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior) the date / time                                                                                   |
| <code>30&#124;get_date_time_delta</code>                                                       | Convert a time [delta](https://docs.python.org/2/library/datetime.html#datetime.timedelta) like '30' days in the future, to a datetime string. You can also use negative values for the past. |


## Developer Install (OS X El Capitan)

Clone the repository:
```
$ git clone https://github.com/cloud-custodian/cloud-custodian
```
Install dependencies (with virtualenv):
```
$ virtualenv c7n_mailer
$ source c7n_mailer/bin/activate
$ cd tools/c7n_mailer
$ pip install -r requirements.txt
```
Install the extensions:
```
python setup.py develop
```

## Testing Templates and Recipients

A ``c7n-mailer-replay`` entrypoint is provided to assist in testing email notifications
and templates. This script operates on an actual SQS message from cloud-custodian itself,
which you can either retrieve from the SQS queue or replicate locally. By default it expects
the message file to be base64-encoded, gzipped JSON, just like c7n sends to SQS. With the
``-p`` | ``--plain`` argument, it will expect the message file to contain plain JSON.

``c7n-mailer-replay`` has three main modes of operation:

* With no additional arguments, it will render the template specified by the policy the
  message is for, and actually send mail from the local machine as ``c7n-mailer`` would.
  This only works with SES, not SMTP.
* With the ``-T`` | ``--template-print`` argument, it will log the email addresses that would
  receive mail, and print the rendered message body template to STDOUT.
* With the ``-d`` | ``--dry-run`` argument, it will print the actual email body (including headers)
  that would be sent, for each message that would be sent, to STDOUT.
  
#### Testing Templates for Azure

The ``c7n-mailer-replay`` entrypoint can be used to test templates for Azure with either of the arguments:
* ``-T`` | ``--template-print`` 
* ``-d`` | ``--dry-run`` 
  
Running ``c7n-mailer-replay`` without either of these arguments will throw an error as it will attempt
to authorize with AWS. 

The following is an example for retrieving a sample message to test against templates:

* Run a policy with the notify action, providing the name of the template to test, to populate the queue.

* Using the azure cli, save the message locally: 
```
$ az storage message get --queue-name <queuename> --account-name <storageaccountname> --query '[].content' > test_message.gz
```
* The example message can be provided to ``c7n-mailer-replay`` by running:

```
$ c7n-mailer-replay test_message.gz -T --config mailer.yml
```
