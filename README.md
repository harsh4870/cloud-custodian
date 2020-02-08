# cloud-custodian-container

## Why?

To provide a standalone containerized runtime for Capital One's [Cloud Custodian] project.  

## Usage

### Prerequisites

You'll need these installed locally to to use this solution.

- [Local Docker client](https://www.docker.com/products/docker-desktop)
- [jq](https://stedolan.github.io/jq/)
- [awscli](https://github.com/aws/aws-cli)
- bash
- standard GNU tools:  mv, grep, awk, sort, wget, tar, make

### AWS Account - First-Time Setup 

### Tutorial

Our goal in starting out with the Custodian mailer is to install the mailer, and run a policy that triggers an email to your inbox.

Clone this Git repository locally  
In your text editor, create or edit mailer.yml file to hold your mailer config.
In the AWS console, create a new standard SQS queue (quick create is fine). Copy the queue URL to queue_url in mailer.yml.
In AWS, locate or create a IAM role that has read access to the queue. Grab the IAM role ARN and set it as role in mailer.yml.
There are different notification endpoints options, you can combine both.

### Email (Mailer setup):
Make sure your email address is verified in SES, and set it as from_address in mailer.yml. 

Your mailer.yml should now look something like this:

```yaml
queue_url: https://sqs.us-east-1.amazonaws.com/1234567890/c7n-mailer-test
role: arn:aws:iam::123456790:role/c7n-mailer-test
from_address: you@example.com
```

### Custodian policy (Custodian policy setup):
Now let's make a Custodian policy to populate your mailer queue. Create a policy.yml file with this content (update to and queue to match your environment)

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

### Docker - Running

Using the provided `Makefile`, you can run this container locally.  You need to set the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION` environment variables to do so.  You also need a `./logs` directory present.  Steps to run:

- `$ mkdir logs`
- export AWS_ACCESS_KEY_ID=""
- export AWS_SECRET_ACCESS_KEY=""
- export AWS_DEFAULT_REGION=""
- `$ make cust-lambda` (this sets up the Lambda for the mailer)
- `$ make cust-run` (this runs docker container of custodian (policy) and the mailer)
 
To push logs in S3 bucket 
- export S3_BUCKET_NAME="" (set bucket name to push logs inside it)
- `$ make logs-s3` (this runs docker container custodian (policy), mailer and send logs to s3 bucket)


### Docker - Building/Updating Images

*Follow Tutorial, Email, Custodian policy step first!*

- `$ make dkr-build`
- `$ make dkr-clean`

- To authenticat (e.g. `AWS_PROFILE` or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`), `make dkr-push-latest` will tag image latets & push your locally built container to your new ECR repo. 