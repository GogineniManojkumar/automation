
# AWS VPC information to HTML tables report



This Python automation script helps fetch the vpc information and visualize it into HTML tables. this helps keep the vpc information documented in confluence or other by injecting an HTML file as a team reference.

as of now, the script fetches the following resources information: AWS VPC, Subnets, Routetables, Routes, NACLS, Internet Gateway, NAT Gateway, VPC Endpoints, VPC Peering Connections, Transit Gateway, attachments, and transit gateway routes.


## pre-requisites:
1. A working aws account with an access key and secret key or local aws cli profile.
2. (>3.5) and boto3 and following modules installed:
    boto3, os, sys, argparse, logging, datetime, jinja2
3. aws vpc name to generate the report.


# Execution
python vpc_info.py  - profile <AWS CLI Profile Name> -- vpc_name <VPC_NAME>

## Usage/Examples

```javascript
$ python vpc_info.py -h
usage: vpc_info.py [-h] --vpc_name VPC_NAME [--region REGION] [-p PROFILE]
                   [--dryrun]

VPC Subnets Information

options:
  -h, --help            show this help message and exit

required arguments:
  --vpc_name VPC_NAME   aws vpc name (default: None)

optional arguments:
  --region REGION       aws region (default: us-east-1)
  -p PROFILE, --profile PROFILE
                        aws profile (default: None)
  --dryrun              dryrun (default: False)

```


## Documentation

[Documentation](https://medium.com/@manojkumarcloud/export-aws-vpc-infomation-to-html-report-using-python-and-boto3-946b7d1951d9)


## Demo

![alt text](https://github.com/GogineniManojkumar/automation/blob/main/python/aws/vpc_html_report/img/demo.JPG?raw=true)
