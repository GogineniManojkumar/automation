# Lambda Permissions Policy
"""
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ecspermissions",
            "Effect": "Allow",
            "Action": [
                "ecs:UpdateService",
                "ecs:ListTasks",
                "ecs:DescribeServices",
                "ecs:DescribeTasks",
                "ecs:ListServices"
            ],
            "Resource": "arn:aws:ecs:*:*:service/*/*"
        },
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1::*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:us-east-1:*:log-group:/aws/lambda/<LOGS GROUP NAME>:*"
            ]
        }
    ]
}

"""
import sys
import boto3
import botocore
import os
import json
session = boto3.Session()
ecs = session.client('ecs')
stop_waiter=ecs.get_waiter('tasks_stopped')
start_waiter=ecs.get_waiter('tasks_running')

def update_service(service, cluster_name, action):
    if action == 'stop':
        count=0
    else:
        count=1

    print("Updating Tasks on Service "+service + " to desired count "+ str(count))
    response = ecs.update_service(
        cluster=cluster_name,
        service=service,
        desiredCount=count
    )
    return response

def get_all_tasks(cluster_name):
    response = ecs.list_tasks(
        cluster=cluster_name
    )
    return response['taskArns']

#example event data
#{
#  "CLUSTER_NAME": "test-cluster",
#  "ACTION": "start/stop"
#}

def lambda_handler(event, context):
    try:
        # get inputs from env vars
        cluster_name=event['CLUSTER_NAME']
        action=event['ACTION']
        # get current state of services 
        get_svcs = ecs.list_services(cluster=cluster_name)
        current_svc_list=[]
        for svcarn in get_svcs['serviceArns']:
            current_svc_list.append(svcarn.split('/')[-1])

        # invoke update function
        print(current_svc_list)
        for svc in current_svc_list:
            print('svc found: ' + svc)
            res=update_service(svc,cluster_name,action)
            print(res)
            
        if action == "stop":
            print("Waiting to Stop all the tasks")
            stop_waiter.wait(
                cluster=cluster_name,
                tasks=get_all_tasks(cluster_name),
                WaiterConfig={
                    'Delay': 10,
                    'MaxAttempts': 30
                }
            )
        elif action == "start":
            print("Waiting to Start all the tasks")
            start_waiter.wait(
                cluster=cluster_name,
                tasks=get_all_tasks(cluster_name),
                WaiterConfig={
                    'Delay': 10,
                    'MaxAttempts': 30
                }
            )
    except botocore.exceptions.ClientError as error:
        raise error
