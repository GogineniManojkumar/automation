import boto3
import os, sys, time
import argparse

def validate_params():
    if (accessKey == None and secretKey == None) and args.profile == None :
        print("Please export aws credentails(AWS_ACCESSKEY, AWS_SECRETKEY) or provide --Profile argument")
        sys.exit(1)
    if (args.action != 'STOP' and args.action != 'START'):
        print ("Action should be either STOP or START")
        sys.exit(1)

def print_inputs():
    print("-------- Recieved Parameters -----")
    print("Region: " + args.region)
    print("Action: " + args.action)
    print("Dryrun: " + str(args.dryrun))
    if args.profile != None:
        print("Profile: " + args.profile)
    print("-----------------------------------")

def get_ins_list(ec2_session):
    try:
        print("Getting the instances list based on the auto_start_stop tags")
        if args.action == "STOP":
            ins_response = ec2_session.describe_instances(Filters=[{'Name':'tag:auto_start_stop', 'Values': ["true"]},{'Name' : 'instance-state-name', 'Values' : ["running"]}], DryRun=args.dryrun)
        elif args.action == "START":
            ins_response = ec2_session.describe_instances(Filters=[{'Name':'tag:auto_start_stop', 'Values': ["true"]},{'Name' : 'instance-state-name', 'Values' : ["stopped"]}], DryRun=args.dryrun)

        for r in ins_response['Reservations']:
            for instance in r['Instances']:
                instance_id = instance['InstanceId']
                for tag in instance['Tags']:
                    if tag['Key'] == "Name":
                        instance_name = tag['Value']                        
                print ('---------------------------')
                print ('InstanceName: '+ instance_name)
                print ('InstanceId: '+ instance_id)
                # append instance id to list
                ins_list.append({'instanceName': instance_name, 'instanceId': instance_id})
        return ins_list
    except Exception as error:
        print(error)

def get_ins_state(ec2_session,ins_id):
    instance_ids = [ins_id]
    res = ec2_session.describe_instance_status(InstanceIds=instance_ids, IncludeAllInstances=True, DryRun=args.dryrun)
    state = res['InstanceStatuses'][0]['InstanceState']['Name']
    return state

def stop_ec2(ec2_session,ins_list):
    for item in ins_list:
        instance_name = item['instanceName']
        instance_id = item['instanceId']
        instance_ids = [instance_id]
        print("Stopping: "+ str(instance_name)+"_"+str(instance_id))
        res = ec2_session.stop_instances(InstanceIds=instance_ids, DryRun=args.dryrun)
        state = res['StoppingInstances'][0]['CurrentState']['Name']
        while state != "stopped":
            time.sleep(5)
            state = get_ins_state(ec2_session,instance_id)
            print("Current Instance Status: " + state)
        print("Stopped: "+ str(instance_name)+"_"+str(instance_id))

def start_ec2(ec2_session,ins_list):
    for item in ins_list:
        instance_name = item['instanceName']
        instance_id = item['instanceId']
        instance_ids = [instance_id]
        print("Starting: "+ str(instance_name)+"_"+str(instance_id))
        res = ec2_session.start_instances(InstanceIds=instance_ids, DryRun=args.dryrun)
        state = res['StartingInstances'][0]['CurrentState']['Name']
        while state != "running":
            time.sleep(5)
            state = get_ins_state(ec2_session,instance_id)
            print("Current Instance Status: " + state)
        print("Started: "+ str(instance_name)+"_"+str(instance_id))

def main():
    print("Making connection to AWS based on auth method")
    if args.profile != None:
        session = boto3.session.Session(region_name=args.region, profile_name=args.profile)
    else:
        session = boto3.session.Session(region_name=args.region, aws_access_key_id=accessKey, aws_secret_access_key=secretKey)

    ec2_session = session.client('ec2')

    ins_list = get_ins_list(ec2_session)
    print ("Total Number Of Instances Found: " + str(len(ins_list)))
    print(ins_list)
    # execute actions
    if args.action == "START":
        start_ec2(ec2_session,ins_list)
    elif args.action == "STOP":
        stop_ec2(ec2_session,ins_list)
    else:
        print ("Unknown Action Recieved")
        sys.exit(1)

if __name__ == "__main__":
    try:
        accessKey = os.environ.get('AWS_ACCESSKEY')
        secretKey = os.environ.get('AWS_SECRETKEY')

        parser = argparse.ArgumentParser(description="EC2 Instance Stop/Start",
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("--region", default="us-east-1", help="aws region")
        parser.add_argument("-p", "--profile", help="aws profile")
        parser.add_argument("--dryrun", action="store_true", help="dryrun")
        parser.add_argument("-a", "--action", help="Action to perform: STOP / START")
        parser.parse_args(args=None if sys.argv[1:] else ['--help'])
        args = parser.parse_args()
        params = vars(args)

        # run parameter validations
        validate_params()
        # print inputs
        print_inputs()
        # empty list
        ins_list = []
        # main function
        main()
    except Exception as error:
        print(error)