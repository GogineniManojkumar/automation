import boto3
import os, sys
import argparse
import logging as log
from datetime import datetime
from jinja2 import Template

html_data = {}

def validate_params():
    if (accessKey == None and secretKey == None) and args.profile == None :
        log.info("Please export aws credentails(AWS_ACCESSKEY, AWS_SECRETKEY) or provide --Profile argument")
        sys.exit(1)

def print_inputs():
    print("-------- Recieved Parameters -----")
    print("Region: " + args.region)
    print("Dryrun: " + str(args.dryrun))
    if args.profile != None:
        print("Profile: " + args.profile)
    print("VPC: " + args.vpc_name)
    print("-----------------------------------")


def get_vpc(connection):
    vpc_info = {}
    log.info("Getting VPC Information from AWS of " + args.vpc_name)
    res = connection.describe_vpcs(Filters=[{'Name': "tag:Name", 'Values':[args.vpc_name]},{'Name': "state", 'Values':['available']}], DryRun=args.dryrun)
    vpc_info['VpcId'] = res['Vpcs'][0]['VpcId']
    vpc_info['CidrBlock'] = res['Vpcs'][0]['CidrBlock']
    vpc_info['VpcName'] = args.vpc_name
    vpc_info['IsDefault'] = res['Vpcs'][0]['IsDefault']
    #vpc_info.append({'VpcId': vpc_id,'CidrBlock': vpc_cidr, 'VpcName':args.vpc_name, 'IsDefault': res['Vpcs'][0]['IsDefault']})
    return vpc_info

def get_subnets(connection,vpc_info):
    subnets_info = []
    vpc_id = vpc_info['VpcId']
    print("Getting Subnets Information from AWS VPC of " + args.vpc_name + '_'+vpc_id)
    res = connection.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}], DryRun=args.dryrun)
    subnets = res['Subnets']
    if len(subnets) > 0:
        for subnet in subnets:
            for tag in subnet['Tags']:
                if tag['Key'] == 'Name':
                    subnet_name = tag['Value']
            subnets_info.append({'SubnetName': subnet_name, 'SubnetId': subnet['SubnetId'], 'CidrBlock': subnet['CidrBlock'], 'AvailabilityZone': subnet['AvailabilityZone'], 'State': subnet['State'], 'AvailableIpAddressCount': subnet['AvailableIpAddressCount'] })
    return subnets_info

def get_route_tables(connection,vpc_info):
    rt_id = ""
    rt_name = ""
    rts_retrun = []
    subnet_ids = []
    routes_list = []
    print("Getting Routeable information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    rt_res = connection.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    routetables = rt_res['RouteTables']
    if len(routetables) > 0:
        for routetable in routetables:
            rt_id = routetable['RouteTableId']
            rt_name = "N/A"
            for tag in routetable['Tags']:
                if tag['Key'] == 'Name':
                    rt_name = tag['Value']

            # subnets associated
            subnet_ids = [association['SubnetId'] for association in routetable['Associations'] if 'SubnetId' in association]

            # get routes available in rt
            for route in routetable['Routes']:
                route_key = list(route.keys())[0]
                via_key = list(route.keys())[1]
                route_value = route[route_key]
                route_via_value = route[via_key]
                routes_list.append({'Route': route_value,'RouteVia': route_via_value })
            # append subnet info to list        
            rts_retrun.append({'RoueTableName': rt_name, 'RoueTableId': rt_id, 'SubnetIds': subnet_ids, 'Routes': routes_list})
            routes_list = [] #reset list
    return rts_retrun

def get_igw(connection, vpc_info):
    igw_return = []
    igw_name = "N/A"
    print("Getting Internet Gateway from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    igw_res = connection.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    igws = igw_res['InternetGateways']
    if len(igws) > 0:
        for igw in igws:
            igw_id = igw['InternetGatewayId']

            for attachemnt in igw['Attachments']:
                state = attachemnt['State']

            for tag in igw['Tags']:
                if tag['Key'] == 'Name':
                    igw_name = tag['Value']
        igw_return.append({'igwName': igw_name, 'igwID': igw_id, 'igwState': state})
    return igw_return

def get_vpc_endpoints(connection, vpc_info):
    endpoint_list = []
    endpoint_name = "N/A"
    print("Getting VPC Endpoints information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    vep_res = connection.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    endpoints = vep_res['VpcEndpoints']
    if len(endpoints) > 0:
        for endpoint in endpoints:
            for tag in endpoint['Tags']:
                if tag['Key'] == 'Name':
                    endpoint_name = tag['Value']
            endpoint_list.append({'VpcEndpointName': endpoint_name, 'VpcEndpointId': endpoint['VpcEndpointId'], 'VpcEndpointType': endpoint['VpcEndpointType'], 'ServiceName': endpoint['ServiceName'], 'State': endpoint['State'], 'RouteTableIds': endpoint['RouteTableIds'], 'CreationTime': endpoint['CreationTimestamp']})       
    return endpoint_list

def get_nat_gw(connection, vpc_info):
    nat_gw_return = []
    nat_gw_name = "N/A"
    print("Getting NAT Gateway information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    nat_gw_res = connection.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    nat_gws = nat_gw_res['NatGateways']
    if len(nat_gws) > 0:
        for nat_gw in nat_gws:
            nat_gw_id = nat_gw['NatGatewayId']
            nat_gw_conn_type = nat_gw['ConnectivityType']
            nat_gw_subnet = nat_gw['SubnetId']

            nat_gw_state = nat_gw['State']
            for address in nat_gw['NatGatewayAddresses']:
                private_ip = address['PrivateIp']
                public_ip = address['PublicIp']

            for tag in nat_gw['Tags']:
                if tag['Key'] == 'Name':
                    nat_gw_name = tag['Value']
        nat_gw_return.append({'natGwName': nat_gw_name, 'natGwID': nat_gw_id, 'natGwPrivateIp': private_ip, 'natGwPublicIp': public_ip, 'natGwType': nat_gw_conn_type, 'natGwSubnet': nat_gw_subnet, 'natGwState': nat_gw_state})
    return nat_gw_return
def get_vpc_peering(connection, vpc_info):
    vpc_peer_return = []
    peer_name = ""
    print("Getting VPC Peering Connection information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    vpc_peer_res = connection.describe_vpc_peering_connections(Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    peer_connections = vpc_peer_res['VpcPeeringConnections']
    if len(peer_connections) > 0:
        for peer in peer_connections:
            peer_id = peer['VpcPeeringConnectionId']
            peer_state = peer['Status']
            accepter = peer['AccepterVpcInfo']
            requester = peer['RequesterVpcInfo']
            for tag in peer['Tags']:
                if tag['Key'] == 'Name':
                    peer_name = tag['Value']
            
            VpcPeerAccepter = [{'VpcId': accepter['VpcId'],'CidrBlock': accepter['CidrBlock'], 'Region': accepter['Region'], 'OwnerId': accepter['OwnerId']}]
            VpcPeerRequester = [{'VpcId': requester['VpcId'],'CidrBlock': requester['CidrBlock'], 'Region': requester['Region'], 'OwnerId': requester['OwnerId']}]
            vpc_peer_return.append({'VpcPeerName': peer_name, 'VpcPeerId': peer_id,'VpcPeerState': peer_state.get('Code'), 'VpcPeerAccepter': VpcPeerAccepter, 'VpcPeerRequester': VpcPeerRequester})
    return vpc_peer_return

def get_nacls(connection, vpc_info):
    nacls_return = []
    nacl_name = "N/A"
    CidrRangeKey = ""
    CidrBlock_Value = ""
    print("Getting NACL information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    res = connection.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    nacls = res['NetworkAcls']
    if len(nacls) > 0:
        for nacl in nacls:
            naclId = nacl['NetworkAclId']
            for tag in nacl['Tags']:
                if tag['Key'] == 'Name':
                    nacl_name = tag['Value']
            isdefault = nacl['IsDefault']
            subnets_associated = [ assoc['SubnetId'] for assoc in nacl['Associations'] if 'SubnetId' in assoc]
            rules = []
            #rules = [{'RuleNumber': rule['RuleNumber'],'RuleAction': rule['RuleAction'], 'Protocol': rule['Protocol'], 'CidrBlock': [rule['CidrBlock'] if CidrBlock in rule['CidrBlock']], 'Egress': rule['Egress']} for rule in nacl['Entries']]
            for rule in nacl['Entries']:
                if "Ipv6CidrBlock" in rule:
                    CidrRangeKey = 'Ipv6CidrBlock'
                else:
                    CidrRangeKey = 'CidrBlock'

                if 'PortRange' in rule:
                    from_port = str(rule['PortRange']['From'])
                    to_port = str(rule['PortRange']['To'])
                    port_range = (from_port+"_"+to_port)
                else:
                    port_range = "All"

                CidrBlock_Value = rule[CidrRangeKey]
                
                rules.append({'RuleNumber': rule['RuleNumber'],'RuleAction': rule['RuleAction'], 'Protocol': rule['Protocol'], 'CidrBlock': CidrBlock_Value, 'PortRange': port_range, 'Egress': rule['Egress']})

            nacls_return.append({'naclName': nacl_name,'naclId': naclId,'isDefault': isdefault, 'naclSubnets': subnets_associated,'naclRules': rules })
    return nacls_return

def get_transit_gw(connection, vpc_info):
    tgw_return = []
    tgw_name = "N/A"
    print("Getting Transit Gateway information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    res = connection.describe_transit_gateways(DryRun=args.dryrun)
    tgws = res['TransitGateways']
    if len(tgws) > 0:
        for tgw in tgws:
            for tag in tgw['Tags']:
                if tag['Key'] == 'Name':
                    tgw_name = tag['Value']

            tgw_return.append({'TgwName': tgw_name,'TgwId': tgw['TransitGatewayId'], 'TgwState': tgw['State'], 'TgwOwner': tgw['OwnerId'], 'TgwDefaultRTEnable': tgw['Options']['DefaultRouteTableAssociation'], 'TgwDefaultRTId': tgw['Options']['AssociationDefaultRouteTableId'], 'TgwPropagationEnable': tgw['Options']['DefaultRouteTablePropagation'], 'TgwPropagationRTId': tgw['Options']['PropagationDefaultRouteTableId'], 'TgwDnsSupport': tgw['Options']['DnsSupport']})
    return tgw_return

def get_tgw_attachments(connection, vpc_info):
    tgw_attach_return = []
    attachment_name = "N/A"
    print("Getting Transit Gateway Attachmets information from vpc " + vpc_info['VpcName'] + '_' +vpc_info['VpcId'])
    res = connection.describe_transit_gateway_vpc_attachments(Filters=[{'Name': 'vpc-id', 'Values': [vpc_info['VpcId']]}], DryRun=args.dryrun)
    attachments = res['TransitGatewayVpcAttachments']
    if len(attachments)>0:
        for attachment in attachments:
            for tag in attachment['Tags']:
                if tag['Key'] == 'Name':
                    attachment_name = tag['Value']
            
            tgw_attach_return.append({'AttachmentName': attachment_name ,'AttachmentId': attachment['TransitGatewayAttachmentId'], 'TgwId': attachment['TransitGatewayId'], 'VpcId': attachment['VpcId'], 'VpvOwner': attachment['VpcOwnerId'], 'State': attachment['State'], 'Subnets': attachment['SubnetIds'], 'DnsSupport': attachment['Options']['DnsSupport'], 'ApplianceMode': attachment['Options']['ApplianceModeSupport']})
    return tgw_attach_return

def get_tgw_rts(connection, tgw_info):
    tgw_rts_return = []
    rt_name = "N/A"
    for tgw in tgw_info:
        res = connection.describe_transit_gateway_route_tables(Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw['TgwId']]}, {'Name': 'state', 'Values': ['available']}], DryRun=args.dryrun)
        rts = res['TransitGatewayRouteTables']
        if len(rts)>0:
            for rt in rts:
                for tag in rt['Tags']:
                    if tag['Key'] == 'Name':
                        rt_name = tag['Value']
                tgw_rts_return.append({'TgwRTName': rt_name, 'TgwRTId': rt['TransitGatewayRouteTableId'], 'TgwId': rt['TransitGatewayId'], 'State': rt['State'], 'IsDefault': rt['DefaultAssociationRouteTable'], 'IsDefaultPropagated': rt['DefaultPropagationRouteTable']})
    return tgw_rts_return

def get_tgw_attach_routes(connection, tgw_rts):
    data_return = []
    for rt in tgw_rts:
        rt_id = rt['TgwRTId']
        res = connection.search_transit_gateway_routes(TransitGatewayRouteTableId=rt_id, Filters=[{'Name': 'state', 'Values': ['active']}], DryRun=args.dryrun)
        routes = res['Routes']
        for route in routes:
            DestinationCidrBlock = route['DestinationCidrBlock']
            Type = route['Type']
            State = route['State']
            for attachment in route['TransitGatewayAttachments']:
                ResourceType = attachment['ResourceType']
                TransitGatewayAttachmentId = attachment['TransitGatewayAttachmentId']
                ResourceId = attachment['ResourceId']

            data_return.append({'TgwRTId': rt_id, 'DestinationCidrBlock': DestinationCidrBlock, 'Type': Type, 'State': State, 'AttachmentResourceType': ResourceType, 'VpcId': ResourceId, 'TgwAttachmentId': TransitGatewayAttachmentId})
    return data_return

def generate_html(data):
    with open('./vpc_info.html', 'r') as f:
        template = Template(f.read())
    return template.render(data=data, timestamp=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


def main():
    try:
        print("Making connection to AWS with auth method provided")
        if args.profile != None:
            session = boto3.session.Session(region_name=args.region, profile_name=args.profile)
        else:
            session = boto3.session.Session(region_name=args.region, aws_access_key_id=accessKey, aws_secret_access_key=secretKey)

        connection = session.client('ec2')
        account_name = session.client('iam').list_account_aliases()['AccountAliases'][0]
        account_number = session.client('sts').get_caller_identity().get('Account')

        # get vpc info
        vpc_info = get_vpc(connection)
        html_data = vpc_info

        #get subnets information
        html_data['Subnets'] = []
        subnets_info = get_subnets(connection,vpc_info)
        if len(subnets_info) > 0:
            for subnet in subnets_info:
                html_data['Subnets'].append(subnet)

        # get routetables information
        html_data['RouteTables'] = []
        rts_info = get_route_tables(connection,vpc_info)
        if len(rts_info) > 0:
            for rt in rts_info:
                html_data['RouteTables'].append(rt)

        #get igw information
        html_data['IGW'] = []
        igw_info = get_igw(connection,vpc_info)
        if len(igw_info) > 0:
            for igw in igw_info:
                html_data['IGW'].append(igw)
        
        #get vpcendpoints
        endpoints_info = get_vpc_endpoints(connection, vpc_info)
        if len(endpoints_info) > 0:
            html_data['VpcEndpoints'] = endpoints_info

        #get Nat gateways
        natgw_info = get_nat_gw(connection, vpc_info)
        if len(natgw_info) > 0:
            html_data['NatGw'] = natgw_info

        #get Peering connections
        vpc_peer_info = get_vpc_peering(connection, vpc_info)
        if len(vpc_peer_info) > 0:
            html_data['VpcPeerConnections'] = vpc_peer_info
        #get nacls
        nacl_info = get_nacls(connection, vpc_info)
        if len(nacl_info) > 0:
            html_data['NACLs'] = nacl_info

        #get tgw
        tgw_info = get_transit_gw(connection, vpc_info)
        if len(tgw_info) >0:
            html_data['TGWs'] = tgw_info

        #get tgw attchments
        tgw_attach_info = get_tgw_attachments(connection, vpc_info)
        if len(tgw_attach_info) > 0:
            html_data['TGWAttachments'] = tgw_attach_info

        #get tgw rts
        tgw_rts = get_tgw_rts(connection, tgw_info)
        if len(tgw_rts) > 0:
            html_data['TGWRTs'] = tgw_rts

        #get tgw routes
        tgw_routes_info = get_tgw_attach_routes(connection,tgw_rts)
        if len(tgw_routes_info) > 0:
            html_data['TGWRTRoutes'] = tgw_routes_info

        html_data['account_name'] = account_name
        html_data['account_number'] = account_number

        #render the html with data
        html = generate_html(html_data)
        #print(html)
        with open(f'{account_name+"_"+args.vpc_name}.html', 'w') as f:
            f.write(html)

    except Exception as error:
        log.error(error)

if __name__ == "__main__":
    try:
        accessKey = os.environ.get('AWS_ACCESSKEY')
        secretKey = os.environ.get('AWS_SECRETKEY')

        parser = argparse.ArgumentParser(description="VPC Subnets Information",
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        # required args
        required = parser.add_argument_group('required arguments')
        required.add_argument("--vpc_name", help="aws vpc name", required=True)

        # optional args
        optional = parser.add_argument_group('optional arguments')
        optional.add_argument("--region", default="us-east-1", help="aws region")
        optional.add_argument("-p", "--profile", help="aws profile")
        optional.add_argument("--dryrun", action="store_true", help="dryrun")

        # print help on empty args
        parser.parse_args(args=None if sys.argv[1:] else ['--help'])
        args = parser.parse_args()

        # run parameter validations
        validate_params()
        # print inputs
        print_inputs()
        main()
    except Exception as error:
        log.error(error)