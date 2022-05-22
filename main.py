import boto3
from botocore.exceptions import ClientError
from typing import Dict, List

# new commit to check if least priveleged permissions are applied correctly

def get_role_names(client) -> List[str]:
    """ Retrieve a list of role names by paginating over list_roles() calls """
    roles = []
    role_paginator = client.get_paginator('list_roles')
    for response in role_paginator.paginate():
        response_role_names = [r.get('RoleName') for r in response['Roles']]
        roles.extend(response_role_names)
    return roles

def append_new_line(file_name, text_to_append):
    """Append given text as a new line at the end of file"""
    # Open the file in append & read mode ('a+')
    with open(file_name, "a+") as file_object:
        # Move read cursor to the start of file.
        file_object.seek(0)
        # If file is not empty then append '\n'
        data = file_object.read(100)
        if len(data) > 0:
            file_object.write("\n")
        # Append text at the end of file
        file_object.write(text_to_append)

def get_bucket_logging_of_s3(bucket_name):
    try:
        result = s3.get_bucket_logging(Bucket=bucket_name)
    except ClientError as e:
        raise Exception( "boto3 client error in get_bucket_logging_of_s3: " + e.__str__())
    except Exception as e:
        raise Exception( "Unexpected error in get_bucket_logging_of_s3 function: " + e.__str__())
    return result

def get_lambda_tracing_config(function_name):
    try:
        config = lambda_f.get_function(Function_name=function_name)
        result = config["Configuration"]["TracingConfig"]
    except ClientError as e:
        raise Exception( "boto3 client error in get_bucket_logging_of_s3: " + e.__str__())
    except Exception as e:
        raise Exception( "Unexpected error in get_bucket_logging_of_s3 function: " + e.__str__())
    return result

if __name__ == '__main__':
    
    prod_read = boto3.session.Session(profile_name='prod-dataplat',region_name='us-west-2')
    open('results.txt', 'w').close()

    #####################################
    ##                S3               ##
    #####################################

    # Retrieve the list of existing buckets
    s3 = prod_read.client('s3')
    response = s3.list_buckets()

    s3_enable = []
    s3_disable = []
    # Output the bucket names
    for bucket in response['Buckets']:
        try:
            result = get_bucket_logging_of_s3(bucket["Name"])["LoggingEnabled"]
            s3_enable.append(bucket["Name"])
        except Exception as e:
            s3_disable.append(bucket["Name"])

    append_new_line('results.txt', '## S3 Buckets ##')
    append_new_line('results.txt', 'Logs enabled:')
    for s3 in s3_enable:
        append_new_line('results.txt', '\t'+s3)
    append_new_line('results.txt', 'Logs disabled:')
    for s3 in s3_disable:
        append_new_line('results.txt', '\t'+s3)

    #####################################
    ##              Lambdas            ##
    #####################################

    xray_enabled = []
    xray_disabled = []

    lambda_f = prod_read.client('lambda')
    response = lambda_f.list_functions()

    for function in response["Functions"]:
        if function["TracingConfig"] == 'Active':
            xray_enabled.append(function["FunctionName"])
        else:
            xray_disabled.append(function["FunctionName"])
    
    # Append in File
    append_new_line('results.txt', '## Lambdas ##')
    append_new_line('results.txt','Lambdas with X-Ray:')
    for lam in xray_enabled:
        append_new_line('results.txt', '\t'+lam)
    append_new_line('results.txt', 'X-Ray disabled')
    for lam in xray_disabled:
        append_new_line('results.txt', '\t'+lam)
    #####################################
    ##                RDS              ##
    #####################################

    rds_audit_logs = []
    rds_other_logs = []
    rds_no_cloudwatch_logs = []

    rds = prod_read.client('rds', region_name='us-west-2')
    rds_instances = rds.describe_db_instances()

    for instance in rds_instances['DBInstances']:
        try:
            if "audit" in instance["EnabledCloudwatchLogsExports"]:
                rds_audit_logs.append(instance["DBInstanceIdentifier"])
            else:
                rds_other_logs.append(instance["DBInstanceIdentifier"])
        except KeyError:
            rds_no_cloudwatch_logs.append(instance["DBInstanceIdentifier"])

    append_new_line('results.txt', '## RDS ##')
    append_new_line('results.txt','RDS with Audit:')
    for rds in rds_audit_logs:
        append_new_line('results.txt', '\t'+rds)
    append_new_line('results.txt','RDS with other logs (Error, General, Slow query):')
    for rds in rds_other_logs:
        append_new_line('results.txt', '\t'+rds)
    append_new_line('results.txt','RDS with no logs:')
    for rds in rds_no_cloudwatch_logs:
        append_new_line('results.txt', '\t'+rds)

    #####################################
    ##                ECS              ##
    #####################################

    ecs = prod_read.client('ecs', region_name='us-west-2')

    clusters_with_config = []
    clusters_without_config = []

    clusters_arns = []
    cluster_list = ecs.list_clusters()

    for arn in cluster_list["clusterArns"]:
        clusters_arns.append(arn)

    clusters = ecs.describe_clusters(clusters=clusters_arns, include=['CONFIGURATIONS'])

    for cluster in clusters['clusters']:
        try:
            if cluster['configuration']:
                clusters_with_config.append(cluster['clusterArn'])
        except KeyError:
            clusters_without_config.append(cluster['clusterArn'])
    
    append_new_line('results.txt', '## ECS ##')
    append_new_line('results.txt','clusters with Config:')
    for cluster in clusters_with_config:
        append_new_line('results.txt', '\t'+cluster)
    append_new_line('results.txt','clusters without config:')
    for cluster in clusters_without_config:
        append_new_line('results.txt', '\t'+cluster)

    #####################################
    ##                EC2              ##
    #####################################

    ec2 = prod_read.client('ec2', region_name='us-west-2')

    instances_with_monitoring = []
    instnaces_without_monitoring = []

    reservations = ec2.describe_instances()
    
    for reservation in reservations['Reservations']:
        for instance in reservation['Instances']:
            if instance['Monitoring']['State'] == 'enabled':
                instances_with_monitoring.append(instance['InstanceId'])
            else:
                instnaces_without_monitoring.append(instance['InstanceId'])
    
    append_new_line('results.txt', '## EC2 ##')
    append_new_line('results.txt','ec2 with Monitoring:')
    for instance in instances_with_monitoring:
        append_new_line('results.txt', '\t'+instance)
    append_new_line('results.txt','ec2 without Monitoring:')
    for instance in instnaces_without_monitoring:
        append_new_line('results.txt', '\t'+instance)

    #####################################
    ##             AppSync             ##
    #####################################

    iam = prod_read.client('iam', region_name='us-west-2')
    roles = iam.list_roles()
    role_paginator = iam.get_paginator('list_roles')
    role_names = get_role_names(iam)
    roles_logging_AppSync = []

    for name in role_names:
        policies = iam.list_attached_role_policies(RoleName=name)
        for policy in policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AWSAppSyncPushToCloudWatchLogs':
                roles_logging_AppSync.append(name)

    append_new_line('results.txt', '## AppSync ##')
    if not roles_logging_AppSync:
        append_new_line('results.txt', '\tThere are no roles to push logs from AppSync to CloudWatch')
    else:
        append_new_line('results.txt','Roles with AWSAppSyncPushToCloudWatchLogs:')
        for role in roles_logging_AppSync:
            append_new_line('results.txt', '\t'+role)

    #####################################
    ##             RedShift            ##
    #####################################

    # prod_read = boto3.session.Session(profile_name='staging_dataint',region_name='us-west-2')
    redshift = prod_read.client('redshift', region_name='us-west-2')
    response = redshift.describe_clusters()
    cluster_ids = []

    clusters_with_logging = []
    clusters_without_logging = []

    for cluster in response['Clusters']:
        cluster_ids.append(cluster['ClusterIdentifier'])
    for cluster_id in cluster_ids:
        resp = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
        # print(resp)
        if resp['LoggingEnabled'] == True:
            clusters_with_logging.append(cluster_id)
        else:
            clusters_without_logging.append(cluster_id)
    
    append_new_line('results.txt', '## Redshift ##')
    if not cluster_ids:
        append_new_line('results.txt', '\tThere are no Redshift clusters in this account')
    else:
        append_new_line('results.txt','Clusters with Logging:')
        for cluster in clusters_with_logging:
            append_new_line('results.txt', '\t'+cluster)
        append_new_line('results.txt','Clusters without Logging:')
        for cluster in clusters_without_logging:
            append_new_line('results.txt', '\t'+cluster)

    #####################################
    ##             DynamoDB            ##
    #####################################

    cloudtrail = prod_read.client('cloudtrail')
    dynamodb = prod_read.client('dynamodb')

    trails = cloudtrail.list_trails()
    tables_arn_in_trail_data_event = []
    tables_arn_without_logging = []

    for trail in trails['Trails']:
        trail_arn = trail['TrailARN']
        event_selectors = cloudtrail.get_event_selectors(
            TrailName=trail_arn
        )
        try:
            for event_selector in event_selectors['EventSelectors']:
                if event_selector['DataResources']:
                    for data_source in event_selector['DataResources']:
                        if data_source['Type'] == 'AWS::DynamoDB::Table':
                            for value in data_source['Values']:
                                tables_arn_in_trail_data_event.append(value)
        except KeyError as e:
            continue
    
    tables = dynamodb.list_tables()
    paginator = dynamodb.get_paginator('list_tables')
    page_iterator = paginator.paginate()

    table_names = []
    tables_arn = []
    for page in page_iterator:
        table_names += [name for name in page['TableNames']]
    
    for name in table_names:
        arn = dynamodb.describe_table(
            TableName=name
        )['Table']['TableArn']
        tables_arn.append(arn)
    
    # Comparator
    for arn in tables_arn:
        if arn not in tables_arn_in_trail_data_event:
            tables_arn_without_logging.append(arn)
    

    append_new_line('results.txt', '### DynamoDB ###')
    if not tables_arn_in_trail_data_event:
        append_new_line('results.txt', '\tThere are no Data Events of type: DynamoDB')
    else:
        append_new_line('results.txt','Tables with Trail Data Events:')
        for table_name in tables_arn_in_trail_data_event:
            append_new_line('results.txt', '\t'+table_name)
        append_new_line('results.txt','Tables without Logging:')
        for table_name in tables_arn_without_logging:
            append_new_line('results.txt', '\t'+table_name)

    #####################################
    ##            CloudFront           ##
    #####################################

    cloudfront = prod_read.client('cloudfront')

    cloudfront_with_logging = []
    cloudfront_without_logging = []

    paginator = cloudfront.get_paginator('list_distributions')
    page_iterator = paginator.paginate()

    distributions = []
    try:
        for page in page_iterator:
            distributions += [d["Id"] for d in page['DistributionList']['Items']]
    except KeyError as e:
        append_new_line('results.txt','## Nothing for CloudFront:')
    
    for item in distributions:
        cfg = cloudfront.get_distribution_config(Id=item)
        dist = cfg['DistributionConfig']
        if dist['Logging']['Enabled'] == True:
            cloudfront_with_logging.append(item)
        else:
            cloudfront_without_logging.append(item)

    append_new_line('results.txt', '### CloudFront ###')
    append_new_line('results.txt','CloudFront with Logging:')
    for item in cloudfront_with_logging:
        append_new_line('results.txt', '\t'+item)
    append_new_line('results.txt','CloudFront without Logging:')
    for item in cloudfront_without_logging:
        append_new_line('results.txt', '\t'+item)

    #####################################
    ##      ElasticLoadBalacingV2      ##
    #####################################

    elbv2 = prod_read.client('elbv2')

    elb_with_logging = []
    elb_without_logging = []

    paginator = elbv2.get_paginator('describe_load_balancers')
    page_iterator = paginator.paginate()

    arns = []
    for page in page_iterator:
        arns += [arn['LoadBalancerArn'] for arn in page['LoadBalancers']]
    
    for arn in arns:
        attributes = elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)
        for attribute in attributes['Attributes']:
            if attribute['Key'] == 'access_logs.s3.enabled' and attribute['Value'] == 'true':
                elb_with_logging.append(arn)
            elif attribute['Key'] == 'access_logs.s3.enabled' and attribute['Value'] == 'false':
                elb_without_logging.append(arn)
    
    append_new_line('results.txt', '### ElasticLoadBalacingV2 ###')
    append_new_line('results.txt','ELBs with Logging:')
    for item in elb_with_logging:
        append_new_line('results.txt', '\t'+item)
    append_new_line('results.txt','ELBs without Logging:')
    for item in elb_without_logging:
        append_new_line('results.txt', '\t'+item)

    #####################################
    ##              EKS                ##
    #####################################

    eks = prod_read.client('eks')

    eks_with_audit_log = []
    eks_without_audit_log = []

    paginator = eks.get_paginator('list_clusters')
    page_iterator = paginator.paginate()
    
    names = []
    for page in page_iterator:
        names += [name for name in page['clusters']]
    
    # clustersssssss = eks.list_clusters()
    append_new_line('results.txt', '## EKS ##')
    if not names:
        append_new_line('results.txt', '\tThere are no EKS clusters in this account')
    else:
        for name in names:
            cluster = eks.describe_cluster(name=name)
            for cluster_log in cluster['cluster']['logging']['clusterLogging']:
                if 'audit' in cluster_log['types'] and cluster_log['enabled'] == True:
                    eks_with_audit_log.append(name)
                else:
                    eks_without_audit_log.append(name)

    append_new_line('results.txt', 'EKS with audit logs:')
    for item in eks_with_audit_log:
        append_new_line('results.txt', '\t'+item)
    append_new_line('results.txt','EKS without Logging:')
    for item in eks_without_audit_log:
        append_new_line('results.txt', '\t'+item) 