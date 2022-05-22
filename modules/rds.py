## RDS analysis code
def read_rds(session, region):    
    rds_audit_logs = []
    rds_other_logs = []
    rds_no_cloudwatch_logs = []

    rds = session.client('rds', region_name=region)
    rds_instances = rds.describe_db_instances()

    for instance in rds_instances['DBInstances']:
        try:
            if "audit" in instance["EnabledCloudwatchLogsExports"]:
                rds_audit_logs.append(instance["DBInstanceIdentifier"])
            else:
                rds_other_logs.append(instance["DBInstanceIdentifier"])
        except KeyError:
            rds_no_cloudwatch_logs.append(instance["DBInstanceIdentifier"])
    if rds_audit_logs and rds_no_cloudwatch_logs and rds_other_logs:
        return {region:{"rds_audit_logs":rds_audit_logs, "rds_other_logs":rds_other_logs, "rds_no_cloudwatch_logs":rds_no_cloudwatch_logs}}
    else:
        return