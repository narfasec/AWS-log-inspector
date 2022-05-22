import boto3, botocore
from botocore.exceptions import ClientError

def get_bucket_logging_of_s3(bucket_name, s3):
    try:
        result = s3.get_bucket_logging(Bucket=bucket_name)
    except ClientError as e:
        raise Exception( "boto3 client error in get_bucket_logging_of_s3: " + e.__str__())
    except Exception as e:
        raise Exception( "Unexpected error in get_bucket_logging_of_s3 function: " + e.__str__())
    return result

def read_s3(session):
    s3 = session.client('s3')
    response = s3.list_buckets()

    s3_enable = []
    s3_disable = []
    # Output the bucket names
    for bucket in response['Buckets']:
        try:
            result = get_bucket_logging_of_s3(bucket["Name"])["LoggingEnabled"]
            s3_enable.append(bucket["Name"], s3)
        except Exception as e:
            s3_disable.append(bucket["Name"])
    if s3_disable or s3_enable:
        return {'S3':{"s3_enable":s3_enable, "s3_disable":s3_disable}}
    else:
        return