## CloudFront analysis code
def read_cloudFront(session):
    cloudfront = session.client('cloudfront')

    cloudfront_with_logging = []
    cloudfront_without_logging = []

    paginator = cloudfront.get_paginator('list_distributions')
    page_iterator = paginator.paginate()

    distributions = []
    try:
        for page in page_iterator:
            distributions += [d["Id"] for d in page['DistributionList']['Items']]
    except KeyError as e:
        return 'Nothing for CloudFront'
    
    for item in distributions:
        cfg = cloudfront.get_distribution_config(Id=item)
        dist = cfg['DistributionConfig']
        if dist['Logging']['Enabled'] == True:
            cloudfront_with_logging.append(item)
        else:
            cloudfront_without_logging.append(item)
    return {'CloudFront':{'cloudfront_with_logging':cloudfront_with_logging, 'cloudfront_without_logging':cloudfront_without_logging}}