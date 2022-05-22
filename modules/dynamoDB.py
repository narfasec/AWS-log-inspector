## DynamoDB analysis code
def read_dynamodb(session,region):
    cloudtrail = session.client('cloudtrail')
    dynamodb = session.client('dynamodb')

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
    
    if not tables_arn_in_trail_data_event:
        return 'There are no Data Events of type: DynamoDB'
    else:
        return{region:{'dynamoDB_tables_with_logs':tables_arn_in_trail_data_event, 'dynamoDB_tables_without_logs':tables_arn_without_logging}}