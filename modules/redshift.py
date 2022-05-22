## Redshift analysis code
def read_redshift(session, region):
    redshift = session.client('redshift', region_name=region)
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
    if clusters_with_logging or clusters_without_logging:
        return {region:{"redshift_enable":clusters_with_logging, "redshift_disable":clusters_without_logging}}
    else:
        return 