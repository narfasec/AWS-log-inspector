## ECS anlysis code
def read_ecs(session, region):
    ecs = session.client('ecs', region_name=region)

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
    if clusters_without_config or clusters_with_config:
        return {region:{'Clusters_with_config':clusters_with_config, 'Clusters_without_config':clusters_without_config}}
    else:
        return