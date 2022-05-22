## EKS Analysis code
def read_eks(session, region):
    eks = session.client('eks')

    eks_with_audit_log = []
    eks_without_audit_log = []

    paginator = eks.get_paginator('list_clusters')
    page_iterator = paginator.paginate()
    
    names = []
    for page in page_iterator:
        names += [name for name in page['clusters']]
    
    # clusters = eks.list_clusters()
    if not names:
        return
    else:
        for name in names:
            cluster = eks.describe_cluster(name=name)
            for cluster_log in cluster['cluster']['logging']['clusterLogging']:
                if 'audit' in cluster_log['types'] and cluster_log['enabled'] == True:
                    eks_with_audit_log.append(name)
                else:
                    eks_without_audit_log.append(name)
    if eks_without_audit_log or eks_with_audit_log:
        return {region:{'EKS_with_audit_logs':eks_with_audit_log, 'EKS_without_audit_logs':eks_without_audit_log}}
    else:
        return