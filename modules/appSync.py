## AppSync code analysis
from typing import List

def get_role_names(client) -> List[str]:
    """ Retrieve a list of role names by paginating over list_roles() calls """
    roles = []
    role_paginator = client.get_paginator('list_roles')
    for response in role_paginator.paginate():
        response_role_names = [r.get('RoleName') for r in response['Roles']]
        roles.extend(response_role_names)
    return roles

def read_appSync(session, region):
    iam = session.client('iam', region_name=region)
    roles = iam.list_roles()
    role_paginator = iam.get_paginator('list_roles')
    role_names = get_role_names(iam)
    roles_logging_AppSync = []

    for name in role_names:
        policies = iam.list_attached_role_policies(RoleName=name)
        for policy in policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AWSAppSyncPushToCloudWatchLogs':
                roles_logging_AppSync.append(name)