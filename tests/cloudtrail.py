"""Synthetic CloudTrail records for the impact replay (ADR-0012): the Athena fixture organization at work.

Synthetic only: the fixture accounts and endpoints, an analyst role, nothing real.
"""

import datetime as dt

PREVIEW, OTHER = "111122223333", "444455556666"
ATHENA_VPCE, S3_VPCE = "vpce-0example1111111111", "vpce-0example2222222222"


def record(when, source, name, account=PREVIEW, role="analyst", region="ca-central-1", vpce=None, resources=None,
           error=None, recipient=None, **extra):
    r = {"eventVersion": "1.10", "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": source,
         "eventName": name, "awsRegion": region, "recipientAccountId": recipient or account,
         "userIdentity": {"type": "AssumedRole", "accountId": account, "sessionContext": {
             "sessionIssuer": {"type": "Role", "arn": f"arn:aws:iam::{account}:role/{role}"}}},
         **extra}
    if vpce:
        r["vpcEndpointId"] = vpce
    if resources:
        r["resources"] = resources
    if error:
        r["errorCode"] = error
    return r


def normal_activity(days=40, start=dt.datetime(2026, 9, 20, 9, tzinfo=dt.timezone.utc)):
    """Every day: Athena queries through the endpoint, S3 and KMS on organization resources, Glue, IAM reads,
    and another team's SageMaker use."""
    out = []
    for day in range(days):
        t = start + dt.timedelta(days=day)
        bucket = [{"ARN": "arn:aws:s3:::example-athena-results/q.csv", "accountId": PREVIEW}]
        out += [
            record(t, "athena.amazonaws.com", "StartQueryExecution", vpce=ATHENA_VPCE),
            record(t, "athena.amazonaws.com", "GetQueryResults", vpce=ATHENA_VPCE),
            record(t, "s3.amazonaws.com", "GetObject", vpce=S3_VPCE, resources=bucket),
            record(t, "kms.amazonaws.com", "Decrypt", vpce=S3_VPCE,
                   resources=[{"ARN": f"arn:aws:kms:ca-central-1:{PREVIEW}:key/example", "accountId": PREVIEW}]),
            record(t, "glue.amazonaws.com", "GetTable", vpce=ATHENA_VPCE, invokedBy="athena.amazonaws.com"),
            record(t, "iam.amazonaws.com", "ListRoles", region="us-east-1"),
            record(t, "sagemaker.amazonaws.com", "ListDomains", account=OTHER),
            # A call that was already denied isn't a workload: it is skipped.
            record(t, "athena.amazonaws.com", "StartSession", vpce=ATHENA_VPCE, error="AccessDeniedException"),
        ]
    return {"Records": out}
