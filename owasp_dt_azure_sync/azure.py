from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from owasp_dt.models import Finding
from owasp_dt import Client
from owasp_dt_azure_sync import config
from owasp_dt.api.analysis import retrieve_analysis

def create_connection_from_env() -> Connection:
    credentials = BasicAuthentication('', config.reqenv("AZURE_API_KEY"))
    return Connection(base_url=config.reqenv("AZURE_ORG_URL"), creds=credentials)


def sync_finding(owasp_dt_client: Client, finding: Finding):
    pass
    #retrieve_analysis.sync(owasp_dt_client, project=finding.p)
    #/v1/analysis
