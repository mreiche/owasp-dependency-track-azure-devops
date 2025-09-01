from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication

from owasp_dt_azure_sync import config


def create_connection_from_env() -> Connection:
    credentials = BasicAuthentication('', config.reqenv("AZURE_API_KEY"))
    return Connection(base_url=config.reqenv("AZURE_ORG_URL"), creds=credentials)
