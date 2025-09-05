import pytest
from azure.devops.connection import Connection
from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding, FindingAnalysis, FindingComponent, FindingVulnerability

from owasp_dt_sync import owasp_dt_helper, azure_helper, config

@pytest.fixture
def finding_stub():
    return Finding(analysis=FindingAnalysis(),component=FindingComponent(),vulnerability=FindingVulnerability())

@pytest.fixture
def azure_connection() -> Connection:
    return azure_helper.create_connection_from_env()

@pytest.fixture
def work_item_tracking_client(azure_connection: Connection) -> WorkItemTrackingClient:
    return azure_connection.clients.get_work_item_tracking_client()

@pytest.fixture
def azure_project() -> str:
    return config.reqenv("AZURE_PROJECT")

@pytest.fixture
def owasp_dt_client() -> AuthenticatedClient:
    return owasp_dt_helper.create_client_from_env()

@pytest.fixture
def findings(owasp_dt_client: AuthenticatedClient):
    return owasp_dt_helper.load_and_filter_findings(owasp_dt_client, load_suppressed=True, load_inactive=True)
