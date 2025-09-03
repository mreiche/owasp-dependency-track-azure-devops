import pytest
from azure.devops.connection import Connection
from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding

from owasp_dt_azure_sync import dependency_track, azure, config


@pytest.fixture
def azure_connection() -> Connection:
    return azure.create_connection_from_env()

@pytest.fixture
def work_item_tracking_client(azure_connection: Connection) -> WorkItemTrackingClient:
    return azure_connection.clients.get_work_item_tracking_client()

@pytest.fixture
def azure_project() -> str:
    return config.reqenv("AZURE_PROJECT")

@pytest.fixture
def azure_work_item_type():
    return config.getenv("AZURE_WORK_ITEM_TYPE")

@pytest.fixture
def owasp_dt_client() -> AuthenticatedClient:
    return dependency_track.create_client_from_env()

@pytest.fixture
def findings(owasp_dt_client: AuthenticatedClient) -> list[Finding]:
    return dependency_track.load_and_filter_findings(owasp_dt_client)
