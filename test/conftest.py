import pytest
from azure.devops.connection import Connection
from azure.devops.released.work_item_tracking import WorkItemTrackingClient

from owasp_dt_azure_sync.azure import create_connection_from_env, config


@pytest.fixture
def azure_connection() -> Connection:
    return create_connection_from_env()

@pytest.fixture
def work_item_tracking_client(azure_connection: Connection) -> WorkItemTrackingClient:
    return azure_connection.clients.get_work_item_tracking_client()

@pytest.fixture
def azure_project() -> str:
    return config.reqenv("AZURE_PROJECT")
