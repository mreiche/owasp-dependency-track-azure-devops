from typing import Iterator

from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding

from test import test_sync_tickets
from owasp_dt_sync import globals, mappers


def setup_module():
    mappers.load_custom_mapper_module("plugins/vulnerability_mapper.py")


def test_render_work_item(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: Iterator[Finding],
):
    test_sync_tickets.test_render_work_item(owasp_dt_client, work_item_tracking_client, azure_project, findings)


def test_sync_status(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: Iterator[Finding],
):
    test_sync_tickets.test_sync_status(owasp_dt_client, work_item_tracking_client, azure_project, findings)


def teardown_module():
    globals.mapper = mappers.default_mapper
