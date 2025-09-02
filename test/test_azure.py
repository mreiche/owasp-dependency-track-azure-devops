from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_1.work_item_tracking import WorkItemType


def test_read_work_item_types(work_item_tracking_client: WorkItemTrackingClient, azure_project: str):
    types: list[WorkItemType] = work_item_tracking_client.get_work_item_types(azure_project)
    pass

def test_read_work_item(work_item_tracking_client: WorkItemTrackingClient, azure_project: str):
    work_item_tracking_client.get_work_item()
