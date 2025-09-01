from azure.devops.released.work_item_tracking import WorkItemTrackingClient

def test_read_work_item_types(work_item_tracking_client: WorkItemTrackingClient, azure_project: str):
    types = work_item_tracking_client.get_work_item_types(azure_project)
    pass
