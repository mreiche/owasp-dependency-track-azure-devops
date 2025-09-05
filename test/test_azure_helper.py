from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_0.work_item_tracking import JsonPatchOperation
from azure.devops.v7_1.work_item_tracking import WorkItem
from is_empty import empty

from owasp_dt_sync import azure_helper, config


def test_find_preferred_work_item_type(work_item_tracking_client: WorkItemTrackingClient, azure_project: str):
    type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
    pass

def test_mask_area_path():
    given_area_path = config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH")
    assert "\\\\" not in given_area_path
    area_path = azure_helper.mask_area_path(given_area_path)
    assert "\\\\" in area_path
    print(area_path)

def test_read_work_item_id():
    assert azure_helper.read_work_item_id("https://azure.devops.com/abce/_apis/wit/workItems/16142") == 16142

def test_create_and_destroy_work_item(
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str
):
    area_path = azure_helper.mask_area_path(config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH"))
    # https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1&tabs=HTTP
    document: list[JsonPatchOperation] = [
        JsonPatchOperation(op="add", path="/fields/System.Title", value="Test ticket"),
        JsonPatchOperation(op="add", path="/fields/System.Description", value="This is a test"),
        JsonPatchOperation(op="add", path="/fields/System.AreaPath", value=area_path),
    ]
    work_item_type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
    work_item: WorkItem = work_item_tracking_client.create_work_item(document=document, project=azure_project, type=work_item_type.reference_name)
    assert not empty(work_item.id)

    work_item_tracking_client.delete_work_item(id=work_item.id, project=azure_project)
    #work_item_tracking_client.destroy_work_item(id=work_item.id, project=azure_project)  # does not work
