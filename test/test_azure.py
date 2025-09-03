from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_0.work_item_tracking import JsonPatchOperation
from azure.devops.v7_1.work_item_tracking import WorkItemType, WorkItem
from is_empty import empty
from tinystream import Stream

from owasp_dt_sync import azure, config


def test_read_work_item_types(
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        azure_work_item_type: str
):
    assert not empty(azure_work_item_type)

    def _filter_type(type: WorkItemType):
        return type.reference_name == azure_work_item_type

    types: list[WorkItemType] = work_item_tracking_client.get_work_item_types(azure_project)
    assert Stream(types).filter(_filter_type).next().present

def test_mask_area_path():
    given_area_path = config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH")
    assert "\\\\" not in given_area_path
    area_path = azure.mask_area_path(given_area_path)
    assert "\\\\" in area_path
    print(area_path)

def test_read_work_item_id():
    assert azure.read_work_item_id("https://azure.devops.com/abce/_apis/wit/workItems/16142") == 16142

def test_create_and_destroy_work_item(
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        azure_work_item_type: str
):
    area_path = azure.mask_area_path(config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH"))
    # https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1&tabs=HTTP
    document: list[JsonPatchOperation] = [
        JsonPatchOperation(op="add", path="/fields/System.Title", value="Test ticket"),
        JsonPatchOperation(op="add", path="/fields/System.Description", value="This is a test"),
        JsonPatchOperation(op="add", path="/fields/System.AreaPath", value=area_path),
    ]
    work_item: WorkItem = work_item_tracking_client.create_work_item(document=document, project=azure_project, type=azure_work_item_type)
    assert not empty(work_item.id)

    work_item_tracking_client.delete_work_item(id=work_item.id, project=azure_project)
    #work_item_tracking_client.destroy_work_item(id=work_item.id, project=azure_project)  # does not work
