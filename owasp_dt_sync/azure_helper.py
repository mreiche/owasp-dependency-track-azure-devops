import re

from azure.devops.connection import Connection
from azure.devops.released.work_item_tracking import WorkItemTrackingClient, WorkItemType, JsonPatchOperation
from is_empty import empty
from msrest.authentication import BasicAuthentication
from tinystream import Stream

from owasp_dt_sync import config


def create_connection_from_env() -> Connection:
    credentials = BasicAuthentication('', config.reqenv("AZURE_API_KEY"))
    return Connection(base_url=config.reqenv("AZURE_ORG_URL"), creds=credentials)

__preferred_work_item_Type: WorkItemType = None

def find_best_work_item_type(work_item_tracking_client: WorkItemTrackingClient, azure_project: str) -> WorkItemType:
    global __preferred_work_item_Type
    if __preferred_work_item_Type is None:
        preferred_type_names = ["Vulnerability", "Bug", "Incident", "Issue", "Task"]
        found_types: dict[str, WorkItemType] = {}
        types: list[WorkItemType] = work_item_tracking_client.get_work_item_types(azure_project)
        for type in types:
            for type_name in preferred_type_names:
                if type_name in type.name:
                    found_types[type_name] = type
                    break

        for type_name in preferred_type_names:
            if type_name in found_types:
                __preferred_work_item_Type = found_types[type_name]
                break

        assert __preferred_work_item_Type is not None, f"Could not find a WorkItem type with on of the names: '{preferred_type_names}'. Please define a proper work_item_type on the WorkItemMapper instead."

    return __preferred_work_item_Type

def pretty_changes(changes: list[JsonPatchOperation]):
    def _map(op: JsonPatchOperation):
        op_dict = op.as_dict()
        if "value" in op_dict:
            value = str(op_dict["value"])
            if len(value) > 100:
                value = value[:100] + "..."
            op_dict["value"] = value
        return op_dict
    return Stream(changes).map(_map).collect()

def mask_area_path(area_path: str):
    return area_path.replace("\\", "\\\\")

__work_item_id_regex = re.compile("workItems/(\\d+)")

def read_work_item_id(url: str) -> int:
    matches = __work_item_id_regex.search(url)
    found = matches.group(1)
    assert not empty(found)
    work_item_id = int(found)
    assert work_item_id > 0
    return work_item_id
