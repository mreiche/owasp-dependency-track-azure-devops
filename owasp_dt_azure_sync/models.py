from dataclasses import dataclass
from enum import StrEnum

from azure.devops.v7_0.core import JsonPatchOperation
from azure.devops.v7_1.work import WorkItem
from owasp_dt.models import Finding

from owasp_dt_azure_sync import azure, config, jinja


@dataclass
class IssueData:
    findings: None|list[Finding]

class Issue:
    def __init__(
            self,
            title: str,
            area_path: str,
            data: IssueData = None,
    ):
        self.__title = title
        self.__area_path = azure.mask_area_path(area_path)
        self.__data = data

    def render_description(self):
        return jinja.get_template().render(issue=self)

    @property
    def data(self):
        return self.__data

    def create_work_item_document(self):
        document: list[JsonPatchOperation] = [
            JsonPatchOperation(op="add", path=WorkItemField.TITLE.field_path, value=self.__title),
            JsonPatchOperation(op="add", path=WorkItemField.DESCRIPTION.field_path, value=self.render_description()),
            JsonPatchOperation(op="add", path=WorkItemField.AREA.field_path, value=self.__area_path),
        ]
        return document

def create_issue_from_findings(findings: list[Finding]):
    return Issue(
        "New Finding",
        config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH"),
        data=IssueData(findings=findings),
    )

class WorkItemState(StrEnum):
    NEW="New"
    ACTIVE="Active"
    CLOSED="Closed"

class WorkItemField(StrEnum):
    TITLE="System.Title"
    DESCRIPTION="System.Description"
    AREA="System.AreaPath"
    STATE="System.State"

    @property
    def field_path(self):
        return f"/fields/{self.value}"

class WorkItemWrapper:
    def __init__(self, work_item: WorkItem):
        self.__work_item = work_item
        self.__changes: list[JsonPatchOperation] = []

    def __get_field_value(self, field: WorkItemField):
        return self.__work_item.fields[field.value]

    @property
    def work_item(self):
        return self.__work_item

    @property
    def state(self):
        return WorkItemState(self.__get_field_value(WorkItemField.STATE))

    @state.setter
    def state(self, value: WorkItemState):
        if self.state != value:
            self.__changes.append(JsonPatchOperation(op="add", path=WorkItemField.STATE.field_path, value=value.value))

    @property
    def changes(self):
        return self.__changes
