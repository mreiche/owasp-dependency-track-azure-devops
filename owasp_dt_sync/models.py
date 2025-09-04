import importlib.util
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from azure.devops.v7_0.core import JsonPatchOperation
from azure.devops.v7_1.work import WorkItem
from owasp_dt.models import Finding
from tinystream import Opt

from owasp_dt_sync import config, jinja


def load_wrapper_module(mapper_path: Path, modulname="extern"):
    spec = importlib.util.spec_from_file_location(modulname, mapper_path)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    assert callable(getattr(modul, "transform", None)), f"Mapper function {mapper_path}.transform is not callable"
    return modul

def create_new_work_item_wrapper(findings: list[Finding] = None):
    work_item_wrapper = WorkItemWrapper(WorkItem(), findings)
    work_item_wrapper.title = "New Finding"
    work_item_wrapper.area = config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH", "")
    transform_work_item_wrapper(work_item_wrapper)
    return work_item_wrapper

class WorkItemState(StrEnum):
    NEW="New"
    ACTIVE="Active"
    CLOSED="Closed"

class WorkItemField(StrEnum):
    TITLE="System.Title"
    DESCRIPTION="System.Description"
    AREA="System.AreaPath"
    STATE="System.State"
    CHANGED_DATE="System.ChangedDate"

    @property
    def field_path(self):
        return f"/fields/{self.value}"

class WorkItemWrapper:
    def __init__(self, work_item: WorkItem, findings:list[Finding] = None):
        self.__work_item = work_item
        self.__operations: dict[str, JsonPatchOperation] = {}
        self.__findings = findings
        self.work_item_type = ""

    def __opt_field_value(self, field: WorkItemField) -> Opt:
        return Opt(self.__work_item.fields).kmap(field.value)

    def __set_field_value(self, field: WorkItemField, value: any):
        if not self.__work_item.fields:
            self.__work_item.fields = {}

        self.__work_item.fields[field.value] = value
        self.__operations[field.field_path] = JsonPatchOperation(op="add", path=field.field_path, value=value)

    @property
    def findings(self):
        return self.__findings

    @property
    def work_item(self):
        return self.__work_item

    def update_work_item(self, work_item: WorkItem):
        self.__work_item = work_item
        self.__operations.clear()

    @property
    def title(self) -> str:
        return self.__opt_field_value(WorkItemField.TITLE).get()

    @title.setter
    def title(self, value: str):
        self.__set_field_value(WorkItemField.TITLE, value)

    @property
    def state(self) -> WorkItemState:
        return self.__opt_field_value(WorkItemField.STATE).if_absent(lambda: WorkItemState.NEW.value).map(WorkItemState).get()

    @state.setter
    def state(self, value: WorkItemState|str):
        if isinstance(value, str):
            value = WorkItemState(value)

        if self.state != value:
            self.__set_field_value(WorkItemField.STATE, value.value)

    @property
    def area(self) -> str:
        return self.__opt_field_value(WorkItemField.AREA).get("")

    @area.setter
    def area(self, value: str):
        if self.area != value:
            self.__set_field_value(WorkItemField.AREA, value)

    @property
    def description(self) -> str:
        return self.__opt_field_value(WorkItemField.DESCRIPTION).get()

    @description.setter
    def description(self, value: str):
        self.__set_field_value(WorkItemField.DESCRIPTION, value)

    @property
    def changed_date(self) -> datetime:
        field_value = self.__opt_field_value(WorkItemField.CHANGED_DATE)
        if field_value.present:
            return field_value.map(datetime.fromisoformat).get()
        else:
            return datetime.fromtimestamp(0, tz=timezone.utc)

    @property
    def changes(self):
        return list(self.__operations.values())

    def render_description(self):
        self.description = jinja.get_template().render(work_item_wrapper=self)

def transform_work_item_wrapper(work_item_wrapper: WorkItemWrapper):
    pass
