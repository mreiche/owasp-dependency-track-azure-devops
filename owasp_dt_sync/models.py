import importlib.util
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Callable

from azure.devops.v7_0.core import JsonPatchOperation
from azure.devops.v7_1.work import WorkItem
from owasp_dt.models import Finding, AnalysisRequest, AnalysisRequestAnalysisState, AnalysisRequestAnalysisJustification, AnalysisAnalysisResponse, AnalysisRequestAnalysisResponse, Analysis, AnalysisAnalysisState, AnalysisAnalysisJustification
from tinystream import Opt

from owasp_dt_sync import jinja, log

class WorkItemField(StrEnum):
    TITLE = "System.Title"
    DESCRIPTION = "System.Description"
    AREA = "System.AreaPath"
    STATE = "System.State"
    CHANGED_DATE = "System.ChangedDate"

    @property
    def field_path(self):
        return f"/fields/{self.value}"


class WorkItemWrapper:
    def __init__(self, work_item: WorkItem, finding: Finding = None):
        self.__work_item = work_item
        self.__operations: dict[str, JsonPatchOperation] = {}
        self.__finding = finding
        self.work_item_type = ""

    def __opt_field_value(self, field: WorkItemField) -> Opt:
        return Opt(self.__work_item.fields).kmap(field.value)

    def __set_field_value(self, field: WorkItemField, value: any):
        if not self.__work_item.fields:
            self.__work_item.fields = {}

        self.__work_item.fields[field.value] = value
        self.__operations[field.field_path] = JsonPatchOperation(op="add", path=field.field_path, value=value)

    @property
    def finding(self):
        return self.__finding

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
    def state(self) -> str:
        return self.__opt_field_value(WorkItemField.STATE).get("New")

    @state.setter
    def state(self, value: str):
        if self.state != value:
            self.__set_field_value(WorkItemField.STATE, value)

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


class AnalysisWrapper:
    def __init__(self, analysis: Analysis, finding: Finding):
        self.__analysis = analysis
        self.__analysis_request = AnalysisRequest(project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid)

    @property
    def state(self) -> str:
        return Opt(self.__analysis).map_keys("analysis_state", "value").get("")

    @state.setter
    def state(self, value: str):
        if self.state != value:
            self.__analysis.analysis_state = AnalysisAnalysisState(value.upper())
            self.__analysis_request.analysis_state = AnalysisRequestAnalysisState(value.upper())

    @property
    def justification(self) -> str:
        return Opt(self.__analysis).map_keys("analysis_justification", "value").get("")

    @justification.setter
    def justification(self, value: str):
        if self.justification != value:
            self.__analysis.analysis_justification = AnalysisAnalysisJustification(value.upper())
            self.__analysis_request.analysis_justification = AnalysisRequestAnalysisJustification(value.upper())

    @property
    def response(self) -> str:
        return Opt(self.__analysis).map_keys("analysis_response", "value").get("")

    @response.setter
    def response(self, value: str):
        if self.response != value:
            self.__analysis.analysis_response = AnalysisAnalysisResponse(value.upper())
            self.__analysis_request.analysis_response = AnalysisRequestAnalysisResponse(value.upper())

    @property
    def details(self) -> str:
        return Opt(self.__analysis).kmap("analysis_details").filter_type(str).get("")

    @details.setter
    def details(self, value: str):
        if self.details != value:
            self.__analysis.analysis_details = value
            self.__analysis_request.analysis_details = value

    @property
    def suppressed(self) -> bool:
        return Opt(self.__analysis).kmap("is_suppressed").filter_type(bool).get(False)

    @suppressed.setter
    def suppressed(self, value: bool):
        self.__analysis.is_suppressed = value
        self.__analysis_request.is_suppressed = value

    @property
    def request(self):
        return self.__analysis_request


@dataclass
class MapperModule:
    process_finding: Callable[[Finding], bool]
    new_work_item: Callable[[WorkItemWrapper], None]
    map_work_item_to_analysis: Callable[[WorkItemWrapper, AnalysisWrapper], None]
    map_analysis_to_work_item: Callable[[AnalysisWrapper, WorkItemWrapper], None]
    function_names = ["process_finding", "new_work_item", "map_work_item_to_analysis", "map_analysis_to_work_item"]


def load_custom_mapper_module(mapper_path: Path):
    from owasp_dt_sync import globals

    spec = importlib.util.spec_from_file_location(str(mapper_path), mapper_path)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)

    for function_name in MapperModule.function_names:
        mapper_function = getattr(modul, function_name, None)
        if mapper_function:
            assert callable(mapper_function), f"Mapper function '{modul.__name__}:{function_name}' is not callable"
            log.logger.info(f"Connect custom mapper function: '{mapper_path}:{function_name}'")
            globals.mapper.__setattr__(function_name, mapper_function)

def map_work_item_to_analysis(
    work_item_wrapper: WorkItemWrapper,
    analysis_wrapper: AnalysisWrapper
):
    analysis_wrapper.suppressed = False

    if work_item_wrapper.state == "New":
        analysis_wrapper.state = "NOT_SET"
    elif work_item_wrapper.state in ["Closed", "Removed"]:
        analysis_wrapper.state = "RESOLVED"
        analysis_wrapper.suppressed = True
    else:
        analysis_wrapper.state = "IN_TRIAGE"

def map_analysis_to_work_item(
    analysis_wrapper: AnalysisWrapper,
    work_item_wrapper: WorkItemWrapper
):
    if analysis_wrapper.state in [
        "IN_TRIAGE",
        "EXPLOITABLE",
    ]:
        work_item_wrapper.state = "Active"
    elif analysis_wrapper.state in [
        "RESOLVED",
        "FALSE_POSITIVE",
        "NOT_AFFECTED",
    ]:
        work_item_wrapper.state = "Closed"
    else:
        work_item_wrapper.state = "New"

default_mapper = MapperModule(
    process_finding=lambda x: True,
    new_work_item=lambda x: None,
    map_analysis_to_work_item=map_analysis_to_work_item,
    map_work_item_to_analysis=map_work_item_to_analysis,
)
